# Performance

Every number in the tables below comes from one run of
[`loadtest/run_benchmarks.sh`](../loadtest/run_benchmarks.sh) on the final code (the reference
run). Its outputs are in [`loadtest/results/`](../loadtest/results/), and
[loadtest/README.md](../loadtest/README.md) explains how to reproduce them. Nothing here is
extrapolated. Earlier runs are used only where stated: to show run-to-run variation and the
problems they uncovered.

## Environment

| | |
|---|---|
| Date | 2026-10-26 |
| Host | VMware VM, 10 vCPU, 9 GiB RAM, Debian 12 |
| Container limits | web 2 vCPU / 768 MiB, PostgreSQL 2 vCPU / 1 GiB, worker 1 vCPU / 512 MiB |
| Services | Gunicorn 3 workers x 4 threads, Celery concurrency 4, PostgreSQL 16.15 (`shared_buffers` 256 MB) |
| Dataset | 2,717,466 audit events at the start, 2,905,547 at the end |
| Load generator | k6 in a container on the same host |

The limits are the defaults from `docker-compose.yml`, so the results describe the default
deployment, not the host's full capacity. k6 competes with the service for the host's CPU; a
separate load generator would show slightly better numbers.

## Query plans on 2.7 million events

`EXPLAIN (ANALYZE, BUFFERS)` of the exact SQL the API issues, with the default 30-day window
and a page of 50 ([full plans](../loadtest/results/explain.txt)). The worst cases are values
that are not spread evenly over time and a cursor at the far end of the window: these are the
queries that took seconds before the fixes described below.

| Query | Execution | Access path |
|---|---|---|
| Newest page | 0.40 ms | Index Scan Backward `audit_created_id_idx` |
| Deep page, 5,000 rows in | 0.36 ms | Index Scan Backward `audit_created_id_idx` |
| **Last page of the window, 2,215,778 newer rows behind the cursor** | 0.74 ms | Index Scan Backward `audit_created_id_idx` |
| Actor history (busiest actor) | 4.57 ms | Index Scan Backward `audit_actor_created_id_idx` |
| Resource history | 0.88 ms | Index Scan Backward `audit_resource_created_id_idx` |
| Severity CRITICAL | 0.37 ms | Index Scan Backward `audit_severity_created_id_idx` |
| Action `auth.login.failed` | 0.46 ms | Index Scan Backward `audit_action_created_id_idx` |
| **Action common only in older rows** (`auth.token.refreshed`) | 4.59 ms | Index Scan Backward `audit_action_created_id_idx` |
| Source IP | 0.43 ms | Index Scan Backward `audit_ip_created_id_idx` |
| **Source IP with no events** | 0.85 ms | Index Scan Backward `audit_ip_created_id_idx` |
| **API key scope, producer with one event** | 1.12 ms | Index Scan Backward `audit_producer_created_id_idx` |
| Metadata, common value `{"mfa": true}` | 0.33 ms | Step 1 (newest 10,000 rows) fills the page |
| **Metadata, rare value** `{"rule_id": "R-2518"}` | 6.0 + 7.1 ms | Step 1, then Bitmap Index Scan `audit_metadata_gin` |

No query reads the audit table sequentially, and every one uses the index it was designed for
(the script checks this). Why the queries are shaped this way is explained in
[architecture decisions 7 and 12](architecture.md#12-page-queries-that-do-not-depend-on-planner-estimates).

## Latency at a fixed arrival rate

Open model (k6 `constant-arrival-rate`): requests arrive at the given rate whether or not
earlier ones have finished, as real clients do. Measured by k6 over 60 seconds each.

| Request | Rate | Requests | p50 | p95 | p99 | Errors |
|---|---|---|---|---|---|---|
| Single event ingestion | 50 req/s | 3,000 | 19.6 ms | 33.5 ms | 56.9 ms | 0 |
| Query: newest page | mix of 25 req/s | 531 | 32.3 ms | 82.1 ms | 129.7 ms | 0 |
| Query: actor | | 271 | 34.0 ms | 118.0 ms | 162.5 ms | 0 |
| Query: resource | | 227 | 16.3 ms | 57.4 ms | 140.8 ms | 0 |
| Query: severity CRITICAL | | 222 | 32.2 ms | 84.2 ms | 136.0 ms | 0 |
| Query: action | | 156 | 31.8 ms | 68.6 ms | 121.8 ms | 0 |
| Query: metadata containment | | 94 | 63.8 ms | 139.2 ms | 765.5 ms | 0 |
| Query: next page by cursor (100 rows) | | 320 | 55.3 ms | 125.9 ms | 167.4 ms | 0 |

PostgreSQL needs at most 13 ms for any of these queries, and under 1 ms for most (see the
plans), so most of the query latency is spent outside the database: in the Django process
(authentication, serializing 50 or 100 events to JSON) and HTTP.

## Ingestion throughput

Closed model: N clients send bulk requests of 100 events back to back for 60 seconds.

| Clients | Requests | Events/s | p50 | p95 | p99 | Errors |
|---|---|---|---|---|---|---|
| 2 | 719 | 1,196 | 148.7 ms | 252.9 ms | 353.2 ms | 0 |
| 10 | 1,065 | 1,760 | 602.6 ms | 917.3 ms | 1,063.9 ms | 0 |

A `docker stats` sample 30 seconds into the 10-client run showed the web container at 198 % CPU
(its limit is 200 %), PostgreSQL at 116 % of 200 % and the worker at 66 % of 100 %. The limit is
CPU for request handling in the web tier, not the database: going from 2 to 10 clients added
47 % throughput and four times the median latency, which is queueing.

## Event-to-webhook latency

Time from an event's `created_at` (stamped in the ingest transaction just before commit) to the
receiver's acknowledgement of the signed webhook (`delivery.completed_at`), for every CRITICAL
event sent during the test, read from PostgreSQL. The receiver runs on the same host.

| Scenario | Events | Delivered | p50 | p95 | p99 | Max |
|---|---|---|---|---|---|---|
| Idle system, 20 CRITICAL events/s | 1,200 | 1,200 | 881 ms | 1,582 ms | 1,932 ms | 2,483 ms |
| During 10-client bulk ingestion, 10 events/s | 601 | 601 | 882 ms | 1,582 ms | 1,807 ms | 1,899 ms |

Every event was delivered. Part of this latency is by design: outbox drains are coalesced per
one-second window. In an earlier run, the time from event to drain averaged about 0.45 s
throughout a 60-second test, and the rest was queueing and delivery work on the worker's
single vCPU.

## Beyond capacity

Single events were scheduled at 200 req/s for 30 seconds. The service completed 4,880 requests
(148.8 req/s) without a single error, with a median latency of 2,419 ms (p95 2,902 ms) because
requests queued. k6 could not send the other 1,121 scheduled requests: all of its 400 virtual
users were waiting for responses. Overload therefore shows up as latency, not as failed or
lost requests.

## Run-to-run variation

The last three runs used the same schema and query code (they differed only in the Gunicorn
connection settings described below):

| Metric | Run 8 | Run 9 | Reference run |
|---|---|---|---|
| Bulk ingestion, 2 clients | 1,218 events/s | 1,362 events/s | 1,196 events/s |
| Bulk ingestion, 10 clients | 1,479 events/s | 1,811 events/s | 1,760 events/s |
| Single ingestion at 50 req/s, p95 | 45.7 ms | 28.4 ms | 33.5 ms |
| Beyond capacity, completed | 133.2 req/s | 145.0 req/s | 148.8 req/s |
| Webhook latency on an idle system, p50 | 918 ms | 917 ms | 881 ms |

CPU-bound results vary by up to about 20 % between runs on this shared VM, and individual runs
are not consistently higher or lower. Treat single numbers as approximate.

## How the numbers changed the code

The benchmark was run ten times during development, and the results fed back into the code:

* **Outbox dispatch flood.** The first run enqueued one outbox drain task per committed
  request. During bulk ingestion those mostly empty drains queued ahead of real deliveries,
  and the median event-to-webhook latency of the probe events was 19 seconds. Drains are now
  coalesced: at most one immediately and one at the end of a one-second window.
* **TLS context per delivery.** Measuring the worker showed that `httpx.Client()` loaded the
  CA bundle on every delivery, 11 ms of CPU each, on a worker limited to one vCPU. A shared
  verifying context removed that cost, and the dispatcher now creates deliveries with one bulk
  `INSERT ... ON CONFLICT DO NOTHING` instead of a `get_or_create` per row. Between two runs
  that differed only in these changes, the idle median latency fell from 1,525 ms to 875 ms and
  the 95th percentile from 3,070 ms to 1,514 ms (both runs measured up to the start of the
  delivery attempt; `completed_at` now also includes the HTTP round trip).
* **Query plans that depended on statistics.** As benchmark runs added recent rows whose actors,
  actions and metadata differed from the seeded history, plans that had been fast flipped: the
  busiest actor took 3,612 ms, an action common only in older rows 3,270 ms, an IP with no
  events 2,898 ms, a page 1.6 million rows deep 2,965 ms, and one metadata search hit the
  5-second statement timeout. Filter indexes now end in `(created_at, id)`, the selector pins
  the most selective filter to its index, unordered filters run a bounded recent probe before a
  selective plan, and the cursor predicate has an index bound. The same worst cases now take
  0.7 to 13 ms (table above).
* **Connections closed under the client.** Two runs had 2 and 3 failed bulk requests, all
  `EOF` within one second: a Gunicorn worker reaching `max_requests` closed keep-alive
  connections while clients were sending on them. With recycling off, one request still failed
  the same way on a connection that had been idle for Gunicorn's 5-second keep-alive limit.
  Recycling is now off by default (an option), and the keep-alive limit is 75 s, longer than
  common proxy idle timeouts, so the client side always closes first. The reference run had no
  failed request.
* **Closed-model latency.** Early runs reported latency from a fixed number of virtual users at
  saturation, which measures queueing rather than the service. Latency is now reported at fixed
  arrival rates below capacity, and saturation is shown separately.

## Limitations

* **Rare action prefixes.** The database collation (`en_US.utf8`) does not let a B-tree index
  serve `LIKE 'prefix%'`. A prefix that fills the page from the newest 10,000 rows is fast
  (`auth.`: 15 ms), but one that is rare there reads the whole window: `admin.`, 0.2 % of the
  rows and absent from the newest 10,000, took 2.1 s. Declaring the `action` column with the
  `C` collation would let the existing index serve prefixes.
* **Metadata values common only in older rows.** A metadata value that is frequent overall
  but missing from the newest 10,000 rows makes the second step read every match. For
  `{"mfa": true}` (80 % of the rows) that plan took 3.3 s; the API did not need it in this
  dataset because the first step filled the page.
* Both cases grow with the number of rows in the window and are bounded by the 5-second
  statement timeout, after which the API answers `503` without side effects. Combining them with
  an indexed filter or a shorter time window avoids them.
* The dataset is synthetic: seeded history with long-tail actors, plus the events the benchmark
  itself ingested in earlier runs, which is what exposed the uneven-distribution problems above.
* The benchmark raises rate limits; with the defaults, ingestion is capped at 1,200 requests per
  minute per service account before the service itself becomes the limit.
* Webhook latency includes the one-second coalescing window by design
  (`AUDIT_OUTBOX_DISPATCH_WINDOW_SECONDS`); the receiver is local, so internet round trips to
  real receivers come on top.
