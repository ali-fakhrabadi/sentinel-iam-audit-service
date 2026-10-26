# Load and performance testing

Everything needed to reproduce the numbers in [docs/performance.md](../docs/performance.md).

| File | Purpose |
|---|---|
| `seed_audit_events.py` | Inserts a representative dataset (default 1,000,000 events over 60 days) |
| `explain_queries.py` | `EXPLAIN (ANALYZE, BUFFERS)` for the exact ORM queries the API issues |
| `k6/ingest_bulk.js` | Bulk ingestion (closed model: N virtual users, 100 events per request) |
| `k6/ingest_single.js` | Single-event ingestion at a fixed arrival rate (open model) |
| `k6/query.js` | Weighted mix of audit queries and deep cursor pagination at a fixed rate |
| `webhook_receiver.py` | Local receiver for the event-to-webhook latency test |
| `docker-compose.loadtest.yml` | Benchmark-only overrides (see below) |
| `run_benchmarks.sh` | Runs everything and writes `results/` |
| `summarize_k6.py` | Turns k6 JSON summaries into the Markdown table |

## Running

```bash
# 1. Seed the database (about 4 minutes for one million events)
docker compose --profile dev run --rm -e SEED_EVENTS=1000000 dev \
    python manage.py shell -c "exec(open('loadtest/seed_audit_events.py').read())"

# 2. Run the suite (about 10 minutes); k6 runs in Docker on the same host
bash loadtest/run_benchmarks.sh
```

## Methodology

* **Open vs closed model.** Latency is measured with a fixed arrival rate (k6
  `constant-arrival-rate`) below saturation, as real clients behave. Throughput is
  measured separately with a fixed number of concurrent clients. A saturation run then shows
  what happens beyond capacity. Reporting closed-model latency at saturation would mostly
  measure queueing.
* **Rate limits** are raised in `docker-compose.loadtest.yml`; otherwise the test would
  measure the throttle instead of the service.
* **Webhook latency** is measured from PostgreSQL: `delivery.completed_at - event.created_at`
  for every delivered event. `created_at` is stamped in the ingest transaction just before it
  commits; `completed_at` is the start of the successful attempt plus its HTTP round trip,
  i.e. when the receiver acknowledged the signed request. The receiver runs inside the Docker network, so the
  benchmark enables the SSRF development override for the worker only. That override only
  works with `DEBUG` on, which the API never has in this setup.
* **Resources**: the default container limits from `docker-compose.yml` are kept (web 2 vCPU,
  PostgreSQL 2 vCPU, worker 1 vCPU), so the numbers describe the default deployment, not
  the host.
* Every run starts by printing the environment (CPU, memory, PostgreSQL version, dataset size)
  into `results/environment.txt`.
