# Architecture and design decisions

## Components and trust boundaries

| Boundary | Who is on the other side | Controls |
|---|---|---|
| Internet → API | SPAs and people (JWT), machines (API keys) | TLS at the edge, strict input serializers, request size limit, rate limits, RFC 7807 errors without internals |
| Human ↔ machine credentials | Two authentication policies | JWT-only endpoints for people; API-key-only ingestion; per-method principal checks where both are accepted |
| Authenticated → authorized | Every caller | Permission codes per HTTP method, deny by default; API keys carry scopes; privilege-escalation guard in services |
| Application → PostgreSQL | Runtime role `sentinel_app` | No DDL, no `UPDATE`/`DELETE` on audit events, 5 s statement timeout; append-only trigger for every role |
| Application → Redis | Broker and cache | Password, internal network only, holds no source-of-truth data |
| Worker → webhook receivers | Untrusted URLs | SSRF validation of every resolved address, IP pinning with SNI, no redirects, timeouts, HMAC signatures |
| Network | Containers / pods | PostgreSQL and Redis on an internal network; only the worker may egress, and on Kubernetes only to public ranges |

## Module structure

```
config/            settings, URLs, Celery app, logging, middleware, errors, probes, metrics, OpenAPI
apps/accounts/     users, RBAC, service accounts, API keys, JWT/API-key authentication
apps/audit_logs/   audit events, ingestion, querying, transactional outbox, retention
apps/webhooks/     endpoints, outbox dispatch, signed delivery, SSRF protection
```

Each app keeps business rules in `services.py` (writes) and `selectors.py` (reads). Views
validate input, call a service or selector and shape the response; Celery tasks are
one-line wrappers around services. Dependencies point one way: `audit_logs` and
`webhooks` use `accounts` for identities; `webhooks` consumes the `audit_logs` outbox;
`accounts` records its own changes through `audit_logs.services.record_internal_event`.
`audit_logs` never imports `webhooks`: it triggers dispatch through a Celery task name.

## Decisions

### 1. Django 5.2 LTS on Python 3.12
Django 6.1 was available, but `django-prometheus` did not support it, and 5.2 is the long-term
release (security fixes until April 2028). All dependencies are hash-locked with `uv`, and
images install wheels only.

### 2. Separate input and output serializers that reject unknown fields
Inputs list exactly the fields a caller may set; an unexpected field (`is_superuser`,
`producer_user`, `created_at`) is a 400 instead of being silently ignored. Outputs never share a
class with inputs, which also yields clean `*Request`/response types for TypeScript generators
(`COMPONENT_SPLIT_REQUEST`).

### 3. API keys hashed with SHA-256, passwords with Argon2id
Keys carry 256 bits of randomness, so a fast hash cannot be brute-forced and avoids Argon2's
cost on every machine request. Lookup uses a non-secret 8-character prefix; verification is
constant time; every failure returns the same message. Passwords are low-entropy, hence Argon2id.

### 4. "You can only grant what you hold"
`roles:manage` alone would otherwise be equivalent to `admin`. Every privilege-changing service
checks that the actor holds the permissions involved (for role edits: both added and removed
ones), forbids self-assignment, and protects superusers. API key scopes follow the same rule.

### 5. Append-only audit log in three layers, without claiming tamper-proofing
No mutation API, a trigger that rejects `UPDATE`/`DELETE`/`TRUNCATE` for all roles, and revoked
privileges for the runtime role. A hash chain was considered and rejected for now: under
concurrent bulk ingestion it serializes inserts, and without external anchoring it still does not
stop a database superuser. The documentation states this limit explicitly.

### 6. Bulk ingestion: per-item validation, one transaction for the valid set
Clients get a precise per-item report, but storage is all-or-nothing for the valid items, so a
failure never leaves a client guessing what was committed (503 = nothing stored). Idempotency
keys use `INSERT ... ON CONFLICT DO NOTHING` against partial unique indexes, which is race-free
under concurrent retries and needs no read-before-write lock.

### 7. Keyset pagination on `(created_at, id)`
`OFFSET` pagination slows down linearly and shifts when rows arrive; timestamp-only cursors break
on ties (bulk inserts share `created_at`). The cursor predicate is
`created_at <= c AND (created_at < c OR (created_at = c AND id < i))`: the first term is
redundant logically but is what lets PostgreSQL start the index scan at the cursor. Without it,
a page 1.6 million rows deep read and discarded every newer row (3 s); with it, the deepest page
costs about as much as the first, around a millisecond ([measured](performance.md)).

### 8. Transactional outbox with coalesced dispatch
Publishing to Celery after commit can lose messages; the outbox row commits with the event, and
a beat loop replays anything missed. The first benchmark showed that triggering one drain per
commit flooded the queue (p50 event-to-webhook latency of 19 s during bulk ingestion). Drains are
now coalesced per one-second window: one runs immediately, one at the window's end. The window
trades up to one second of latency for a bounded number of drain tasks; the measured end-to-end
latency is in [performance.md](performance.md#event-to-webhook-latency).

### 9. Webhook secrets encrypted, not hashed; dual signing during rotation
The service must produce HMACs, so secrets are recoverable: Fernet with keys from the
environment (MultiFernet allows key rotation). Rotating an endpoint secret keeps the old secret
signing for 24 h, so receivers switch without dropped deliveries.

### 10. SSRF: resolve, validate every address, pin the connection
Validating a hostname and then letting the HTTP client resolve it again is vulnerable to DNS
rebinding. Sentinel resolves once, rejects the host if any address is non-public, connects to
the validated address and keeps TLS verification through SNI. Redirects are not followed. The
Helm chart repeats the restriction as a NetworkPolicy.

### 11. Metrics from two sources
Gunicorn workers share counters through Prometheus multiprocess mode. Work done by Celery (which
Prometheus does not scrape) is reported as gauges computed from PostgreSQL at scrape time, which
is always consistent with the source of truth.

### 12. Page queries that do not depend on planner estimates
PostgreSQL assumes filtered values are spread evenly over time, so for a value that looks
common it walks the time index and filters. When the value is absent from recent rows, that
reads the whole window: on 2 million rows, 3.3 s for an action, 3.6 s for an actor, and over the
5 s statement timeout for a metadata value. Two measures make the fast plan structural rather than statistical:

* **Pinned filter.** Each searchable equality filter (actor, IP, resource, producing service
  account, action, severity) has an index ending in `(created_at, id)`. The selector writes the
  most selective one as `column = ANY(ARRAY[value])` and puts it first in `ORDER BY`: the same
  rows in the same order, but only that filter's index can return them without a sort.
* **Recent probe, then selective plan.** Metadata containment, action prefixes and multiple
  severities have no index in time order. They are first applied to the newest 10,000 rows of
  the window (exact if that fills the page, since all other matches are older); otherwise the
  page is sorted on an expression no index provides, so PostgreSQL reads only the matches
  through the filter's index (GIN for metadata).

The remaining slow case is documented: a metadata value common in old rows but absent from the
newest 10,000 still reads every match. Both techniques are explained in `selectors.py`,
covered by tests that page through every query shape with both probe paths and compare rows and
order with the expected result, and checked on the benchmark database by `explain_queries.py`.
