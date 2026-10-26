# Operations guide

## Deployment options

| Option | Use it for | Entry point |
|---|---|---|
| Docker Compose | Single host, demos, small installations | `make env && make up` |
| Helm chart | Kubernetes (tested in CI on kind, Kubernetes 1.35) | `charts/sentinel` |

Both run the same image: Gunicorn (`web`), a Celery worker (`worker`), a single Celery beat
scheduler (`beat`) and a one-shot migration step that runs as the schema owner.

## Database roles

| Role | Used by | Privileges |
|---|---|---|
| bootstrap superuser | PostgreSQL container, test runner | everything; never used by the application |
| `sentinel_owner` | migrations, retention purge | owns the schema (DDL) |
| `sentinel_app` | web, worker, beat | `SELECT/INSERT/UPDATE/DELETE` on application tables, but only `SELECT/INSERT` on `audit_logs_auditevent` |

Every statement issued by the application is bounded by `DB_STATEMENT_TIMEOUT_MS`
(5 s by default); migrations run without that limit.

## Secret rotation

| Secret | Effect of rotation | Procedure |
|---|---|---|
| `DJANGO_SECRET_KEY` | Django admin sessions end | Replace and redeploy. |
| `JWT_SIGNING_KEY` | Every access and refresh token becomes invalid; users log in again | Replace and redeploy, ideally in a quiet window. |
| `METRICS_AUTH_TOKEN` | Prometheus scrapes fail until updated | Update the Prometheus scrape config, then redeploy. |
| `WEBHOOK_SECRET_ENCRYPTION_KEYS` | None if done in order | 1. Prepend a new Fernet key and deploy. 2. `python manage.py reencrypt_webhook_secrets`. 3. Remove the old key and deploy. |
| Webhook signing secret (per endpoint) | None: both secrets sign for 24 h | `POST /api/v1/webhooks/endpoints/{id}/rotate-secret/`, update the receiver within the grace period. |
| Service-account API key | Revoked keys fail immediately | Issue a new key, roll it out, revoke the old one. |
| Database and Redis passwords | Connections fail until updated | `ALTER ROLE ... PASSWORD`, update the secret, redeploy. |

## Backup and restore

* Back up with `pg_dump --format=custom` as `sentinel_owner` (or the superuser); Redis holds
  no state that needs backing up.
* Restores re-insert rows, which the append-only trigger allows (it only blocks `UPDATE`,
  `DELETE` and `TRUNCATE`).
* After restoring into a fresh cluster, run `docker/postgres/initdb/10-create-roles.sh` (or
  create the roles yourself) before `migrate`, so `sentinel_app` regains its restricted grants.
* Webhook secrets are encrypted with `WEBHOOK_SECRET_ENCRYPTION_KEYS`: keep those keys in the
  secret store, separately from database backups. A backup without the keys cannot sign webhooks.

## Audit retention

Audit events are append-only; retention is the only sanctioned way to remove them:

```bash
# Compose: the migrate service runs as the schema owner
docker compose run --rm migrate python manage.py purge_audit_events --older-than-days 365 --dry-run
docker compose run --rm migrate python manage.py purge_audit_events --older-than-days 365
```

* Retention below `AUDIT_RETENTION_MIN_DAYS` (30 by default) is refused.
* Deletion happens in batches (default 5,000 rows per transaction) to keep locks short. Each
  batch sets `sentinel.audit_retention = 'on'` for that transaction only. The trigger accepts
  that flag for `DELETE`, never for `UPDATE`.
* Outbox messages and webhook delivery records of purged events are deleted with them.
* On Kubernetes, run the command as a `CronJob` that uses the owner credentials (like the
  migration Job).

## Large-table maintenance

* The audit table is insert-only, so it does not bloat from updates. Autovacuum still needs
  to set visibility-map bits, which keep index-only scans cheap. With the default settings
  this happens on its own; for very high ingest rates lower
  `autovacuum_vacuum_insert_scale_factor` for this table.
* Run `ANALYZE audit_logs_auditevent` after bulk imports so the planner's statistics stay current.
* Index choice is documented on the model and in `apps/audit_logs/selectors.py`, and verified
  with `loadtest/explain_queries.py` (results in [performance.md](performance.md)). The script
  prints `designed index used: yes/NO` for every query, including worst cases; run it after
  PostgreSQL upgrades or index changes, because a `NO` means a page may read the whole window.

## Partitioning (not enabled yet)

At 2.9 million rows the table takes 681 MB and its twelve indexes 1,479 MB (2.2 GB in total).
Every indexed filter reads one bounded index range, including the worst cases; the remaining
exceptions are listed in [performance.md](performance.md#limitations). The indexes are the price
of that: each searchable filter has its own, so plan storage at about three times the raw table
size. Monthly range partitioning on
`created_at` becomes worthwhile in the hundreds of millions of rows, mainly to make
retention a `DETACH`/`DROP PARTITION` instead of batched deletes. It is not enabled now
because:

* PostgreSQL requires the partition key in every unique constraint, so the primary key
  becomes `(id, created_at)` and the idempotency constraints must include `created_at`. That
  changes how duplicate keys are detected across partitions;
* the append-only trigger and the privilege grants must be applied to every partition;
* the cursor and the indexes already keep page reads independent of table size.

## Monitoring

`/metrics` (bearer token) exports:

| Metric | Meaning | Suggested alert |
|---|---|---|
| `sentinel_audit_events_ingested_total{result}` | Ingestion outcomes | Sudden rise of `rejected` |
| `sentinel_outbox_pending_messages` | Committed events not yet dispatched | > 0 for 5 min |
| `sentinel_outbox_oldest_pending_age_seconds` | Dispatch lag | > 300 |
| `sentinel_webhook_deliveries{status}` | Delivery states | `exhausted` or `failed` increasing |
| `django_http_requests_*`, `django_db_*` | Request rate, latency, errors, DB queries | p95 latency, 5xx ratio |

Logs are JSON on stdout. Correlate a client error with logs using the `request_id` from the
problem response or the `X-Request-ID` header.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `400 Bad Request` with an HTML body on every request | Host not in `DJANGO_ALLOWED_HOSTS` | Add the host. Keep `127.0.0.1` and `localhost` for health checks. |
| Health checks fail behind HTTPS | Probes follow the HTTPS redirect | They should not: `/health/` and `/metrics` are exempt. Check that the probe sends an allowed `Host`. |
| `/health/ready/` is 503 | PostgreSQL or Redis unreachable | The web logs contain the failing check (`Readiness check failed: ...`). |
| Webhooks stay `retrying` with `private_address` | The destination resolves to a private address | Use a public HTTPS endpoint; SSRF protection blocks internal targets by design. |
| Webhooks never leave `pending` | Worker or beat not running, or broker down | `docker compose ps`, `celery inspect ping`; the outbox is replayed once the worker is back. |
| `401` with `invalid-token` right after a password change | Expected: tokens are revoked | Log in again. |
| Event `rejected` with `credentials must not be stored in metadata` | A metadata key or value looks like a secret | Remove credentials from the event metadata. |
| `manage.py check` reports `webhooks.E00x` | Missing or malformed Fernet key | Generate one: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
