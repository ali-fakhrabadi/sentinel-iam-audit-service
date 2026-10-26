# Sentinel IAM & Audit Service

Headless Identity and Access Management (IAM), Role-Based Access Control (RBAC) and
append-only security audit logging microservice with HMAC-signed webhooks. It is built
API-first for React / Next.js / TypeScript SPAs and machine-to-machine clients.

> **Status:** under active development. The foundation (containers, database roles,
> dependency locking, CI) and the Django platform layer (structured logging, RFC 7807
> errors, probes, metrics, OpenAPI) are in place; the IAM, audit and webhook modules
> are being added phase by phase.

## Planned capabilities

- Email-based accounts, JWT authentication and a `GET /api/v1/accounts/me/` bootstrap endpoint
- Roles, permissions and scoped API keys for service accounts (prefix lookup + SHA-256 hash)
- High-volume audit event ingestion (single and bulk) with deterministic cursor pagination
- Transactional outbox and Celery webhook delivery signed with HMAC-SHA256, with SSRF protection
- OpenAPI 3 schema, Swagger UI and ReDoc; Prometheus metrics; liveness and readiness probes

## Technology stack

Python 3.12 · Django 5.2 LTS · Django REST Framework · PostgreSQL 16 · Celery + Redis ·
Gunicorn · Docker Compose · GitHub Actions

## Infrastructure design (in place)

| Area | Decision |
|---|---|
| Dependencies | `requirements.in` → hash-locked `requirements.txt` (`pip install --require-hashes`, wheels only) |
| Container | Multi-stage build, non-root UID 10001, read-only root filesystem, all Linux capabilities dropped |
| Networks | PostgreSQL and Redis sit on an internal network with no internet access; only the Celery worker gets egress (webhooks) |
| Database roles | Superuser for bootstrap only, a schema-owner role for migrations, and a data-only app role for runtime |
| Redis | Password-protected broker and cache, no persistence; PostgreSQL stays the source of truth |
| Metrics | Gunicorn is configured for Prometheus multiprocess mode, so `/metrics` can aggregate all workers |
| CI pipeline | Ruff, mypy, Django checks, migration drift, OpenAPI validation, pytest on real PostgreSQL/Redis, pip-audit, Trivy image scan, GHCR publish |
| Supply chain | GitHub Actions pinned to commit SHAs; Dependabot for actions and images |

## Authentication and authorization

| Caller | Credential | Used on |
|---|---|---|
| People (SPA, CLI) | JWT access token: `Authorization: Bearer <access>` | All `/api/v1/accounts/*` endpoints |
| Machines (log shippers, CI, SIEM connectors) | Service-account API key: `X-API-Key: sntl_<prefix>_<secret>` | Machine endpoints only (ingestion, introspection) |

The two credential types never unlock each other's endpoints. Authentication only
establishes identity; every endpoint then checks permission codes (`resource:action`):

* **Users** receive codes through roles. Built-in roles: `admin`, `iam_manager`,
  `security_analyst`, `auditor`; custom roles can be added.
* **API keys** carry explicit scopes, a mandatory expiry (90 days by default, 365 at most)
  and are stored as SHA-256 digests. The raw key is returned once, with `Cache-Control: no-store`.
* **No privilege escalation:** you can only grant, revoke or manage permissions you hold
  yourself, cannot change your own roles, and only superusers manage superusers.
* **Token lifecycle:** 15-minute access tokens, rotating single-use refresh tokens, logout
  blacklisting, and instant revocation of all tokens on password change or deactivation.
* Passwords are hashed with Argon2id; login and password endpoints are rate limited.

`GET /api/v1/accounts/me/` returns the profile, active role names and the sorted,
de-duplicated permission codes a frontend needs to render role-based UI.

## Audit events

`POST /api/v1/audit/events/bulk/` (API key with `audit:write`) ingests up to 500 events:

* every item is validated on its own; invalid items come back as `rejected` with field errors;
* all valid items are stored in **one** transaction. A `503` means nothing was stored, so
  retrying the whole request is always safe;
* an `idempotency_key` already used by the same service account returns `duplicate` with the
  original event ID (first write wins);
* `producer` is set by the server from the API key. `actor_id`, `ip_address`, `user_agent` and
  `occurred_at` are the producer's claims; `occurred_at` may be at most 5 minutes ahead and
  30 days old.

`GET /api/v1/audit/events/` filters by actor, action (exact or prefix), resource, severity,
IP address, time range and metadata containment. Pagination uses an opaque keyset cursor on
`(created_at, id)`, which stays stable and duplicate-free while new events arrive. Time
windows default to 30 days and are capped at 90. API keys only see events they produced.

**Append-only:** there is no update or delete API; a PostgreSQL trigger rejects `UPDATE`,
`DELETE` and `TRUNCATE` for every role; and the runtime role has no `UPDATE`/`DELETE`
privileges on the table. The only removal path is the retention command run as the schema
owner: `python manage.py purge_audit_events --older-than-days 365`. This is database-level
immutability, not cryptographic tamper evidence: a database superuser can still disable
triggers.

Sentinel audits itself: role grants, API key issuance and revocation, user deactivation,
password changes and webhook changes are recorded as events in the same transaction.

## Webhooks

WARN and CRITICAL events are written to a transactional outbox together with the event. A
Celery task drains it right after commit (and every 30 s as a safety net), creating one
delivery per matching endpoint. Endpoints subscribe by minimum severity and optional action
prefixes.

```
POST <your endpoint>
X-Sentinel-Event-Id:  6f1c2c1e-...        # de-duplication key (delivery is at-least-once)
X-Sentinel-Timestamp: 1790000000
X-Sentinel-Signature: t=1790000000,v1=<hex>[,v1=<hex during secret rotation>]
```

The signature is `HMAC_SHA256(secret, f"{timestamp}.{event_id}." + raw_body)`. Verify it
on the receiver like this:

```python
import hashlib, hmac, time

def verify(secret: str, header: str, event_id: str, body: bytes, tolerance: int = 300) -> bool:
    timestamp, candidates = None, []
    for item in header.split(","):
        key, _, value = item.strip().partition("=")
        if key == "t" and value.isdigit():
            timestamp = int(value)
        elif key == "v1":
            candidates.append(value)
    if timestamp is None or abs(time.time() - timestamp) > tolerance:  # stale or replayed
        return False
    message = f"{timestamp}.{event_id}.".encode() + body
    expected = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, candidate) for candidate in candidates)
```

Retries use exponential backoff with jitter (30 s base, 30 min cap) for timeouts, connection
errors, `408`, `425`, `429` and `5xx`; other `4xx` and redirects fail permanently. The default
of 5 retries means at most 6 attempts. Signing secrets are stored encrypted (Fernet); after a
rotation both secrets sign for 24 hours.

**SSRF protection:** destinations must be `https`, without credentials, and every resolved
address must be public (loopback, RFC 1918, CGNAT, link-local including `169.254.169.254`,
multicast and reserved ranges are rejected, also as IPv4-mapped IPv6). The client connects to
the validated address with SNI set to the host name, so DNS rebinding cannot redirect it, and
redirects are never followed. Production deployments should still restrict egress at the
network layer.

## Operational endpoints

| Endpoint | Purpose | Access |
|---|---|---|
| `GET /health/live/` | Liveness: the process can serve requests (no dependency checks) | Public |
| `GET /health/ready/` | Readiness: PostgreSQL and Redis reachable, bounded timeouts; 503 otherwise | Public |
| `GET /metrics` | Prometheus metrics aggregated across Gunicorn workers | `Authorization: Bearer $METRICS_AUTH_TOKEN` |
| `GET /api/schema/` | OpenAPI 3 schema (`?format=json` for JSON) | Public |
| `GET /api/docs/` | Swagger UI (self-hosted assets, no CDN) | Public |
| `GET /api/redoc/` | ReDoc | Public |

Probes and metrics are exempt from the HTTPS redirect and from CORS, and they never
return hostnames, connection strings or error messages.

## Error format

Every error is an RFC 7807 problem document served as `application/problem+json`:

```json
{
  "type": "urn:sentinel:problem:validation-error",
  "title": "Request validation failed",
  "status": 400,
  "detail": "One or more fields are invalid.",
  "instance": "/api/v1/audit/events/bulk/",
  "request_id": "9b2f7c0e4d1a4c3e8f6b5a2d1c0e9f8a",
  "errors": [{ "field": "events.3.severity", "message": "\"BOGUS\" is not a valid choice.", "code": "invalid_choice" }]
}
```

Every response carries `X-Request-ID` (a caller-supplied value is kept if it is safe).
The same ID appears in the JSON logs, so a client-reported error can be traced end to end.

## Logging

All processes (Gunicorn, Django, Celery) write one JSON object per line to stdout with
`timestamp`, `level`, `logger`, `message` and `request_id`. Values under sensitive keys
(`password`, `authorization`, `token`, `api_key`, `secret`, ...) and credential-shaped
strings (JWTs, `sntl_` API keys, bearer tokens) are redacted before they are written.
Query strings are never logged.

## Quick start

Requirements: Docker with Compose v2, GNU make, Python 3 (only for generating `.env`).

```bash
make env     # create .env with generated secrets
make up      # build, migrate and start; waits for health checks
make ps      # service status
make help    # all commands
```

To expose the API on your LAN instead of localhost:

```bash
make env ENV_ARGS="--set SENTINEL_BIND_ADDRESS=0.0.0.0 --set DJANGO_ALLOWED_HOSTS=192.0.2.10,localhost,127.0.0.1"
```

## Development commands

| Command | Purpose |
|---|---|
| `make test` | pytest with coverage against real PostgreSQL and Redis containers |
| `make lint` / `make format` | Ruff lint and format |
| `make typecheck` | mypy with the Django and DRF plugins |
| `make check` | Django system checks and migration drift detection |
| `make schema` | Validate and export the OpenAPI schema |
| `make audit` | pip-audit on the locked runtime dependencies |
| `make ci` | Everything CI runs |
| `make lock` | Re-resolve and hash-pin dependencies for Python 3.12 / Linux |

## License

[MIT](LICENSE)
