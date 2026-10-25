# Sentinel IAM & Audit Service

Headless Identity and Access Management (IAM), Role-Based Access Control (RBAC) and
append-only security audit logging microservice with HMAC-signed webhooks. It is built
API-first for React / Next.js / TypeScript SPAs and machine-to-machine clients.

> **Status:** under active development. The foundation (containers, database roles,
> dependency locking and CI) is in place; the application modules are being added
> phase by phase. This README is expanded with full API documentation as features land.

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
