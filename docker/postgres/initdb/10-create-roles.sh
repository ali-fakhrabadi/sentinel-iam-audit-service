#!/usr/bin/env bash
# Runs once, when the PostgreSQL data volume is first initialised.
#
# Creates two least-privilege roles on top of the bootstrap superuser:
#   DB_OWNER_USER  owns the database and schema; runs migrations (DDL)
#   DB_APP_USER    used by the API and Celery; data access only (no DDL)
#
# Audit-table restrictions (no UPDATE/DELETE/TRUNCATE for the app role) are applied
# by the audit_logs migrations, because that table does not exist yet at this point.
set -e

: "${DB_OWNER_USER:?DB_OWNER_USER is required}"
: "${DB_OWNER_PASSWORD:?DB_OWNER_PASSWORD is required}"
: "${DB_APP_USER:?DB_APP_USER is required}"
: "${DB_APP_PASSWORD:?DB_APP_PASSWORD is required}"

psql --no-psqlrc -v ON_ERROR_STOP=1 \
    --username "${POSTGRES_USER}" \
    --dbname "${POSTGRES_DB}" \
    --set=db="${POSTGRES_DB}" \
    --set=owner="${DB_OWNER_USER}" \
    --set=owner_password="${DB_OWNER_PASSWORD}" \
    --set=app="${DB_APP_USER}" \
    --set=app_password="${DB_APP_PASSWORD}" <<'SQL'
CREATE ROLE :"owner" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'owner_password';
CREATE ROLE :"app" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'app_password';

ALTER DATABASE :"db" OWNER TO :"owner";
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE :"db" TO :"app";

ALTER SCHEMA public OWNER TO :"owner";
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO :"app";

-- Tables and sequences created later by the owner (migrations) are usable by the app role.
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :"app";
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO :"app";

-- Query statistics for EXPLAIN-driven index tuning (readable by the owner, not the app).
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
GRANT pg_read_all_stats TO :"owner";
SQL
