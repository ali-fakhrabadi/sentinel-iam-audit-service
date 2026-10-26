"""Database-level append-only guarantees for audit events.

1. A trigger rejects UPDATE, DELETE and TRUNCATE on ``audit_logs_auditevent`` for
   every role, including the table owner. DELETE/TRUNCATE are allowed only when the
   current transaction set ``sentinel.audit_retention = 'on'``, which the
   ``purge_audit_events`` command does for its own batches.
2. The runtime role (``settings.DB_APP_ROLE``) loses UPDATE, DELETE and TRUNCATE
   privileges on the table, so even a compromised application process cannot set
   the retention flag and delete events. Skipped when the role does not exist
   (single-role setups such as CI).

Limits: a superuser can disable triggers; these guards stop application bugs and
compromised app credentials, not a malicious database administrator.
"""

from django.conf import settings
from django.db import migrations

TABLE = "audit_logs_auditevent"

# Statements are listed individually so Django does not try to split the
# dollar-quoted function body.
CREATE_GUARDS = [
    """
    CREATE FUNCTION audit_logs_block_mutation() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        IF TG_OP IN ('DELETE', 'TRUNCATE')
           AND coalesce(current_setting('sentinel.audit_retention', true), '') = 'on' THEN
            IF TG_OP = 'DELETE' THEN
                RETURN OLD;
            END IF;
            RETURN NULL;
        END IF;
        RAISE EXCEPTION 'audit events are append-only: % is not allowed', TG_OP
            USING ERRCODE = 'insufficient_privilege',
                  HINT = 'Use the purge_audit_events management command for retention.';
    END;
    $$
    """,
    f"""
    CREATE TRIGGER audit_event_block_update
        BEFORE UPDATE ON {TABLE}
        FOR EACH ROW EXECUTE FUNCTION audit_logs_block_mutation()
    """,
    f"""
    CREATE TRIGGER audit_event_block_delete
        BEFORE DELETE ON {TABLE}
        FOR EACH ROW EXECUTE FUNCTION audit_logs_block_mutation()
    """,
    f"""
    CREATE TRIGGER audit_event_block_truncate
        BEFORE TRUNCATE ON {TABLE}
        FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_block_mutation()
    """,
]

DROP_GUARDS = [
    f"DROP TRIGGER IF EXISTS audit_event_block_truncate ON {TABLE}",
    f"DROP TRIGGER IF EXISTS audit_event_block_delete ON {TABLE}",
    f"DROP TRIGGER IF EXISTS audit_event_block_update ON {TABLE}",
    "DROP FUNCTION IF EXISTS audit_logs_block_mutation()",
]


def _app_role_exists(schema_editor) -> bool:
    with schema_editor.connection.cursor() as cursor:
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", [settings.DB_APP_ROLE])
        return cursor.fetchone() is not None


def revoke_mutation_privileges(apps, schema_editor):
    if _app_role_exists(schema_editor):
        role = schema_editor.quote_name(settings.DB_APP_ROLE)
        schema_editor.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON {TABLE} FROM {role}")


def restore_mutation_privileges(apps, schema_editor):
    if _app_role_exists(schema_editor):
        role = schema_editor.quote_name(settings.DB_APP_ROLE)
        schema_editor.execute(f"GRANT UPDATE, DELETE ON {TABLE} TO {role}")


class Migration(migrations.Migration):
    dependencies = [("audit_logs", "0001_initial")]

    operations = [
        migrations.RunSQL(CREATE_GUARDS, reverse_sql=DROP_GUARDS),
        migrations.RunPython(revoke_mutation_privileges, restore_mutation_privileges),
    ]
