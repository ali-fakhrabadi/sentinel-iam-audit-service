"""The database itself refuses to change or remove audit events."""

from __future__ import annotations

import importlib
from datetime import timedelta
from io import StringIO

import pytest
from django.conf import settings
from django.core.management import CommandError, call_command
from django.db import DatabaseError, connection, transaction
from django.utils import timezone

from apps.audit_logs.models import AuditEvent, OutboxMessage
from apps.webhooks.models import WebhookDelivery
from tests.factories import create_endpoint, create_event, create_service_account

pytestmark = pytest.mark.django_db


@pytest.fixture
def event() -> AuditEvent:
    return create_event(producer=create_service_account(), severity="INFO")


def test_updates_are_rejected_by_the_database(event: AuditEvent) -> None:
    with pytest.raises(DatabaseError, match="append-only"), transaction.atomic():
        AuditEvent.objects.filter(pk=event.pk).update(severity="CRITICAL")

    event.refresh_from_db()
    assert event.severity == "INFO"


def test_deletes_are_rejected_by_the_database(event: AuditEvent) -> None:
    with pytest.raises(DatabaseError, match="append-only"), transaction.atomic():
        AuditEvent.objects.filter(pk=event.pk).delete()

    assert AuditEvent.objects.filter(pk=event.pk).exists()


def test_truncate_is_rejected_by_the_database(event: AuditEvent) -> None:
    with transaction.atomic(), connection.cursor() as cursor:
        # Flush pending deferred FK checks from this transaction's inserts; otherwise
        # PostgreSQL refuses TRUNCATE before our trigger even runs.
        cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")
        with pytest.raises(DatabaseError, match="append-only"), transaction.atomic():
            cursor.execute("TRUNCATE audit_logs_auditevent CASCADE")

    assert AuditEvent.objects.filter(pk=event.pk).exists()


def test_retention_flag_permits_deletes_but_never_updates(event: AuditEvent) -> None:
    with transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute("SET LOCAL sentinel.audit_retention = 'on'")
        with pytest.raises(DatabaseError, match="UPDATE"), transaction.atomic():
            AuditEvent.objects.filter(pk=event.pk).update(severity="WARN")
        AuditEvent.objects.filter(pk=event.pk).delete()

    assert not AuditEvent.objects.filter(pk=event.pk).exists()


def test_purge_removes_only_expired_events_with_their_outbox_and_deliveries() -> None:
    account = create_service_account()
    endpoint, _ = create_endpoint()
    old = create_event(
        producer=account, severity="CRITICAL", created_at=timezone.now() - timedelta(days=400)
    )
    recent = create_event(producer=account, severity="CRITICAL")
    for item in (old, recent):
        OutboxMessage.objects.create(event=item)
        WebhookDelivery.objects.create(endpoint=endpoint, event=item)

    dry_run = StringIO()
    call_command("purge_audit_events", "--older-than-days", "365", "--dry-run", stdout=dry_run)
    assert "1 audit events" in dry_run.getvalue()
    assert AuditEvent.objects.filter(pk=old.pk).exists()

    output = StringIO()
    call_command("purge_audit_events", "--older-than-days", "365", stdout=output)

    assert "Deleted 1 audit events" in output.getvalue()
    assert not AuditEvent.objects.filter(pk=old.pk).exists()
    assert AuditEvent.objects.filter(pk=recent.pk).exists()
    assert not OutboxMessage.objects.filter(event_id=old.pk).exists()
    assert not WebhookDelivery.objects.filter(event_id=old.pk).exists()
    assert WebhookDelivery.objects.filter(event_id=recent.pk).exists()


def test_purge_refuses_short_retention_windows() -> None:
    with pytest.raises(CommandError, match="at least"):
        call_command("purge_audit_events", "--older-than-days", "1")


def test_migration_revokes_mutation_privileges_from_the_app_role() -> None:
    role = settings.DB_APP_ROLE
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", [role])
        if cursor.fetchone() is None:
            pytest.skip(f"database role {role!r} does not exist in this environment")
        cursor.execute(f"GRANT ALL ON audit_logs_auditevent TO {connection.ops.quote_name(role)}")

    migration = importlib.import_module("apps.audit_logs.migrations.0002_append_only_guards")
    with connection.schema_editor() as schema_editor:
        migration.revoke_mutation_privileges(None, schema_editor)

    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT has_table_privilege(%s, 'audit_logs_auditevent', 'INSERT'), "
            "has_table_privilege(%s, 'audit_logs_auditevent', 'SELECT'), "
            "has_table_privilege(%s, 'audit_logs_auditevent', 'UPDATE'), "
            "has_table_privilege(%s, 'audit_logs_auditevent', 'DELETE'), "
            "has_table_privilege(%s, 'audit_logs_auditevent', 'TRUNCATE')",
            [role] * 5,
        )
        assert cursor.fetchone() == (True, True, False, False, False)
