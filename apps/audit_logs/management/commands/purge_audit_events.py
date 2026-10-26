"""Retention: delete audit events older than a cut-off, in batches.

This is the only sanctioned way to remove audit events. It must run with the schema
owner role, because the application role has no DELETE privilege on the table::

    docker compose run --rm migrate python manage.py purge_audit_events --older-than-days 365

Each batch sets ``sentinel.audit_retention = 'on'`` for its own transaction only,
which the append-only trigger accepts for DELETE (never for UPDATE). Outbox messages
and webhook deliveries of purged events are removed with them.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import connection, transaction
from django.utils import timezone

from apps.audit_logs.models import AuditEvent


class Command(BaseCommand):
    help = "Delete audit events older than N days (run as the schema owner role)."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--older-than-days", type=int, required=True)
        parser.add_argument("--batch-size", type=int, default=5000)
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args: Any, **options: Any) -> None:
        days: int = options["older_than_days"]
        minimum: int = settings.AUDIT_RETENTION_MIN_DAYS
        if days < minimum:
            raise CommandError(f"--older-than-days must be at least {minimum}.")
        batch_size: int = options["batch_size"]
        if batch_size < 1:
            raise CommandError("--batch-size must be positive.")

        cutoff = timezone.now() - timedelta(days=days)
        expired = AuditEvent.objects.filter(created_at__lt=cutoff)
        if options["dry_run"]:
            self.stdout.write(
                f"{expired.count()} audit events older than {cutoff.isoformat()} would be deleted."
            )
            return

        total = 0
        while True:
            with transaction.atomic():
                with connection.cursor() as cursor:
                    cursor.execute("SET LOCAL sentinel.audit_retention = 'on'")
                ids = list(
                    expired.order_by("created_at", "id").values_list("id", flat=True)[:batch_size]
                )
                if not ids:
                    break
                AuditEvent.objects.filter(id__in=ids).delete()
                total += len(ids)
        self.stdout.write(f"Deleted {total} audit events older than {cutoff.isoformat()}.")
