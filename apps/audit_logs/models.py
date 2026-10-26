"""Audit events and the transactional outbox.

Trust model for an event:
* ``producer_*`` is set by the server from the authenticated principal and is
  trustworthy. Exactly one producer is recorded per event.
* ``actor_id``, ``ip_address``, ``user_agent`` and ``occurred_at`` are claims made
  by the producer about something that happened in its own system. They are
  validated and stored as reported, never treated as verified identities.

Timestamps:
* ``occurred_at``  optional producer-supplied time of the action (bounded skew/age)
* ``received_at``  when Sentinel received the HTTP request carrying the event
* ``created_at``   when Sentinel persisted the row; ordering and cursor key

Integrity: rows are append-only. The API exposes no update or delete, and a
PostgreSQL trigger (migration 0002) rejects UPDATE, DELETE and TRUNCATE except for
the explicit retention procedure. This is application- and database-level
immutability, not cryptographic tamper evidence.
"""

from __future__ import annotations

import uuid
from typing import ClassVar

from django.contrib.postgres.indexes import GinIndex
from django.db import models
from django.db.models import Q
from django.utils import timezone

from apps.accounts.models import ServiceAccount, User

ACTION_PATTERN = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,5}$"
RESOURCE_TYPE_PATTERN = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){0,4}$"


class Severity(models.TextChoices):
    INFO = "INFO", "Info"
    WARN = "WARN", "Warning"
    CRITICAL = "CRITICAL", "Critical"


SEVERITY_RANK: dict[str, int] = {Severity.INFO: 0, Severity.WARN: 1, Severity.CRITICAL: 2}


class AuditEvent(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    action = models.CharField(max_length=128, help_text="Dotted, lowercase, e.g. auth.login.failed")
    resource_type = models.CharField(max_length=64, help_text="Dotted, lowercase, e.g. iam.user")
    # NULL (not provided) is deliberately distinct from "": partial indexes and the
    # idempotency constraints below rely on it, hence the DJ001 exceptions.
    resource_id = models.CharField(max_length=255, null=True, blank=True)  # noqa: DJ001
    actor_id = models.CharField(  # noqa: DJ001
        max_length=255,
        null=True,
        blank=True,
        help_text="Actor identifier as reported by the producer (an unverified claim).",
    )
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True, default="")
    severity = models.CharField(max_length=8, choices=Severity.choices)
    metadata = models.JSONField(default=dict, blank=True)
    occurred_at = models.DateTimeField(null=True, blank=True)
    received_at = models.DateTimeField()
    created_at = models.DateTimeField(default=timezone.now)
    # PROTECT: principals with audit history are deactivated, never deleted, because
    # SET_NULL or CASCADE would have to modify append-only rows.
    # Indexed by audit_producer_created_id_idx below, which also serves PROTECT checks.
    producer_service_account = models.ForeignKey(
        ServiceAccount,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="+",
        db_index=False,
    )
    producer_user = models.ForeignKey(
        User, on_delete=models.PROTECT, null=True, blank=True, related_name="+"
    )
    idempotency_key = models.CharField(  # noqa: DJ001
        max_length=128,
        null=True,
        blank=True,
        help_text="Producer-chosen key; resubmitting it returns the original event.",
    )

    class Meta:
        ordering: ClassVar[list[str]] = ["-created_at", "-id"]
        indexes: ClassVar[list[models.Index]] = [
            # Deterministic keyset pagination and time-range scans (newest first).
            models.Index(fields=["created_at", "id"], name="audit_created_id_idx"),
            # Filter indexes end in (created_at, id), the full sort key, so a filtered page
            # is one ordered index range with no sort step; selectors.page_queryset makes
            # sure PostgreSQL uses them (see its module docstring for the measurements).
            # "What did this actor do?" Partial: most machine events have no actor.
            models.Index(
                fields=["actor_id", "created_at", "id"],
                name="audit_actor_created_id_idx",
                condition=Q(actor_id__isnull=False),
            ),
            # "History of this resource."
            models.Index(
                fields=["resource_type", "resource_id", "created_at", "id"],
                name="audit_resource_created_id_idx",
            ),
            models.Index(fields=["action", "created_at", "id"], name="audit_action_created_id_idx"),
            # "What came from this address?" Real traffic has many distinct IPs, so most
            # lookups are rare values: without this index they scan the whole time window.
            models.Index(
                fields=["ip_address", "created_at", "id"],
                name="audit_ip_created_id_idx",
                condition=Q(ip_address__isnull=False),
            ),
            # API keys only read their own producer's events.
            models.Index(
                fields=["producer_service_account", "created_at", "id"],
                name="audit_producer_created_id_idx",
                condition=Q(producer_service_account__isnull=False),
            ),
            # Alert views read WARN/CRITICAL only; INFO dominates volume, so it is excluded.
            models.Index(
                fields=["severity", "created_at", "id"],
                name="audit_severity_created_id_idx",
                condition=~Q(severity=Severity.INFO),
            ),
            # Containment queries (metadata @> '{...}'); jsonb_path_ops is smaller and
            # faster than the default operator class for @>.
            GinIndex(fields=["metadata"], name="audit_metadata_gin", opclasses=["jsonb_path_ops"]),
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(
                condition=Q(severity__in=Severity.values), name="audit_severity_valid"
            ),
            models.CheckConstraint(
                condition=Q(action__regex=ACTION_PATTERN), name="audit_action_format"
            ),
            models.CheckConstraint(
                condition=Q(resource_type__regex=RESOURCE_TYPE_PATTERN),
                name="audit_resource_type_format",
            ),
            models.CheckConstraint(
                condition=(
                    Q(producer_service_account__isnull=False, producer_user__isnull=True)
                    | Q(producer_service_account__isnull=True, producer_user__isnull=False)
                ),
                name="audit_exactly_one_producer",
            ),
            models.UniqueConstraint(
                fields=["producer_service_account", "idempotency_key"],
                condition=Q(idempotency_key__isnull=False, producer_service_account__isnull=False),
                name="audit_idempotency_sa_unique",
            ),
            models.UniqueConstraint(
                fields=["producer_user", "idempotency_key"],
                condition=Q(idempotency_key__isnull=False, producer_user__isnull=False),
                name="audit_idempotency_user_unique",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.action} {self.resource_type}:{self.resource_id or '-'} ({self.severity})"


class OutboxStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    DISPATCHED = "dispatched", "Dispatched"


class OutboxMessage(models.Model):
    """Written in the same transaction as its event; drained asynchronously.

    The outbox guarantees that every committed WARN/CRITICAL event is eventually
    offered to webhook dispatch, even if Redis or Celery was unavailable at commit.
    """

    TOPIC_EVENT_CREATED = "audit_event.created"

    event = models.ForeignKey(AuditEvent, on_delete=models.CASCADE, related_name="outbox_messages")
    topic = models.CharField(max_length=64, default=TOPIC_EVENT_CREATED)
    status = models.CharField(
        max_length=16, choices=OutboxStatus.choices, default=OutboxStatus.PENDING
    )
    attempts = models.PositiveIntegerField(default=0)
    available_at = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(default=timezone.now)
    dispatched_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes: ClassVar[list[models.Index]] = [
            models.Index(
                fields=["available_at", "id"],
                name="outbox_pending_idx",
                condition=Q(status=OutboxStatus.PENDING),
            ),
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(fields=["event", "topic"], name="outbox_event_topic_unique"),
        ]

    def __str__(self) -> str:
        return f"{self.topic} {self.event_id} ({self.status})"
