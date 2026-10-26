"""Webhook endpoints (subscriptions) and per-event delivery records."""

from __future__ import annotations

import uuid
from typing import ClassVar

from django.contrib.postgres.fields import ArrayField
from django.db import models
from django.db.models import Q
from django.utils import timezone

from apps.accounts.models import User
from apps.audit_logs.models import SEVERITY_RANK, AuditEvent, Severity


class WebhookEndpoint(models.Model):
    """An HTTPS destination subscribed to WARN and/or CRITICAL audit events.

    The signing secret is stored encrypted (Fernet, keys from the environment) and is
    returned to the API caller only when created or rotated. After a rotation the
    previous secret keeps signing for a grace period, so receivers can switch over
    without dropping deliveries.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=64, unique=True)
    description = models.CharField(max_length=255, blank=True)
    url = models.URLField(max_length=2048)
    is_active = models.BooleanField(default=True)
    min_severity = models.CharField(
        max_length=8,
        choices=[(Severity.WARN, "Warning"), (Severity.CRITICAL, "Critical")],
        default=Severity.CRITICAL,
    )
    action_prefixes = ArrayField(
        models.CharField(max_length=128),
        default=list,
        blank=True,
        help_text="Only events whose action starts with one of these (empty = all).",
    )
    secret_ciphertext = models.TextField(editable=False)
    previous_secret_ciphertext = models.TextField(blank=True, default="", editable=False)
    previous_secret_expires_at = models.DateTimeField(null=True, blank=True, editable=False)
    secret_rotated_at = models.DateTimeField(default=timezone.now, editable=False)
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering: ClassVar[list[str]] = ["name"]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(
                condition=Q(min_severity__in=[Severity.WARN, Severity.CRITICAL]),
                name="webhook_min_severity_valid",
            ),
        ]

    def __str__(self) -> str:
        return self.name

    def matches(self, event: AuditEvent) -> bool:
        if SEVERITY_RANK[event.severity] < SEVERITY_RANK[self.min_severity]:
            return False
        if not self.action_prefixes:
            return True
        return any(
            event.action == prefix or event.action.startswith(f"{prefix}.")
            for prefix in self.action_prefixes
        )


class DeliveryStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    IN_PROGRESS = "in_progress", "In progress"
    RETRYING = "retrying", "Retrying"
    SUCCEEDED = "succeeded", "Succeeded"
    FAILED = "failed", "Failed (permanent error)"
    EXHAUSTED = "exhausted", "Failed (retries exhausted)"


TERMINAL_STATUSES = frozenset(
    {DeliveryStatus.SUCCEEDED, DeliveryStatus.FAILED, DeliveryStatus.EXHAUSTED}
)


class WebhookDelivery(models.Model):
    """One event offered to one endpoint. Unique per pair, so dispatch is idempotent.

    Delivery is at-least-once: receivers must de-duplicate on the event ID. Only a
    safe error code (e.g. ``timeout``, ``http_503``) is stored, never response bodies.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    endpoint = models.ForeignKey(
        WebhookEndpoint, on_delete=models.CASCADE, related_name="deliveries"
    )
    # CASCADE only matters for the audited retention purge; events are otherwise immutable.
    event = models.ForeignKey(AuditEvent, on_delete=models.CASCADE, related_name="+")
    status = models.CharField(
        max_length=16, choices=DeliveryStatus.choices, default=DeliveryStatus.PENDING
    )
    attempt_count = models.PositiveSmallIntegerField(default=0)
    next_attempt_at = models.DateTimeField(null=True, blank=True)
    last_attempt_at = models.DateTimeField(null=True, blank=True)
    last_status_code = models.PositiveSmallIntegerField(null=True, blank=True)
    last_error = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name_plural = "webhook deliveries"
        indexes: ClassVar[list[models.Index]] = [
            models.Index(
                fields=["next_attempt_at"],
                name="webhook_delivery_due_idx",
                condition=Q(status__in=[DeliveryStatus.PENDING, DeliveryStatus.RETRYING]),
            ),
            models.Index(fields=["endpoint", "-created_at"], name="webhook_delivery_endpoint_idx"),
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(fields=["endpoint", "event"], name="webhook_delivery_unique"),
        ]

    def __str__(self) -> str:
        return f"{self.endpoint_id} <- {self.event_id} ({self.status})"
