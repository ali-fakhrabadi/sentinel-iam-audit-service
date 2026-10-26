"""Write-side operations for the audit log.

Bulk ingestion contract (documented in the API):
* every item is validated on its own; invalid items are reported and skipped;
* all valid items are inserted in ONE transaction, so a database failure stores
  nothing and the whole request can be retried;
* ``idempotency_key`` makes retries safe: a key the producer already used returns
  ``duplicate`` with the original event ID (first write wins);
* events at or above ``AUDIT_OUTBOX_MIN_SEVERITY`` get an outbox message in the same
  transaction, and dispatch is triggered after commit.

Cross-module dependency: the outbox is drained by the webhooks app through the
Celery task named in ``settings.AUDIT_OUTBOX_DISPATCH_TASK``. This module never
imports webhooks code.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.db.models import QuerySet
from django.utils import timezone

from apps.accounts.models import ServiceAccount, User
from apps.audit_logs import metrics
from apps.audit_logs.models import SEVERITY_RANK, AuditEvent, OutboxMessage, OutboxStatus, Severity
from config.celery import app as celery_app

logger = logging.getLogger("sentinel.audit")

ItemStatus = Literal["accepted", "duplicate", "rejected"]
Producer = ServiceAccount | User


@dataclass(frozen=True, slots=True)
class EventInput:
    action: str
    resource_type: str
    severity: str
    resource_id: str | None = None
    actor_id: str | None = None
    ip_address: str | None = None
    user_agent: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    occurred_at: datetime | None = None
    idempotency_key: str | None = None


@dataclass(frozen=True, slots=True)
class ItemResult:
    index: int
    status: ItemStatus
    event_id: uuid.UUID | None = None
    errors: list[dict[str, str]] | None = None


def _producer_fields(producer: Producer) -> dict[str, Any]:
    if isinstance(producer, ServiceAccount):
        return {"producer_service_account": producer}
    return {"producer_user": producer}


def _needs_outbox(severity: str) -> bool:
    return SEVERITY_RANK[severity] >= SEVERITY_RANK[settings.AUDIT_OUTBOX_MIN_SEVERITY]


_DISPATCH_GUARD_KEY = "audit:outbox:dispatch-scheduled"


def _enqueue_outbox_dispatch() -> None:
    """Drain the outbox at most twice per window, however many transactions commit.

    The first commit in a window sets a short-lived cache key and schedules two drains:
    one immediately (an isolated alert goes out within milliseconds) and one at the end
    of the window, which covers every commit made meanwhile. Later commits in the same
    window do nothing. Without coalescing, busy ingestion floods the queue with
    near-empty drain tasks that delay real webhook deliveries.

    Best effort: if Redis or the broker is down, the beat reconciliation drains the
    outbox anyway.
    """
    window: int = settings.AUDIT_OUTBOX_DISPATCH_WINDOW_SECONDS
    try:
        if cache.add(_DISPATCH_GUARD_KEY, 1, timeout=window):
            celery_app.send_task(settings.AUDIT_OUTBOX_DISPATCH_TASK)
            celery_app.send_task(settings.AUDIT_OUTBOX_DISPATCH_TASK, countdown=window)
    except Exception:
        logger.warning(
            "Could not enqueue outbox dispatch; reconciliation will pick it up.", exc_info=True
        )


def ingest_events(
    *,
    producer: Producer,
    items: Sequence[tuple[int, EventInput]],
    received_at: datetime,
) -> list[ItemResult]:
    """Persist validated events. ``items`` pairs each event with its request index."""
    created_at = timezone.now()
    producer_fields = _producer_fields(producer)
    results: dict[int, ItemResult] = {}
    first_index_by_key: dict[str, int] = {}
    to_insert: list[tuple[int, AuditEvent]] = []

    for index, item in items:
        key = item.idempotency_key
        if key is not None and key in first_index_by_key:
            continue  # resolved below to the same event as its first occurrence
        if key is not None:
            first_index_by_key[key] = index
        to_insert.append(
            (
                index,
                AuditEvent(
                    id=uuid.uuid4(),
                    action=item.action,
                    resource_type=item.resource_type,
                    resource_id=item.resource_id,
                    actor_id=item.actor_id,
                    ip_address=item.ip_address,
                    user_agent=item.user_agent,
                    severity=item.severity,
                    metadata=item.metadata,
                    occurred_at=item.occurred_at,
                    received_at=received_at,
                    created_at=created_at,
                    idempotency_key=key,
                    **producer_fields,
                ),
            )
        )

    with transaction.atomic():
        # ON CONFLICT DO NOTHING: a concurrent request may insert the same idempotency
        # key between our check and insert; the unique index settles it race-free.
        AuditEvent.objects.bulk_create([event for _, event in to_insert], ignore_conflicts=True)
        candidate_ids = [event.id for _, event in to_insert]
        inserted_ids = set(
            AuditEvent.objects.filter(id__in=candidate_ids).values_list("id", flat=True)
        )
        conflicted_keys = [
            event.idempotency_key
            for _, event in to_insert
            if event.id not in inserted_ids and event.idempotency_key is not None
        ]
        existing_by_key = dict(
            AuditEvent.objects.filter(
                idempotency_key__in=conflicted_keys, **producer_fields
            ).values_list("idempotency_key", "id")
        )

        outbox: list[OutboxMessage] = []
        for index, event in to_insert:
            if event.id in inserted_ids:
                results[index] = ItemResult(index=index, status="accepted", event_id=event.id)
                if _needs_outbox(event.severity):
                    outbox.append(OutboxMessage(event=event, available_at=created_at))
            else:
                existing_id = existing_by_key.get(event.idempotency_key or "")
                if existing_id is None:  # only a PK collision could cause this
                    raise RuntimeError(
                        "Audit event insert was skipped without an idempotency conflict"
                    )
                results[index] = ItemResult(index=index, status="duplicate", event_id=existing_id)
        if outbox:
            OutboxMessage.objects.bulk_create(outbox)
            transaction.on_commit(_enqueue_outbox_dispatch)

    for index, item in items:
        if index not in results and item.idempotency_key is not None:
            first = results[first_index_by_key[item.idempotency_key]]
            results[index] = ItemResult(index=index, status="duplicate", event_id=first.event_id)

    ordered = [results[index] for index, _ in items]
    metrics.record_ingestion(ordered)
    return ordered


def record_internal_event(
    *,
    actor: User,
    action: str,
    resource_type: str,
    resource_id: str | None,
    severity: Severity = Severity.INFO,
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    """Record an action Sentinel itself performed for ``actor`` (IAM, webhook changes).

    Call inside the caller's transaction so the change and its audit trail commit
    together.
    """
    now = timezone.now()
    event = AuditEvent.objects.create(
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        actor_id=str(actor.pk),
        severity=severity,
        metadata=metadata or {},
        received_at=now,
        created_at=now,
        producer_user=actor,
    )
    if _needs_outbox(severity):
        OutboxMessage.objects.create(event=event, available_at=now)
        transaction.on_commit(_enqueue_outbox_dispatch)
    return event


# --------------------------------------------------------------------------------------
# Outbox (consumed by the webhooks app inside its own transaction)
# --------------------------------------------------------------------------------------
def outbox_claim_batch(*, limit: int, now: datetime) -> list[OutboxMessage]:
    """Lock up to ``limit`` due messages. Must run inside ``transaction.atomic()``.

    SKIP LOCKED lets several dispatchers run concurrently without blocking or
    processing the same message twice. ``of=("self",)`` locks only outbox rows:
    audit events stay unlocked (and the app role may not lock them FOR UPDATE).
    """
    queryset: QuerySet[OutboxMessage] = (
        OutboxMessage.objects.select_for_update(skip_locked=True, of=("self",))
        .select_related("event")
        .filter(status=OutboxStatus.PENDING, available_at__lte=now)
        .order_by("available_at", "id")
    )
    return list(queryset[:limit])


def outbox_mark_dispatched(messages: Iterable[OutboxMessage], *, now: datetime) -> None:
    batch = list(messages)
    for message in batch:
        message.status = OutboxStatus.DISPATCHED
        message.dispatched_at = now
        message.attempts += 1
    OutboxMessage.objects.bulk_update(batch, ["status", "dispatched_at", "attempts"])
