"""Webhook endpoint management, outbox dispatch and delivery attempts.

Reliability model:
* dispatch reads the audit outbox with ``FOR UPDATE SKIP LOCKED`` and creates at most
  one delivery per (endpoint, event) thanks to a unique constraint, so running it
  twice or concurrently never duplicates work;
* an attempt first claims the delivery in a short transaction (lease), performs the
  HTTP call outside any transaction, then records the outcome;
* retries use exponential backoff with jitter, bounded by ``WEBHOOK_MAX_RETRIES``
  (retries after the first attempt);
* delivery is at-least-once: a crash after the receiver answered but before the
  outcome was stored leads to a repeat, so receivers de-duplicate on the event ID.
"""

from __future__ import annotations

import logging
import random
import re
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Literal

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from apps.accounts.models import User
from apps.audit_logs import services as audit_services
from apps.audit_logs.models import Severity
from apps.audit_logs.serializers import AuditEventSerializer
from apps.webhooks import crypto, delivery, signing
from apps.webhooks.models import TERMINAL_STATUSES, DeliveryStatus, WebhookDelivery, WebhookEndpoint
from apps.webhooks.ssrf import UnsafeDestinationError, check_destination
from config.exceptions import Conflict

logger = logging.getLogger("sentinel.webhooks")
_jitter = random.SystemRandom()
_ACTION_PREFIX_RE = re.compile(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){0,5}")

AttemptOutcome = Literal["succeeded", "retrying", "exhausted", "failed", "skipped"]


# --------------------------------------------------------------------------------------
# Endpoint management
# --------------------------------------------------------------------------------------
def _validate_url(url: str) -> None:
    try:
        check_destination(url, allow_insecure=settings.WEBHOOK_ALLOW_INSECURE_DESTINATIONS)
    except UnsafeDestinationError as exc:
        raise ValidationError({"url": [exc.message]}) from exc


def _validate_prefixes(prefixes: Iterable[str]) -> list[str]:
    """A prefix is one or more whole action segments, e.g. ``iam`` or ``auth.login``."""
    cleaned = sorted({prefix.strip().lower() for prefix in prefixes})
    invalid = [prefix for prefix in cleaned if not _ACTION_PREFIX_RE.fullmatch(prefix)]
    if invalid:
        raise ValidationError(
            {"action_prefixes": [f"Invalid action prefix: {prefix!r}." for prefix in invalid]}
        )
    return cleaned


@dataclass(frozen=True, slots=True)
class IssuedSecret:
    endpoint: WebhookEndpoint
    secret: str

    def __repr__(self) -> str:
        return f"IssuedSecret(endpoint={self.endpoint!r}, secret=<redacted>)"


@transaction.atomic
def endpoint_create(
    *,
    actor: User,
    name: str,
    url: str,
    description: str = "",
    min_severity: str = Severity.CRITICAL,
    action_prefixes: Iterable[str] = (),
) -> IssuedSecret:
    _validate_url(url)
    prefixes = _validate_prefixes(action_prefixes)
    if WebhookEndpoint.objects.filter(name=name).exists():
        raise Conflict("A webhook endpoint with this name already exists.")
    secret = crypto.generate_signing_secret()
    endpoint = WebhookEndpoint(
        name=name,
        url=url,
        description=description,
        min_severity=min_severity,
        action_prefixes=prefixes,
        secret_ciphertext=crypto.encrypt_secret(secret),
        created_by=actor,
    )
    endpoint.full_clean(validate_unique=False)
    endpoint.save()
    audit_services.record_internal_event(
        actor=actor,
        action="webhook.endpoint.created",
        resource_type="webhook.endpoint",
        resource_id=str(endpoint.pk),
        severity=Severity.WARN,
        metadata={"name": name, "min_severity": min_severity, "action_prefixes": prefixes},
    )
    return IssuedSecret(endpoint=endpoint, secret=secret)


@transaction.atomic
def endpoint_update(
    *,
    actor: User,
    endpoint: WebhookEndpoint,
    url: str | None = None,
    description: str | None = None,
    min_severity: str | None = None,
    action_prefixes: Iterable[str] | None = None,
    is_active: bool | None = None,
) -> WebhookEndpoint:
    changes: dict[str, Any] = {}
    if url is not None and url != endpoint.url:
        _validate_url(url)
        endpoint.url = url
        changes["url_changed"] = True
    if description is not None:
        endpoint.description = description
    if min_severity is not None:
        endpoint.min_severity = min_severity
        changes["min_severity"] = min_severity
    if action_prefixes is not None:
        endpoint.action_prefixes = _validate_prefixes(action_prefixes)
        changes["action_prefixes"] = endpoint.action_prefixes
    if is_active is not None:
        endpoint.is_active = is_active
        changes["is_active"] = is_active
    endpoint.full_clean(validate_unique=False)
    endpoint.save()
    audit_services.record_internal_event(
        actor=actor,
        action="webhook.endpoint.updated",
        resource_type="webhook.endpoint",
        resource_id=str(endpoint.pk),
        severity=Severity.WARN,
        metadata=changes,
    )
    return endpoint


@transaction.atomic
def endpoint_rotate_secret(*, actor: User, endpoint: WebhookEndpoint) -> IssuedSecret:
    """Issue a new secret; the old one keeps signing during the grace period."""
    now = timezone.now()
    secret = crypto.generate_signing_secret()
    endpoint.previous_secret_ciphertext = endpoint.secret_ciphertext
    endpoint.previous_secret_expires_at = now + timedelta(
        hours=settings.WEBHOOK_SECRET_ROTATION_GRACE_HOURS
    )
    endpoint.secret_ciphertext = crypto.encrypt_secret(secret)
    endpoint.secret_rotated_at = now
    endpoint.save(
        update_fields=[
            "previous_secret_ciphertext",
            "previous_secret_expires_at",
            "secret_ciphertext",
            "secret_rotated_at",
            "updated_at",
        ]
    )
    audit_services.record_internal_event(
        actor=actor,
        action="webhook.secret.rotated",
        resource_type="webhook.endpoint",
        resource_id=str(endpoint.pk),
        severity=Severity.WARN,
        metadata={"grace_hours": settings.WEBHOOK_SECRET_ROTATION_GRACE_HOURS},
    )
    return IssuedSecret(endpoint=endpoint, secret=secret)


def signing_secrets(endpoint: WebhookEndpoint, *, now: datetime) -> list[str]:
    secrets = [crypto.decrypt_secret(endpoint.secret_ciphertext)]
    if (
        endpoint.previous_secret_ciphertext
        and endpoint.previous_secret_expires_at is not None
        and endpoint.previous_secret_expires_at > now
    ):
        secrets.append(crypto.decrypt_secret(endpoint.previous_secret_ciphertext))
    return secrets


# --------------------------------------------------------------------------------------
# Dispatch: outbox -> deliveries
# --------------------------------------------------------------------------------------
def dispatch_outbox(*, batch_size: int = 100, now: datetime | None = None) -> int:
    """Turn due outbox messages into delivery records. Returns messages processed."""
    moment = now or timezone.now()
    with transaction.atomic():
        messages = audit_services.outbox_claim_batch(limit=batch_size, now=moment)
        if not messages:
            return 0
        endpoints = list(WebhookEndpoint.objects.filter(is_active=True))
        candidates = [
            WebhookDelivery(
                endpoint=endpoint,
                event=message.event,
                status=DeliveryStatus.PENDING,
                next_attempt_at=moment,
                created_at=moment,
            )
            for message in messages
            for endpoint in endpoints
            if endpoint.matches(message.event)
        ]
        # One INSERT ... ON CONFLICT DO NOTHING for the batch: a pair that already has a
        # delivery (a re-processed message) keeps it, and only new rows are enqueued.
        WebhookDelivery.objects.bulk_create(candidates, ignore_conflicts=True)
        new_delivery_ids = list(
            WebhookDelivery.objects.filter(
                id__in=[candidate.id for candidate in candidates]
            ).values_list("id", flat=True)
        )
        audit_services.outbox_mark_dispatched(messages, now=moment)
        transaction.on_commit(lambda: enqueue_deliveries(new_delivery_ids))
    logger.info(
        "Outbox dispatched",
        extra={"messages": len(messages), "deliveries_created": len(new_delivery_ids)},
    )
    return len(messages)


def enqueue_deliveries(delivery_ids: Iterable[uuid.UUID], *, countdown: float = 0) -> None:
    from apps.webhooks.tasks import deliver_security_webhook_task  # noqa: PLC0415

    for delivery_id in delivery_ids:
        try:
            deliver_security_webhook_task.apply_async(args=(str(delivery_id),), countdown=countdown)
        except Exception:
            # The delivery row is the source of truth; requeue_due_deliveries retries.
            logger.warning(
                "Could not enqueue webhook delivery",
                extra={"delivery_id": str(delivery_id)},
                exc_info=True,
            )


# --------------------------------------------------------------------------------------
# Delivery attempts
# --------------------------------------------------------------------------------------
def backoff_seconds(attempt: int) -> float:
    """Exponential backoff with jitter: base * 2^(attempt-1), capped, scaled by 0.5-1.0."""
    base: int = settings.WEBHOOK_BACKOFF_BASE_SECONDS
    cap: int = settings.WEBHOOK_BACKOFF_MAX_SECONDS
    delay = float(min(cap, base * (1 << max(attempt - 1, 0))))
    return delay * _jitter.uniform(0.5, 1.0)


def build_payload(delivery_record: WebhookDelivery) -> dict[str, Any]:
    return {
        "type": "audit_event.created",
        "webhook_id": str(delivery_record.endpoint_id),
        "delivery_id": str(delivery_record.id),
        "event": AuditEventSerializer(delivery_record.event).data,
    }


def _claim(delivery_id: uuid.UUID, now: datetime) -> WebhookDelivery | None:
    lease = timedelta(seconds=settings.WEBHOOK_DELIVERY_LEASE_SECONDS)
    with transaction.atomic():
        record = (
            WebhookDelivery.objects.select_for_update(skip_locked=True, of=("self",))
            .select_related("endpoint", "event__producer_service_account", "event__producer_user")
            .filter(pk=delivery_id)
            .first()
        )
        if record is None or record.status in TERMINAL_STATUSES:
            return None
        if (
            record.status == DeliveryStatus.IN_PROGRESS
            and record.last_attempt_at is not None
            and record.last_attempt_at > now - lease
        ):
            return None  # another worker holds a live lease
        if (
            record.status != DeliveryStatus.IN_PROGRESS
            and record.next_attempt_at
            and record.next_attempt_at > now
        ):
            return None  # an early duplicate of a scheduled retry
        if not record.endpoint.is_active:
            _finish(record, DeliveryStatus.FAILED, now, error="endpoint_disabled")
            return None
        record.status = DeliveryStatus.IN_PROGRESS
        record.attempt_count += 1
        record.last_attempt_at = now
        record.save(update_fields=["status", "attempt_count", "last_attempt_at"])
        return record


def _finish(
    record: WebhookDelivery,
    status: DeliveryStatus,
    now: datetime,
    *,
    error: str = "",
    status_code: int | None = None,
) -> None:
    record.status = status
    record.last_error = error
    record.last_status_code = status_code
    record.next_attempt_at = None
    record.completed_at = now
    record.save(
        update_fields=[
            "status",
            "last_error",
            "last_status_code",
            "next_attempt_at",
            "completed_at",
        ]
    )


def attempt_delivery(delivery_id: uuid.UUID, *, now: datetime | None = None) -> AttemptOutcome:
    """One delivery attempt; safe to call repeatedly or concurrently."""
    moment = now or timezone.now()
    record = _claim(delivery_id, moment)
    if record is None:
        return "skipped"

    result: delivery.AttemptResult
    try:
        destination = check_destination(
            record.endpoint.url, allow_insecure=settings.WEBHOOK_ALLOW_INSECURE_DESTINATIONS
        )
        secrets = signing_secrets(record.endpoint, now=moment)
    except UnsafeDestinationError as exc:
        result = delivery.AttemptResult("permanent", None, exc.code, 0.0)
    except crypto.SecretUnavailableError:
        result = delivery.AttemptResult("permanent", None, "secret_unavailable", 0.0)
    else:
        body = signing.canonical_body(build_payload(record))
        timestamp = int(moment.timestamp())
        event_id = str(record.event_id)
        headers = {
            signing.EVENT_ID_HEADER: event_id,
            signing.DELIVERY_ID_HEADER: str(record.id),
            signing.TIMESTAMP_HEADER: str(timestamp),
            signing.SIGNATURE_HEADER: signing.signature_header(secrets, timestamp, event_id, body),
        }
        result = delivery.send(destination, body=body, headers=headers)

    return _record_result(record, result, moment)


def _record_result(
    record: WebhookDelivery, result: delivery.AttemptResult, now: datetime
) -> AttemptOutcome:
    """Store the outcome of an attempt that started at ``now``.

    ``completed_at`` is when the receiver answered (start + HTTP duration), so delivery
    latency can be read directly from the table; retries are scheduled from the start.
    """
    finished = now + timedelta(seconds=result.duration_seconds)
    outcome: AttemptOutcome
    with transaction.atomic():
        if result.outcome == "succeeded":
            _finish(record, DeliveryStatus.SUCCEEDED, finished, status_code=result.status_code)
            outcome = "succeeded"
        elif result.outcome == "permanent":
            _finish(
                record,
                DeliveryStatus.FAILED,
                finished,
                error=result.error,
                status_code=result.status_code,
            )
            outcome = "failed"
        elif record.attempt_count > settings.WEBHOOK_MAX_RETRIES:
            _finish(
                record,
                DeliveryStatus.EXHAUSTED,
                finished,
                error=result.error,
                status_code=result.status_code,
            )
            outcome = "exhausted"
        else:
            delay = backoff_seconds(record.attempt_count)
            record.status = DeliveryStatus.RETRYING
            record.last_error = result.error
            record.last_status_code = result.status_code
            record.next_attempt_at = now + timedelta(seconds=delay)
            record.save(
                update_fields=["status", "last_error", "last_status_code", "next_attempt_at"]
            )
            transaction.on_commit(lambda: enqueue_deliveries([record.id], countdown=delay))
            outcome = "retrying"
    log = logger.info if outcome in {"succeeded", "retrying"} else logger.warning
    log(
        "Webhook delivery attempt",
        extra={
            "delivery_id": str(record.id),
            "endpoint_id": str(record.endpoint_id),
            "event_id": str(record.event_id),
            "attempt": record.attempt_count,
            "outcome": outcome,
            "status_code": result.status_code,
            "error": result.error,
            "duration_ms": round(result.duration_seconds * 1000, 1),
        },
    )
    return outcome


def requeue_due_deliveries(*, now: datetime | None = None, limit: int = 500) -> int:
    """Reconciliation: re-enqueue deliveries that are due or whose lease expired."""
    moment = now or timezone.now()
    stale = moment - timedelta(seconds=settings.WEBHOOK_DELIVERY_LEASE_SECONDS)
    due = WebhookDelivery.objects.filter(
        Q(status__in=[DeliveryStatus.PENDING, DeliveryStatus.RETRYING], next_attempt_at__lte=moment)
        | Q(status=DeliveryStatus.IN_PROGRESS, last_attempt_at__lt=stale)
    ).order_by("next_attempt_at")
    ids = list(due.values_list("id", flat=True)[:limit])
    enqueue_deliveries(ids)
    return len(ids)
