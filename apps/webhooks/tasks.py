"""Celery entry points. Thin wrappers: all logic lives in ``services``."""

from __future__ import annotations

import uuid

from celery import shared_task

from apps.webhooks import services


@shared_task(name="webhooks.dispatch_outbox", ignore_result=True)
def dispatch_outbox_task(batch_size: int = 100) -> int:
    """Drain due outbox messages into delivery records (runs after commit and on beat)."""
    total = 0
    while processed := services.dispatch_outbox(batch_size=batch_size):
        total += processed
        if processed < batch_size:
            break
    return total


@shared_task(name="webhooks.deliver", ignore_result=True, acks_late=True)
def deliver_security_webhook_task(delivery_id: str) -> str:
    """Attempt one signed delivery; idempotent under duplicate task execution."""
    return services.attempt_delivery(uuid.UUID(delivery_id))


@shared_task(name="webhooks.requeue_due", ignore_result=True)
def requeue_due_deliveries_task() -> int:
    return services.requeue_due_deliveries()
