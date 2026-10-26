"""Prometheus metrics for the audit log.

* ``sentinel_audit_events_ingested_total{result}`` is counted in the web workers
  (aggregated across Gunicorn processes by multiprocess mode).
* ``sentinel_outbox_*`` gauges are computed from PostgreSQL at scrape time, so they
  are correct no matter which process did the work.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from typing import TYPE_CHECKING

from django.db.models import Min
from django.utils import timezone
from prometheus_client import Counter, Histogram
from prometheus_client.core import GaugeMetricFamily
from prometheus_client.registry import Collector

if TYPE_CHECKING:
    from apps.audit_logs.services import ItemResult

EVENTS_INGESTED = Counter(
    "sentinel_audit_events_ingested",
    "Audit events received through the ingestion API, by outcome.",
    ["result"],
)
INGEST_BATCH_SIZE = Histogram(
    "sentinel_audit_ingest_batch_size",
    "Number of events per ingestion request.",
    buckets=(1, 5, 10, 50, 100, 250, 500, 1000),
)


def record_rejected(count: int) -> None:
    """Items rejected by validation never reach the service layer; count them here."""
    if count:
        EVENTS_INGESTED.labels(result="rejected").inc(count)


def record_ingestion(results: Sequence[ItemResult]) -> None:
    INGEST_BATCH_SIZE.observe(len(results))
    for outcome in ("accepted", "duplicate", "rejected"):
        count = sum(1 for result in results if result.status == outcome)
        if count:
            EVENTS_INGESTED.labels(result=outcome).inc(count)


class OutboxCollector(Collector):
    """Backlog of undispatched outbox messages and the age of the oldest one."""

    def collect(self) -> Iterator[GaugeMetricFamily]:
        from apps.audit_logs.models import OutboxMessage, OutboxStatus  # noqa: PLC0415

        pending = OutboxMessage.objects.filter(status=OutboxStatus.PENDING)
        stats = pending.aggregate(oldest=Min("created_at"))
        count = pending.count()
        oldest = stats["oldest"]
        age = (timezone.now() - oldest).total_seconds() if oldest else 0.0

        yield GaugeMetricFamily(
            "sentinel_outbox_pending_messages",
            "Outbox messages committed but not yet dispatched to webhooks.",
            value=count,
        )
        yield GaugeMetricFamily(
            "sentinel_outbox_oldest_pending_age_seconds",
            "Age of the oldest undispatched outbox message (0 when empty).",
            value=age,
        )
