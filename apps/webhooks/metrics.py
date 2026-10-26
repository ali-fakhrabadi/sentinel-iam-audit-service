"""Delivery-state gauges computed from PostgreSQL at scrape time.

Deliveries run in Celery worker processes, which Prometheus does not scrape; the
delivery table is the shared source of truth, so the web process reports from it.
"""

from __future__ import annotations

from collections.abc import Iterator

from django.db.models import Count
from prometheus_client.core import GaugeMetricFamily
from prometheus_client.registry import Collector


class DeliveryCollector(Collector):
    def collect(self) -> Iterator[GaugeMetricFamily]:
        from apps.webhooks.models import DeliveryStatus, WebhookDelivery  # noqa: PLC0415

        counts = dict(
            WebhookDelivery.objects.values("status")
            .annotate(total=Count("id"))
            .values_list("status", "total")
        )
        gauge = GaugeMetricFamily(
            "sentinel_webhook_deliveries",
            "Webhook deliveries by current status.",
            labels=["status"],
        )
        for status in DeliveryStatus.values:
            gauge.add_metric([status], counts.get(status, 0))
        yield gauge
