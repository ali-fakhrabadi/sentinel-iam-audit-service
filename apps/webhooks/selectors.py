from __future__ import annotations

import uuid

from django.db.models import QuerySet
from django.shortcuts import get_object_or_404

from apps.webhooks.models import WebhookDelivery, WebhookEndpoint


def endpoint_list() -> QuerySet[WebhookEndpoint]:
    return WebhookEndpoint.objects.order_by("name")


def endpoint_get(endpoint_id: uuid.UUID) -> WebhookEndpoint:
    endpoint: WebhookEndpoint = get_object_or_404(endpoint_list(), pk=endpoint_id)
    return endpoint


def delivery_list(
    endpoint: WebhookEndpoint, *, status: str | None = None
) -> QuerySet[WebhookDelivery]:
    queryset = WebhookDelivery.objects.filter(endpoint=endpoint).select_related("event")
    if status:
        queryset = queryset.filter(status=status)
    return queryset.order_by("-created_at", "-id")
