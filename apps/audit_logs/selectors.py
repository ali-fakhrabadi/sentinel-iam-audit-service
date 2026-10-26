"""Read-side queries for audit events, including authorization scoping."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from django.db.models import QuerySet
from django.shortcuts import get_object_or_404

from apps.accounts.models import ServiceAccount
from apps.audit_logs.models import AuditEvent
from apps.audit_logs.pagination import Cursor


@dataclass(frozen=True, slots=True)
class EventQuery:
    created_after: datetime
    created_before: datetime
    actor_id: str | None = None
    action: str | None = None
    action_prefix: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    severities: tuple[str, ...] = ()
    ip_address: str | None = None
    metadata_contains: dict[str, Any] = field(default_factory=dict)


def visible_events(*, scope: ServiceAccount | None) -> QuerySet[AuditEvent]:
    """Events the caller may see.

    Users with ``audit:read`` see every event. A service account with ``audit:read``
    only sees events it produced itself, so one integration cannot read another's
    data.
    """
    queryset = AuditEvent.objects.select_related("producer_service_account", "producer_user")
    if scope is not None:
        queryset = queryset.filter(producer_service_account=scope)
    return queryset


def search_events(
    query: EventQuery,
    *,
    scope: ServiceAccount | None,
    cursor: Cursor | None,
    page_size: int,
) -> tuple[list[AuditEvent], Cursor | None]:
    """One page of events, newest first, plus the cursor for the next page."""
    queryset = visible_events(scope=scope).filter(
        created_at__gte=query.created_after, created_at__lt=query.created_before
    )
    exact_filters = {
        "actor_id": query.actor_id,
        "action": query.action,
        "resource_type": query.resource_type,
        "resource_id": query.resource_id,
        "ip_address": query.ip_address,
    }
    queryset = queryset.filter(
        **{name: value for name, value in exact_filters.items() if value is not None}
    )
    if query.action_prefix:
        queryset = queryset.filter(action__startswith=query.action_prefix)
    if query.severities:
        queryset = queryset.filter(severity__in=query.severities)
    if query.metadata_contains:
        queryset = queryset.filter(metadata__contains=query.metadata_contains)
    if cursor is not None:
        queryset = queryset.filter(cursor.older_than())

    rows = list(queryset.order_by("-created_at", "-id")[: page_size + 1])
    if len(rows) <= page_size:
        return rows, None
    page = rows[:page_size]
    last = page[-1]
    return page, Cursor(created_at=last.created_at, id=last.id)


def event_get(event_id: uuid.UUID, *, scope: ServiceAccount | None) -> AuditEvent:
    event: AuditEvent = get_object_or_404(visible_events(scope=scope), pk=event_id)
    return event
