"""Read-side queries for audit events, including authorization scoping.

How a page query stays fast on millions of rows
-----------------------------------------------
Every page is ``ORDER BY created_at DESC, id DESC LIMIT n``. PostgreSQL picks between
walking the time index ``(created_at, id)`` and filtering, or using a filter's own index,
from its estimate of how common the filtered value is. It assumes values are spread
evenly over time, so a value that is common overall but absent from recent rows sends it
down the time index through the whole window: seconds instead of milliseconds (measured
on 2 million rows: 3.3 s for an action, 3.6 s for an actor, 5 s+ for a metadata value).
The query is therefore shaped so that the fast plan does not depend on statistics:

1. **Pinned filter.** Each equality filter users search by has an index ending in
   ``(created_at, id)``. The most selective one present is written as
   ``column = ANY(ARRAY[value])`` (the same rows) and leads the ORDER BY. Compared with
   ``=`` the column would be a constant to the planner and dropped from the ORDER BY;
   with ``= ANY`` only the filter's own index returns rows in the requested order, so
   the page is one short index range.
2. **Recent probe, then selective plan.** Filters that no index returns in time order
   (metadata containment, action prefix, several severities) are first applied to the
   newest ``RECENT_PROBE_ROWS`` rows of the window only. If that fills the page, the
   result is exact: every other match is older. Otherwise the page is read with a sort
   on an expression no index provides, which makes PostgreSQL use the filter's index
   (GIN for metadata) and sort the matches, which is cheap exactly when matches are rare.

``loadtest/explain_queries.py`` runs both paths, including these worst cases, against a
seeded database and checks which index each one uses.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from django.db.backends.base.base import BaseDatabaseWrapper
from django.db.models import DateTimeField, ExpressionWrapper, F, Lookup, Q, QuerySet, Value
from django.db.models.sql.compiler import SQLCompiler
from django.shortcuts import get_object_or_404

from apps.accounts.models import ServiceAccount
from apps.audit_logs.models import AuditEvent
from apps.audit_logs.pagination import Cursor

# Equality filters with a dedicated (columns..., created_at, id) index, in pinning
# priority: high-cardinality columns first, because they narrow the page the most.
# A multi-column entry is pinnable only when every column is filtered.
_PINNABLE: tuple[tuple[str, ...], ...] = (
    ("actor_id",),
    ("ip_address",),
    ("resource_type", "resource_id"),
    ("producer_service_account_id",),
    ("action",),
    ("severity",),
)
RECENT_PROBE_ROWS = 10_000


class EqualsAny(Lookup):
    """``column = ANY(ARRAY[value]::type[])``: the rows of ``column = value``.

    PostgreSQL folds ``column = constant`` into an equivalence with a constant and
    drops the column from ORDER BY; ``= ANY`` keeps it there. See the module docstring.
    """

    lookup_name = "equals_any"
    prepare_rhs = False

    def as_sql(
        self, compiler: SQLCompiler, connection: BaseDatabaseWrapper
    ) -> tuple[str, tuple[Any, ...]]:
        lhs, lhs_params = self.process_lhs(compiler, connection)
        db_type = self.lhs.output_field.db_type(connection)
        return f"{lhs} = ANY(%s::{db_type}[])", (*lhs_params, [self.rhs])


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

    @property
    def has_unordered_filter(self) -> bool:
        """A filter that no index can return in time order."""
        return bool(self.metadata_contains or self.action_prefix or len(self.severities) > 1)


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


def _equality_filters(query: EventQuery, scope: ServiceAccount | None) -> dict[str, Any]:
    equals: dict[str, Any] = {
        name: value
        for name, value in (
            ("actor_id", query.actor_id),
            ("ip_address", query.ip_address),
            ("resource_type", query.resource_type),
            ("resource_id", query.resource_id),
            ("action", query.action),
        )
        if value is not None
    }
    # The scope is an authorization filter, applied here rather than through
    # visible_events() so that it can be pinned like any other filter.
    if scope is not None:
        equals["producer_service_account_id"] = scope.pk
    if len(query.severities) == 1:
        equals["severity"] = query.severities[0]
    return equals


def _pinned_column(query: EventQuery, scope: ServiceAccount | None) -> str | None:
    equals = _equality_filters(query, scope)
    pinned = next((columns for columns in _PINNABLE if all(c in equals for c in columns)), ())
    return pinned[0] if pinned else None


def _window_after(query: EventQuery, cursor: Cursor | None) -> Q:
    window = Q(created_at__gte=query.created_after, created_at__lt=query.created_before)
    return window & cursor.older_than() if cursor is not None else window


def page_queryset(
    query: EventQuery,
    *,
    scope: ServiceAccount | None,
    cursor: Cursor | None,
    limit: int,
    newest: Cursor | None = None,
) -> QuerySet[AuditEvent]:
    """The SQL behind one page: filters, cursor predicate, newest-first order, LIMIT.

    ``newest`` restricts the page to rows at or after that position (the recent probe).
    Without it, a query with an unordered filter and no pinned filter is sorted on an
    expression, so PostgreSQL reads only the matches through the filter's own index.
    """
    lead = _pinned_column(query, scope)
    queryset = AuditEvent.objects.select_related(
        "producer_service_account", "producer_user"
    ).filter(_window_after(query, cursor))
    for name, value in _equality_filters(query, scope).items():
        if name == lead:
            queryset = queryset.filter(EqualsAny(F(name), value))
        else:
            queryset = queryset.filter(**{name: value})
    if len(query.severities) > 1:
        queryset = queryset.filter(severity__in=query.severities)
    if query.action_prefix:
        queryset = queryset.filter(action__startswith=query.action_prefix)
    if query.metadata_contains:
        queryset = queryset.filter(metadata__contains=query.metadata_contains)
    if newest is not None:
        queryset = queryset.filter(
            Q(created_at__gte=newest.created_at),
            Q(created_at__gt=newest.created_at) | Q(id__gte=newest.id),
        )

    if lead is not None:
        # One value for ``lead``: exactly (created_at DESC, id DESC).
        return queryset.order_by(f"-{lead}", "-created_at", "-id")[:limit]
    if query.has_unordered_filter and newest is None:
        # The same order, but no index provides it, so the time index is not walked.
        unindexed_time = ExpressionWrapper(
            F("created_at") + Value(timedelta(0)), output_field=DateTimeField()
        )
        return queryset.order_by(unindexed_time.desc(), "-id")[:limit]
    return queryset.order_by("-created_at", "-id")[:limit]


def page_querysets(
    query: EventQuery, *, scope: ServiceAccount | None, cursor: Cursor | None, limit: int
) -> list[QuerySet[AuditEvent]]:
    """Querysets for one page, tried in order until one returns ``limit`` rows.

    The last one is always exact. Only pages with an unordered filter and nothing to pin
    get the recent probe first; finding the probe's boundary reads at most
    ``RECENT_PROBE_ROWS`` entries of the time index.
    """
    exact = page_queryset(query, scope=scope, cursor=cursor, limit=limit)
    if not query.has_unordered_filter or _pinned_column(query, scope) is not None:
        return [exact]
    boundary = (
        AuditEvent.objects.filter(_window_after(query, cursor))
        .order_by("-created_at", "-id")
        .values_list("created_at", "id")[RECENT_PROBE_ROWS - 1 : RECENT_PROBE_ROWS]
        .first()
    )
    if boundary is None:
        # The rest of the window is smaller than the probe: read all of it in time order.
        whole_window = Cursor(created_at=query.created_after, id=uuid.UUID(int=0))
        return [page_queryset(query, scope=scope, cursor=cursor, limit=limit, newest=whole_window)]
    probe = page_queryset(
        query,
        scope=scope,
        cursor=cursor,
        limit=limit,
        newest=Cursor(created_at=boundary[0], id=boundary[1]),
    )
    return [probe, exact]


def search_events(
    query: EventQuery,
    *,
    scope: ServiceAccount | None,
    cursor: Cursor | None,
    page_size: int,
) -> tuple[list[AuditEvent], Cursor | None]:
    """One page of events, newest first, plus the cursor for the next page."""
    rows: list[AuditEvent] = []
    for queryset in page_querysets(query, scope=scope, cursor=cursor, limit=page_size + 1):
        rows = list(queryset)
        if len(rows) > page_size:
            break
    if len(rows) <= page_size:
        return rows, None
    page = rows[:page_size]
    last = page[-1]
    return page, Cursor(created_at=last.created_at, id=last.id)


def event_get(event_id: uuid.UUID, *, scope: ServiceAccount | None) -> AuditEvent:
    event: AuditEvent = get_object_or_404(visible_events(scope=scope), pk=event_id)
    return event
