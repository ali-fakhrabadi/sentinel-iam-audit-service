"""Page queries: pinning a filter to its index must not change rows or their order."""

from __future__ import annotations

import random
from collections.abc import Callable
from datetime import timedelta
from typing import Any

import pytest
from django.utils import timezone

from apps.accounts.models import ServiceAccount
from apps.audit_logs import selectors
from apps.audit_logs.models import AuditEvent
from apps.audit_logs.pagination import Cursor
from apps.audit_logs.selectors import EventQuery, page_queryset, page_querysets, search_events
from tests.factories import create_event, create_service_account

pytestmark = pytest.mark.django_db

Matcher = Callable[[AuditEvent], bool]


@pytest.fixture
def dataset() -> tuple[ServiceAccount, list[AuditEvent]]:
    """60 events with mixed attributes; groups of four share one created_at."""
    rng = random.Random(7)
    primary = create_service_account(name="primary")
    other = create_service_account(name="other")
    base = timezone.now() - timedelta(hours=1)
    events = [
        create_event(
            producer=primary if index % 3 else other,
            created_at=base + timedelta(seconds=index // 4),
            actor_id=rng.choice(["alice", "bob", None]),
            action=rng.choice(["auth.login.failed", "iam.role.assigned"]),
            severity=rng.choice(["INFO", "WARN", "CRITICAL"]),
            ip_address=rng.choice(["203.0.113.7", "198.51.100.2", None]),
            resource_type="iam.user",
            resource_id=rng.choice(["u-1", "u-2"]),
            metadata={"rule": rng.choice(["r1", "r2", "r3"]), "mfa": rng.random() < 0.5},
        )
        for index in range(60)
    ]
    return primary, events


def _all_pages(query: EventQuery, scope: ServiceAccount | None) -> list[AuditEvent]:
    rows: list[AuditEvent] = []
    cursor: Cursor | None = None
    while True:
        page, cursor = search_events(query, scope=scope, cursor=cursor, page_size=4)
        rows.extend(page)
        if cursor is None:
            return rows


CASES: list[tuple[dict[str, Any], bool, Matcher]] = [
    ({}, False, lambda e: True),
    ({"actor_id": "alice"}, False, lambda e: e.actor_id == "alice"),
    ({"ip_address": "203.0.113.7"}, False, lambda e: e.ip_address == "203.0.113.7"),
    (
        {"resource_type": "iam.user", "resource_id": "u-2"},
        False,
        lambda e: e.resource_id == "u-2",
    ),
    ({"action": "iam.role.assigned"}, False, lambda e: e.action == "iam.role.assigned"),
    ({"severities": ("CRITICAL",)}, False, lambda e: e.severity == "CRITICAL"),
    ({"severities": ("WARN", "CRITICAL")}, False, lambda e: e.severity != "INFO"),
    ({"metadata_contains": {"rule": "r2"}}, False, lambda e: e.metadata["rule"] == "r2"),
    ({"action_prefix": "iam."}, False, lambda e: e.action.startswith("iam.")),
    (
        {"metadata_contains": {"mfa": True}, "severities": ("WARN", "CRITICAL")},
        False,
        lambda e: e.metadata["mfa"] and e.severity != "INFO",
    ),
    (
        {"actor_id": "alice", "severities": ("WARN",)},
        False,
        lambda e: (e.actor_id, e.severity) == ("alice", "WARN"),
    ),
    ({}, True, lambda e: True),
    (
        {"actor_id": "bob", "action": "auth.login.failed", "metadata_contains": {"mfa": False}},
        True,
        lambda e: (e.actor_id, e.action, e.metadata["mfa"]) == ("bob", "auth.login.failed", False),
    ),
]


@pytest.mark.parametrize(
    "probe_rows",
    [
        pytest.param(10_000, id="probe-covers-window"),
        pytest.param(5, id="probe-then-selective-plan"),
    ],
)
@pytest.mark.parametrize(("filters", "scoped", "matches"), CASES)
def test_every_query_shape_returns_the_same_rows_in_time_order(
    dataset: tuple[ServiceAccount, list[AuditEvent]],
    monkeypatch: pytest.MonkeyPatch,
    probe_rows: int,
    filters: dict[str, Any],
    scoped: bool,
    matches: Matcher,
) -> None:
    monkeypatch.setattr(selectors, "RECENT_PROBE_ROWS", probe_rows)
    primary, events = dataset
    now = timezone.now()
    query = EventQuery(created_after=now - timedelta(days=1), created_before=now, **filters)
    scope = primary if scoped else None

    rows = _all_pages(query, scope)

    visible = [e for e in events if scope is None or e.producer_service_account == scope]
    expected = sorted(
        (e for e in visible if matches(e)), key=lambda e: (e.created_at, e.id), reverse=True
    )
    assert expected, "the case must select at least one event"
    assert [e.id for e in rows] == [e.id for e in expected]


def _sql(**filters: Any) -> str:
    now = timezone.now()
    query = EventQuery(created_after=now - timedelta(days=1), created_before=now, **filters)
    cursor = Cursor(created_at=now - timedelta(hours=1), id=AuditEvent().id)
    return str(page_queryset(query, scope=None, cursor=cursor, limit=51).query)


def test_the_most_selective_indexed_filter_leads_the_order() -> None:
    sql = _sql(actor_id="alice", action="auth.login.failed", severities=("WARN",))

    assert '"audit_logs_auditevent"."actor_id" = ANY(' in sql
    assert '"audit_logs_auditevent"."action" = auth.login.failed' in sql
    assert sql.endswith(
        'ORDER BY "audit_logs_auditevent"."actor_id" DESC, '
        '"audit_logs_auditevent"."created_at" DESC, "audit_logs_auditevent"."id" DESC LIMIT 51'
    )


def test_unordered_filters_sort_on_an_expression_no_index_provides() -> None:
    sql = _sql(severities=("WARN", "CRITICAL"), metadata_contains={"rule": "r1"})

    assert "= ANY(" not in sql
    assert 'ORDER BY ("audit_logs_auditevent"."created_at" + ' in sql


def test_recent_probe_runs_first_only_for_unordered_filters_without_a_pin(
    dataset: tuple[ServiceAccount, list[AuditEvent]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(selectors, "RECENT_PROBE_ROWS", 5)
    now = timezone.now()

    def steps(**filters: Any) -> int:
        query = EventQuery(created_after=now - timedelta(days=1), created_before=now, **filters)
        return len(page_querysets(query, scope=None, cursor=None, limit=5))

    assert steps(metadata_contains={"rule": "r1"}) == 2
    assert steps(action_prefix="iam.") == 2
    assert steps(metadata_contains={"rule": "r1"}, actor_id="alice") == 1
    assert steps() == 1


def test_cursor_predicate_has_an_index_bound() -> None:
    # The plain upper bound lets PostgreSQL start the index scan at the cursor.
    assert '"audit_logs_auditevent"."created_at" <= ' in _sql()
