"""EXPLAIN (ANALYZE, BUFFERS) for the audit queries the API actually issues.

The querysets come from ``apps.audit_logs.selectors.page_querysets``, the function behind
``GET /api/v1/audit/events/``, so the plans reflect the exact SQL the API runs (filters,
keyset cursor predicate, ordering, LIMIT). Pages with a filter that no index returns in
time order run in two steps (recent probe, then selective plan); both are shown, with
whether the probe already filled the page. Each query names the index it was designed for
and the output says whether PostgreSQL used it. Run against a seeded database::

    docker compose --profile dev run --rm dev \
        python manage.py shell -c "exec(open('loadtest/explain_queries.py').read())"
"""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

from django.db.models import Count, QuerySet
from django.utils import timezone

from apps.accounts.models import ServiceAccount
from apps.audit_logs.models import AuditEvent
from apps.audit_logs.pagination import Cursor
from apps.audit_logs.selectors import RECENT_PROBE_ROWS, EventQuery, page_querysets

PAGE = 51  # page_size 50 + 1 look-ahead row, as in search_events()


def summarize(name: str, queryset: QuerySet[AuditEvent], designed_for: str | None) -> None:
    plan = queryset.explain(analyze=True, buffers=True)
    # "Index Scan using X", "Index Scan Backward using X", "Bitmap Index Scan on X", ...
    found = re.findall(
        r"((?:Bitmap )?Index (?:Only )?Scan(?: Backward)?) (?:using|on) (audit_\w+)", plan
    )
    scans = sorted({f"{kind.strip()} {index}" for kind, index in found})
    used = {index for _, index in found}
    seq_scans = sorted(set(re.findall(r"Seq Scan on (audit_\w+)", plan)))
    execution = re.search(r"Execution Time: ([\d.]+) ms", plan)
    print(f"\n### {name}")
    print(f"execution: {execution.group(1) if execution else '?'} ms")
    print(f"audit table access: {'; '.join(scans) or '-'}")
    if designed_for is None:
        print(f"designed index used: n/a (bounded to the newest {RECENT_PROBE_ROWS:,} rows)")
    else:
        print(f"designed index used: {'yes' if designed_for in used else 'NO'} ({designed_for})")
    print(f"sequential scans on audit tables: {', '.join(seq_scans) or 'none'}")
    print("\n".join("    " + line for line in plan.splitlines()[:14]))


def report(
    name: str,
    query: EventQuery,
    designed_for: str,
    *,
    cursor: Cursor | None = None,
    scope: ServiceAccount | None = None,
) -> None:
    steps = page_querysets(query, scope=scope, cursor=cursor, limit=PAGE)
    if len(steps) == 1:
        summarize(name, steps[0], designed_for)
        return
    probe, selective = steps
    filled = len(list(probe)) >= PAGE
    summarize(f"{name}, step 1: newest {RECENT_PROBE_ROWS:,} rows", probe, None)
    print(f"page filled by step 1: {'yes (step 2 not run by the API)' if filled else 'no'}")
    summarize(f"{name}, step 2: selective plan", selective, designed_for)


now = timezone.now()


def in_window(**filters: Any) -> EventQuery:
    """An EventQuery over the default 30-day window."""
    return EventQuery(created_after=now - timedelta(days=30), created_before=now, **filters)


total = AuditEvent.objects.count()
print(f"dataset: {total:,} audit events")

report("Newest page (default 30-day window)", in_window(), "audit_created_id_idx")

sample = AuditEvent.objects.filter(created_at__gte=now - timedelta(days=10)).order_by(
    "-created_at", "-id"
)[5000]
report(
    "Deep page via keyset cursor (5,000 rows in)",
    in_window(),
    "audit_created_id_idx",
    cursor=Cursor(created_at=sample.created_at, id=sample.id),
)

# The busiest actor is a hard case for the planner: it looks so common that walking the
# time index and filtering seems cheap, even when its events are old.
busiest = AuditEvent.objects.values("actor_id").annotate(n=Count("id")).order_by("-n").first()
busy_actor = busiest["actor_id"] if busiest else None
report(
    f"Actor history (busiest actor, {busy_actor})",
    in_window(actor_id=busy_actor),
    "audit_actor_created_id_idx",
)
report(
    "Resource history (storage.bucket/bucket-42)",
    in_window(resource_type="storage.bucket", resource_id="bucket-42"),
    "audit_resource_created_id_idx",
)
report("CRITICAL alerts", in_window(severities=("CRITICAL",)), "audit_severity_created_id_idx")
report(
    "Action filter (auth.login.failed)",
    in_window(action="auth.login.failed"),
    "audit_action_created_id_idx",
)
report(
    "Source IP (203.0.113.77)",
    in_window(ip_address="203.0.113.77"),
    "audit_ip_created_id_idx",
)
report(
    'Metadata containment, common value {"mfa": true}',
    in_window(metadata_contains={"mfa": True}),
    "audit_metadata_gin",
)
report(
    'Metadata containment, rare value {"rule_id": "R-2518"}',
    in_window(metadata_contains={"rule_id": "R-2518"}),
    "audit_metadata_gin",
)

# Worst cases: values whose rows are not spread evenly over time, and a cursor far from
# the newest rows. Each of them used to read most of the time window.
print("\n## Worst cases")
deep_row = (
    AuditEvent.objects.filter(created_at__gte=now - timedelta(days=30))
    .order_by("created_at", "id")[PAGE : PAGE + 1]
    .first()
)
if deep_row is not None:
    behind = AuditEvent.objects.filter(
        created_at__gte=now - timedelta(days=30), created_at__gt=deep_row.created_at
    ).count()
    report(
        f"Last page of the window ({behind:,} newer rows skipped by the cursor)",
        in_window(),
        "audit_created_id_idx",
        cursor=Cursor(created_at=deep_row.created_at, id=deep_row.id),
    )
report(
    "Action filter (auth.token.refreshed)",
    in_window(action="auth.token.refreshed"),
    "audit_action_created_id_idx",
)
report(
    "Source IP with no events (192.0.2.200)",
    in_window(ip_address="192.0.2.200"),
    "audit_ip_created_id_idx",
)
smallest = (
    AuditEvent.objects.filter(producer_service_account__isnull=False)
    .values("producer_service_account")
    .annotate(n=Count("id"))
    .order_by("n")
    .first()
)
if smallest is not None:
    report(
        f"API key scope (smallest producer: {smallest['n']:,} event(s))",
        in_window(),
        "audit_producer_created_id_idx",
        scope=ServiceAccount.objects.get(pk=smallest["producer_service_account"]),
    )
