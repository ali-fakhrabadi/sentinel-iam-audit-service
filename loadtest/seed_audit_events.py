"""Seed a representative audit dataset for query benchmarks.

Run inside the dev container (it bind-mounts the repository and uses the bootstrap
role, which may write directly)::

    docker compose --profile dev run --rm -e SEED_EVENTS=1000000 dev \
        python manage.py shell -c "exec(open('loadtest/seed_audit_events.py').read())"

The distribution mimics a busy SaaS tenant: 85 % INFO, 12 % WARN, 3 % CRITICAL;
5,000 actors with a long tail; events spread over the last 60 days. The generator is
seeded, so runs are reproducible. Rows are inserted directly (no outbox), because
historical data must not trigger webhooks.
"""

from __future__ import annotations

import os
import random
import time
import uuid
from datetime import datetime, timedelta

from django.db import connection
from django.utils import timezone

from apps.accounts.models import ServiceAccount
from apps.audit_logs.models import AuditEvent

TOTAL = int(os.environ.get("SEED_EVENTS", "1000000"))
BATCH = 10_000
DAYS = 60
rng = random.Random(20261026)  # reproducible test data

ACTIONS = [
    ("auth.login.succeeded", "iam.user", "INFO", 30),
    ("auth.login.failed", "iam.user", "WARN", 6),
    ("auth.mfa.challenged", "iam.user", "INFO", 8),
    ("auth.token.refreshed", "iam.user", "INFO", 20),
    ("iam.role.assigned", "iam.user", "WARN", 1),
    ("iam.api_key.issued", "iam.api_key", "WARN", 1),
    ("storage.object.read", "storage.object", "INFO", 15),
    ("storage.object.deleted", "storage.object", "WARN", 3),
    ("storage.bucket.policy_changed", "storage.bucket", "CRITICAL", 1),
    ("network.firewall.rule_changed", "network.firewall", "WARN", 1),
    ("edr.malware.detected", "host", "CRITICAL", 1),
    ("edr.process.blocked", "host", "WARN", 2),
    ("db.query.exported", "db.table", "INFO", 6),
    ("admin.settings.changed", "admin.setting", "WARN", 1),
    ("billing.invoice.viewed", "billing.invoice", "INFO", 4),
]
ACTION_WEIGHTS = [weight for *_, weight in ACTIONS]
COUNTRIES = ["DE", "US", "NL", "GB", "FR", "SE", "SG", "JP", "BR", "CA"]


def producers() -> list[ServiceAccount]:
    accounts = []
    for name in ("bench-idp", "bench-edr", "bench-storage", "bench-network", "bench-app"):
        account, _ = ServiceAccount.objects.get_or_create(
            name=name, defaults={"description": "Benchmark data producer"}
        )
        accounts.append(account)
    return accounts


def event(now: datetime, accounts: list[ServiceAccount]) -> AuditEvent:
    action, resource_type, base_severity, _ = rng.choices(ACTIONS, ACTION_WEIGHTS)[0]
    severity = base_severity
    if severity == "INFO" and rng.random() < 0.03:
        severity = "WARN"
    # Long-tail actors: a few very active, many rare.
    actor = f"user-{int(rng.paretovariate(1.2)) % 5000:04d}"
    created_at = now - timedelta(seconds=rng.randint(0, DAYS * 86_400))
    metadata = {
        "country": rng.choice(COUNTRIES),
        "mfa": rng.random() < 0.8,
        "rule_id": f"R-{rng.randint(1, 5000)}",
    }
    return AuditEvent(
        id=uuid.uuid4(),
        action=action,
        resource_type=resource_type,
        resource_id=f"{resource_type.split('.')[-1]}-{rng.randint(1, 20000)}",
        actor_id=actor,
        ip_address=f"203.0.113.{rng.randint(1, 254)}"
        if rng.random() < 0.5
        else f"198.51.100.{rng.randint(1, 254)}",
        user_agent="Mozilla/5.0 (benchmark)",
        severity=severity,
        metadata=metadata,
        occurred_at=created_at,
        received_at=created_at,
        created_at=created_at,
        producer_service_account=rng.choice(accounts),
    )


def run() -> None:
    accounts = producers()
    now = timezone.now()
    started = time.perf_counter()
    inserted = 0
    while inserted < TOTAL:
        size = min(BATCH, TOTAL - inserted)
        AuditEvent.objects.bulk_create([event(now, accounts) for _ in range(size)])
        inserted += size
        if inserted % 100_000 == 0 or inserted == TOTAL:
            print(f"{inserted:>9,} events  {time.perf_counter() - started:6.1f}s")
    with connection.cursor() as cursor:
        cursor.execute("ANALYZE audit_logs_auditevent")
        cursor.execute("SELECT pg_size_pretty(pg_total_relation_size('audit_logs_auditevent'))")
        print(f"table + indexes: {cursor.fetchone()[0]}")


run()
