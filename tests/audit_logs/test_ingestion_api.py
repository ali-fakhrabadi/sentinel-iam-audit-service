from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Any

import pytest
from django.db import OperationalError
from django.utils import timezone
from prometheus_client import REGISTRY
from pytest_django import DjangoAssertNumQueries, DjangoCaptureOnCommitCallbacks, Settings
from rest_framework.test import APIClient

from apps.accounts.models import ServiceAccount, User
from apps.accounts.services import IssuedAPIKey
from apps.audit_logs.models import AuditEvent, OutboxMessage, OutboxStatus

pytestmark = pytest.mark.django_db
BULK_URL = "/api/v1/audit/events/bulk/"
SINGLE_URL = "/api/v1/audit/events/"

IssueKey = Callable[..., tuple[ServiceAccount, IssuedAPIKey]]


@pytest.fixture
def ingest(issue_key: IssueKey) -> tuple[ServiceAccount, APIClient]:
    account, issued = issue_key(scopes=["audit:write", "audit:read"])
    client = APIClient()
    client.credentials(HTTP_X_API_KEY=issued.raw_key)
    return account, client


def _event(**overrides: Any) -> dict[str, Any]:
    event: dict[str, Any] = {
        "action": "auth.login.failed",
        "resource_type": "iam.user",
        "resource_id": "u-42",
        "actor_id": "jdoe",
        "ip_address": "203.0.113.7",
        "user_agent": "Mozilla/5.0",
        "severity": "WARN",
        "metadata": {"mfa": False},
    }
    event.update(overrides)
    return event


def _stored(account: ServiceAccount) -> int:
    return AuditEvent.objects.filter(producer_service_account=account).count()


# --------------------------------------------------------------------------------------
# Single events and provenance
# --------------------------------------------------------------------------------------
def test_single_event_is_normalized_and_stored_with_server_side_provenance(
    ingest: tuple[ServiceAccount, APIClient],
) -> None:
    account, client = ingest
    before = timezone.now()

    response = client.post(
        SINGLE_URL, _event(action=" Auth.Login.Failed ", severity="warn"), format="json"
    )

    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "accepted"
    event = AuditEvent.objects.get(pk=body["id"])
    assert event.action == "auth.login.failed"
    assert event.severity == "WARN"
    assert event.producer_service_account == account
    assert event.producer_user is None
    assert event.actor_id == "jdoe"
    assert before <= event.received_at <= event.created_at


def test_producer_identity_cannot_be_spoofed(
    ingest: tuple[ServiceAccount, APIClient], admin_user: User
) -> None:
    _, client = ingest

    response = client.post(
        SINGLE_URL,
        _event(producer_user=str(admin_user.pk), created_at="2020-01-01T00:00:00Z"),
        format="json",
    )

    assert response.status_code == 400
    assert {e["field"] for e in response.json()["errors"]} == {"producer_user", "created_at"}


def test_ingestion_requires_an_api_key_with_audit_write(
    api_client: APIClient,
    issue_key: IssueKey,
    client_for: Callable[[User], APIClient],
    admin_user: User,
) -> None:
    _, read_only = issue_key(scopes=["audit:read"])
    human = client_for(admin_user)

    assert api_client.post(SINGLE_URL, _event(), format="json").status_code == 401
    assert (
        APIClient()
        .post(SINGLE_URL, _event(), format="json", HTTP_X_API_KEY=read_only.raw_key)
        .status_code
        == 403
    )
    # Even an admin cannot write audit events with a user token: ingestion is machine-only.
    assert human.post(SINGLE_URL, _event(), format="json").status_code == 403
    assert human.post(BULK_URL, {"events": [_event()]}, format="json").status_code == 401


# --------------------------------------------------------------------------------------
# Bulk semantics
# --------------------------------------------------------------------------------------
def test_bulk_ingestion_uses_a_bounded_number_of_queries(
    ingest: tuple[ServiceAccount, APIClient], django_assert_max_num_queries: DjangoAssertNumQueries
) -> None:
    account, client = ingest
    events = [_event(resource_id=f"u-{i}") for i in range(200)]

    with django_assert_max_num_queries(12):
        response = client.post(BULK_URL, {"events": events}, format="json")

    assert response.status_code == 200
    body = response.json()
    assert (body["accepted"], body["duplicates"], body["rejected"]) == (200, 0, 0)
    assert [r["index"] for r in body["results"]] == list(range(200))
    assert _stored(account) == 200


def test_partial_success_reports_each_item_and_stores_only_valid_ones(
    ingest: tuple[ServiceAccount, APIClient],
) -> None:
    account, client = ingest
    future = (timezone.now() + timedelta(hours=1)).isoformat()
    events = [
        _event(),
        _event(severity="LOUD"),
        _event(action="Not Valid"),
        "not-an-object",
        _event(metadata={"password": "hunter2"}),
        _event(occurred_at=future),
        _event(priority="high"),
    ]

    body = client.post(BULK_URL, {"events": events}, format="json").json()

    assert (body["accepted"], body["rejected"]) == (1, 6)
    statuses = [r["status"] for r in body["results"]]
    assert statuses == ["accepted"] + ["rejected"] * 6
    fields = [{e["field"] for e in r.get("errors", [])} for r in body["results"]]
    assert fields[1:] == [
        {"severity"},
        {"action"},
        {"non_field_errors"},
        {"metadata"},
        {"occurred_at"},
        {"priority"},
    ]
    assert body["results"][1]["event_id"] is None
    assert _stored(account) == 1
    assert "hunter2" not in str(body)


@pytest.mark.parametrize(
    "payload",
    [{}, {"events": []}, {"events": "x"}, [{"action": "a.b"}], {"events": [{}], "extra": 1}],
)
def test_malformed_envelopes_are_rejected(
    ingest: tuple[ServiceAccount, APIClient], payload: Any
) -> None:
    _, client = ingest

    response = client.post(BULK_URL, payload, format="json")

    assert response.status_code == 400
    assert response.json()["type"] == "urn:sentinel:problem:validation-error"


def test_batch_size_is_limited(
    ingest: tuple[ServiceAccount, APIClient], settings: Settings
) -> None:
    settings.AUDIT_BULK_MAX_EVENTS = 3
    _, client = ingest

    response = client.post(BULK_URL, {"events": [_event()] * 4}, format="json")

    assert response.status_code == 400


def test_oversized_bodies_are_rejected_before_parsing(
    ingest: tuple[ServiceAccount, APIClient], settings: Settings
) -> None:
    settings.API_MAX_REQUEST_BYTES = 2048
    _, client = ingest

    response = client.post(BULK_URL, {"events": [_event(user_agent="x" * 500)] * 6}, format="json")

    assert response.status_code == 413


def test_occurred_at_trust_policy(ingest: tuple[ServiceAccount, APIClient]) -> None:
    _, client = ingest
    now = timezone.now()
    events = [
        _event(occurred_at=(now + timedelta(minutes=2)).isoformat()),
        _event(occurred_at=(now - timedelta(days=31)).isoformat()),
        _event(occurred_at=(now - timedelta(days=2)).isoformat()),
    ]

    statuses = [
        r["status"]
        for r in client.post(BULK_URL, {"events": events}, format="json").json()["results"]
    ]

    assert statuses == ["accepted", "rejected", "accepted"]


# --------------------------------------------------------------------------------------
# Idempotency
# --------------------------------------------------------------------------------------
def test_retrying_a_batch_with_idempotency_keys_creates_no_duplicates(
    ingest: tuple[ServiceAccount, APIClient],
) -> None:
    account, client = ingest
    payload = {"events": [_event(idempotency_key="evt-1"), _event(idempotency_key="evt-2")]}

    first = client.post(BULK_URL, payload, format="json").json()
    retry = client.post(BULK_URL, payload, format="json").json()

    assert (first["accepted"], retry["accepted"], retry["duplicates"]) == (2, 0, 2)
    assert [r["event_id"] for r in retry["results"]] == [r["event_id"] for r in first["results"]]
    assert _stored(account) == 2


def test_repeated_keys_inside_one_batch_resolve_to_one_event(
    ingest: tuple[ServiceAccount, APIClient],
) -> None:
    account, client = ingest
    payload = {"events": [_event(idempotency_key="same"), _event(idempotency_key="same")]}

    results = client.post(BULK_URL, payload, format="json").json()["results"]

    assert [r["status"] for r in results] == ["accepted", "duplicate"]
    assert results[0]["event_id"] == results[1]["event_id"]
    assert _stored(account) == 1


def test_idempotency_keys_are_scoped_per_producer(issue_key: IssueKey) -> None:
    clients = []
    for _ in range(2):
        _, issued = issue_key(scopes=["audit:write"])
        client = APIClient()
        client.credentials(HTTP_X_API_KEY=issued.raw_key)
        clients.append(client)

    statuses = [
        c.post(SINGLE_URL, _event(idempotency_key="shared"), format="json").status_code
        for c in clients
    ]

    assert statuses == [201, 201]


def test_single_endpoint_reports_duplicates_with_200(
    ingest: tuple[ServiceAccount, APIClient],
) -> None:
    _, client = ingest

    first = client.post(SINGLE_URL, _event(idempotency_key="k1"), format="json")
    again = client.post(SINGLE_URL, _event(idempotency_key="k1"), format="json")

    assert (first.status_code, again.status_code) == (201, 200)
    assert again.json() == {"id": first.json()["id"], "status": "duplicate"}


# --------------------------------------------------------------------------------------
# Transactions and the outbox
# --------------------------------------------------------------------------------------
def test_database_failure_stores_nothing_and_says_so(
    ingest: tuple[ServiceAccount, APIClient], monkeypatch: pytest.MonkeyPatch
) -> None:
    account, client = ingest

    def fail(*args: Any, **kwargs: Any) -> None:
        raise OperationalError("server closed the connection unexpectedly")

    # Events are inserted first; failing on the outbox insert proves the rollback.
    monkeypatch.setattr(OutboxMessage.objects, "bulk_create", fail)

    response = client.post(BULK_URL, {"events": [_event(), _event()]}, format="json")

    assert response.status_code == 503
    body = response.json()
    assert body["type"] == "urn:sentinel:problem:service-unavailable"
    assert "No events were stored" in body["detail"]
    assert _stored(account) == 0


def test_warn_and_critical_events_enter_the_outbox_and_trigger_dispatch(
    ingest: tuple[ServiceAccount, APIClient],
    django_capture_on_commit_callbacks: DjangoCaptureOnCommitCallbacks,
    sent_tasks: list[tuple[str, float | None]],
) -> None:
    account, client = ingest
    events = [_event(severity="INFO"), _event(severity="WARN"), _event(severity="CRITICAL")]

    with django_capture_on_commit_callbacks(execute=True):
        client.post(BULK_URL, {"events": events}, format="json")

    queued = OutboxMessage.objects.filter(event__producer_service_account=account)
    assert sorted(queued.values_list("event__severity", flat=True)) == ["CRITICAL", "WARN"]
    assert set(queued.values_list("status", flat=True)) == {OutboxStatus.PENDING}
    # A leading drain right away and a trailing one at the end of the window.
    assert sent_tasks == [("webhooks.dispatch_outbox", None), ("webhooks.dispatch_outbox", 1)]


def test_dispatch_triggers_are_coalesced_per_window(
    ingest: tuple[ServiceAccount, APIClient],
    django_capture_on_commit_callbacks: DjangoCaptureOnCommitCallbacks,
    sent_tasks: list[tuple[str, float | None]],
) -> None:
    _, client = ingest

    with django_capture_on_commit_callbacks(execute=True):
        for _ in range(5):
            client.post(SINGLE_URL, _event(severity="CRITICAL"), format="json")

    # Five commits inside one window share one leading and one trailing drain.
    assert sent_tasks == [("webhooks.dispatch_outbox", None), ("webhooks.dispatch_outbox", 1)]


def test_ingestion_outcomes_are_counted_in_metrics(
    ingest: tuple[ServiceAccount, APIClient],
) -> None:
    _, client = ingest

    def sample(result: str) -> float:
        value = REGISTRY.get_sample_value(
            "sentinel_audit_events_ingested_total", {"result": result}
        )
        return value or 0.0

    before = {name: sample(name) for name in ("accepted", "rejected")}
    client.post(BULK_URL, {"events": [_event(), _event(severity="LOUD")]}, format="json")

    assert sample("accepted") - before["accepted"] == 1
    assert sample("rejected") - before["rejected"] == 1
