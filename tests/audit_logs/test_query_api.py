from __future__ import annotations

import base64
import json
from collections.abc import Callable
from datetime import timedelta
from typing import Any

import pytest
from django.utils import timezone
from rest_framework.test import APIClient

from apps.accounts.models import ServiceAccount, User
from apps.accounts.services import IssuedAPIKey
from apps.audit_logs.models import AuditEvent
from tests.factories import create_event, create_service_account

pytestmark = pytest.mark.django_db
URL = "/api/v1/audit/events/"

ClientFor = Callable[[User], APIClient]
MakeUser = Callable[..., User]


@pytest.fixture
def auditor_client(make_user: MakeUser, client_for: ClientFor) -> APIClient:
    return client_for(make_user(roles=["auditor"]))


@pytest.fixture
def sample_events() -> dict[str, AuditEvent]:
    account = create_service_account(name="idp-connector")
    return {
        "failed_login": create_event(
            producer=account,
            action="auth.login.failed",
            actor_id="alice",
            severity="WARN",
            ip_address="203.0.113.7",
            resource_type="iam.user",
            resource_id="u-1",
            metadata={"mfa": False, "geo": {"country": "DE"}},
        ),
        "login": create_event(
            producer=account,
            action="auth.login.succeeded",
            actor_id="alice",
            severity="INFO",
            metadata={"mfa": True},
        ),
        "bucket_deleted": create_event(
            producer=account,
            action="storage.bucket.deleted",
            actor_id="bob",
            severity="CRITICAL",
            resource_type="storage.bucket",
            resource_id="b-9",
        ),
    }


def _names(response: Any, events: dict[str, AuditEvent]) -> set[str]:
    by_id = {str(event.id): name for name, event in events.items()}
    return {by_id[item["id"]] for item in response.json()["results"] if item["id"] in by_id}


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({}, {"failed_login", "login", "bucket_deleted"}),
        ({"actor_id": "alice"}, {"failed_login", "login"}),
        ({"action": "auth.login.failed"}, {"failed_login"}),
        ({"action_prefix": "auth."}, {"failed_login", "login"}),
        ({"resource_type": "storage.bucket", "resource_id": "b-9"}, {"bucket_deleted"}),
        ({"severity": ["WARN", "CRITICAL"]}, {"failed_login", "bucket_deleted"}),
        ({"ip_address": "203.0.113.7"}, {"failed_login"}),
        ({"metadata_contains": '{"geo": {"country": "DE"}}'}, {"failed_login"}),
        ({"actor_id": "alice", "severity": "INFO"}, {"login"}),
    ],
)
def test_filters_combine(
    auditor_client: APIClient,
    sample_events: dict[str, AuditEvent],
    params: dict[str, Any],
    expected: set[str],
) -> None:
    response = auditor_client.get(URL, params)

    assert response.status_code == 200, response.content
    assert _names(response, sample_events) == expected


def test_results_include_trusted_producer_details(
    auditor_client: APIClient, sample_events: dict[str, AuditEvent]
) -> None:
    item = auditor_client.get(URL, {"action": "storage.bucket.deleted"}).json()["results"][0]

    assert item["producer"]["type"] == "service_account"
    assert item["producer"]["name"] == "idp-connector"
    assert item["actor_id"] == "bob"


def test_cursor_pagination_is_complete_and_ordered_with_identical_timestamps(
    auditor_client: APIClient,
) -> None:
    account = create_service_account()
    moment = timezone.now() - timedelta(minutes=1)
    created = [create_event(producer=account, created_at=moment) for _ in range(25)]

    seen: list[str] = []
    page = auditor_client.get(URL, {"page_size": 10}).json()
    while True:
        seen.extend(item["id"] for item in page["results"])
        if page["next_cursor"] is None:
            break
        page = auditor_client.get(URL, {"page_size": 10, "cursor": page["next_cursor"]}).json()

    expected = [str(e.id) for e in sorted(created, key=lambda e: e.id, reverse=True)]
    assert seen == expected


def test_pages_stay_stable_when_new_events_arrive(auditor_client: APIClient) -> None:
    account = create_service_account()
    base = timezone.now() - timedelta(minutes=10)
    for minute in range(5):
        create_event(producer=account, created_at=base + timedelta(minutes=minute))

    first = auditor_client.get(URL, {"page_size": 2}).json()
    newest = create_event(producer=account, created_at=timezone.now() - timedelta(seconds=1))
    rest = auditor_client.get(URL, {"page_size": 10, "cursor": first["next_cursor"]}).json()

    first_ids = {item["id"] for item in first["results"]}
    rest_ids = {item["id"] for item in rest["results"]}
    assert not first_ids & rest_ids
    assert len(first_ids | rest_ids) == 5
    assert str(newest.id) not in rest_ids


def test_next_link_preserves_filters(auditor_client: APIClient) -> None:
    account = create_service_account()
    for _ in range(3):
        create_event(producer=account, actor_id="carol")

    page = auditor_client.get(URL, {"actor_id": "carol", "page_size": "2"}).json()

    assert "actor_id=carol" in page["next"]
    assert f"cursor={page['next_cursor']}" in page["next"]


@pytest.mark.parametrize(
    "params",
    [
        {"cursor": "not-a-cursor"},
        {"cursor": base64.urlsafe_b64encode(json.dumps({"c": "x"}).encode()).decode()},
        {"cursor": base64.urlsafe_b64encode(b'{"c":"2026-01-01T00:00:00","i":"x"}').decode()},
        {"page_size": 0},
        {"page_size": 501},
        {"severity": "LOUD"},
        {"ip_address": "999.1.1.1"},
        {"metadata_contains": "not json"},
        {"metadata_contains": "[1, 2]"},
    ],
)
def test_invalid_query_parameters_are_rejected(
    auditor_client: APIClient, params: dict[str, Any]
) -> None:
    response = auditor_client.get(URL, params)

    assert response.status_code == 400
    assert response.json()["type"] == "urn:sentinel:problem:validation-error"


def test_query_time_windows_are_bounded(auditor_client: APIClient) -> None:
    now = timezone.now()
    account = create_service_account()
    old = create_event(producer=account, created_at=now - timedelta(days=31))

    inverted = auditor_client.get(
        URL,
        {"created_after": now.isoformat(), "created_before": (now - timedelta(days=1)).isoformat()},
    )
    too_wide = auditor_client.get(URL, {"created_after": (now - timedelta(days=91)).isoformat()})
    default = auditor_client.get(URL)
    explicit = auditor_client.get(URL, {"created_after": (now - timedelta(days=40)).isoformat()})

    assert inverted.status_code == 400
    assert too_wide.status_code == 400
    assert str(old.id) not in {item["id"] for item in default.json()["results"]}
    assert str(old.id) in {item["id"] for item in explicit.json()["results"]}


def test_reading_requires_audit_read(
    api_client: APIClient, make_user: MakeUser, client_for: ClientFor
) -> None:
    assert api_client.get(URL).status_code == 401
    assert client_for(make_user(roles=["iam_manager"])).get(URL).status_code == 403


def test_service_accounts_only_see_events_they_produced(
    issue_key: Callable[..., tuple[ServiceAccount, IssuedAPIKey]],
) -> None:
    reader, issued = issue_key(scopes=["audit:read"])
    own = create_event(producer=reader)
    foreign = create_event(producer=create_service_account())
    client = APIClient()
    client.credentials(HTTP_X_API_KEY=issued.raw_key)

    listed = {item["id"] for item in client.get(URL).json()["results"]}

    assert listed == {str(own.id)}
    assert client.get(f"{URL}{own.id}/").status_code == 200
    assert client.get(f"{URL}{foreign.id}/").status_code == 404


def test_users_see_everything_through_the_detail_endpoint(
    auditor_client: APIClient, sample_events: dict[str, AuditEvent]
) -> None:
    event = sample_events["bucket_deleted"]

    response = auditor_client.get(f"{URL}{event.id}/")

    assert response.status_code == 200
    assert response.json()["action"] == "storage.bucket.deleted"


@pytest.mark.parametrize("method", ["put", "patch", "delete"])
def test_the_api_offers_no_way_to_change_events(
    admin_user: User,
    client_for: ClientFor,
    sample_events: dict[str, AuditEvent],
    method: str,
) -> None:
    client = client_for(admin_user)
    event = sample_events["login"]

    response = getattr(client, method)(f"{URL}{event.id}/", {"severity": "INFO"}, format="json")

    assert response.status_code == 405
