from __future__ import annotations

import hashlib
import logging
import uuid
from collections.abc import Callable
from datetime import timedelta

import pytest
import time_machine
from django.utils import timezone
from rest_framework.test import APIClient

from apps.accounts.models import APIKey, Role, ServiceAccount, User
from apps.accounts.services import IssuedAPIKey

pytestmark = pytest.mark.django_db
SA_URL = "/api/v1/accounts/service-accounts/"
INTROSPECT_URL = "/api/v1/auth/api-key/introspect/"

ClientFor = Callable[[User], APIClient]
MakeUser = Callable[..., User]
IssueKey = Callable[..., tuple[ServiceAccount, IssuedAPIKey]]


def _keys_url(account: ServiceAccount) -> str:
    return f"{SA_URL}{account.pk}/api-keys/"


# --------------------------------------------------------------------------------------
# Service accounts
# --------------------------------------------------------------------------------------
def test_service_account_lifecycle(admin_user: User, client_for: ClientFor) -> None:
    client = client_for(admin_user)

    created = client.post(SA_URL, {"name": "siem-forwarder", "description": "SIEM"}, format="json")
    duplicate = client.post(SA_URL, {"name": "siem-forwarder"}, format="json")
    listed = client.get(SA_URL).json()

    assert created.status_code == 201
    assert created.json()["active_key_count"] == 0
    assert duplicate.status_code == 409
    assert [sa["name"] for sa in listed["results"]] == ["siem-forwarder"]


def test_service_account_permissions(make_user: MakeUser, client_for: ClientFor) -> None:
    analyst = client_for(make_user(roles=["security_analyst"]))

    assert analyst.get(SA_URL).status_code == 200
    assert analyst.post(SA_URL, {"name": "nope"}, format="json").status_code == 403


# --------------------------------------------------------------------------------------
# Issuing keys
# --------------------------------------------------------------------------------------
def test_issued_key_is_returned_once_and_stored_hashed(
    admin_user: User, client_for: ClientFor, issue_key: IssueKey
) -> None:
    account, _ = issue_key()
    client = client_for(admin_user)

    response = client.post(
        _keys_url(account), {"name": "ci", "scopes": ["audit:write", "audit:read"]}, format="json"
    )

    assert response.status_code == 201
    assert response["Cache-Control"] == "no-store"
    body = response.json()
    raw = body["key"]
    assert raw.startswith(f"sntl_{body['prefix']}_")
    assert body["scopes"] == ["audit:read", "audit:write"]
    stored = APIKey.objects.get(pk=body["id"])
    assert stored.key_hash == hashlib.sha256(raw.encode()).hexdigest()
    assert raw not in str(APIKey.objects.filter(pk=body["id"]).values().get())

    listing = client.get(_keys_url(account)).json()
    assert all("key" not in item and "key_hash" not in item for item in listing)
    assert raw not in str(listing)


def test_default_and_maximum_key_lifetime(
    admin_user: User, client_for: ClientFor, issue_key: IssueKey
) -> None:
    account, _ = issue_key()
    client = client_for(admin_user)
    now = timezone.now()

    default = client.post(
        _keys_url(account), {"name": "a", "scopes": ["audit:write"]}, format="json"
    )
    too_long = client.post(
        _keys_url(account),
        {
            "name": "b",
            "scopes": ["audit:write"],
            "expires_at": (now + timedelta(days=400)).isoformat(),
        },
        format="json",
    )
    in_past = client.post(
        _keys_url(account),
        {
            "name": "c",
            "scopes": ["audit:write"],
            "expires_at": (now - timedelta(minutes=1)).isoformat(),
        },
        format="json",
    )

    expires = APIKey.objects.get(pk=default.json()["id"]).expires_at
    assert timedelta(days=89, hours=23) < expires - now < timedelta(days=90, minutes=1)
    assert too_long.status_code == 400
    assert in_past.status_code == 400


@pytest.mark.parametrize("scopes", [[], ["audit:destroy"]])
def test_invalid_scopes_are_rejected(
    admin_user: User, client_for: ClientFor, issue_key: IssueKey, scopes: list[str]
) -> None:
    account, _ = issue_key()

    response = client_for(admin_user).post(
        _keys_url(account), {"name": "x", "scopes": scopes}, format="json"
    )

    assert response.status_code == 400
    assert response.json()["errors"][0]["field"] == "scopes"


def test_key_managers_cannot_issue_scopes_they_do_not_hold(
    make_user: MakeUser,
    client_for: ClientFor,
    make_role: Callable[..., Role],
    issue_key: IssueKey,
) -> None:
    make_role("key-manager", ["api_keys:manage", "service_accounts:read", "audit:read"])
    account, _ = issue_key()
    client = client_for(make_user(roles=["key-manager"]))

    escalate = client.post(
        _keys_url(account), {"name": "x", "scopes": ["audit:write"]}, format="json"
    )
    allowed = client.post(
        _keys_url(account), {"name": "y", "scopes": ["audit:read"]}, format="json"
    )

    assert escalate.status_code == 403
    assert allowed.status_code == 201


def test_inactive_service_accounts_cannot_receive_keys(
    admin_user: User, client_for: ClientFor, issue_key: IssueKey
) -> None:
    account, _ = issue_key()
    client = client_for(admin_user)
    client.patch(f"{SA_URL}{account.pk}/", {"is_active": False}, format="json")

    response = client.post(
        _keys_url(account), {"name": "x", "scopes": ["audit:write"]}, format="json"
    )

    assert response.status_code == 400


# --------------------------------------------------------------------------------------
# Authenticating with keys
# --------------------------------------------------------------------------------------
def test_introspection_describes_the_calling_key(issue_key: IssueKey) -> None:
    account, issued = issue_key(scopes=["audit:write"])

    response = APIClient().get(INTROSPECT_URL, HTTP_X_API_KEY=issued.raw_key)

    assert response.status_code == 200
    assert response.json() == {
        "service_account_id": str(account.pk),
        "service_account_name": account.name,
        "key_id": str(issued.api_key.pk),
        "key_name": "test key",
        "prefix": issued.api_key.prefix,
        "scopes": ["audit:write"],
        "expires_at": issued.api_key.expires_at.isoformat().replace("+00:00", "Z"),
    }


def _assert_rejected(raw_key: str) -> None:
    response = APIClient().get(INTROSPECT_URL, HTTP_X_API_KEY=raw_key)
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid API key."
    assert response["WWW-Authenticate"] == 'ApiKey header="X-API-Key"'


def test_every_invalid_key_gets_the_same_generic_rejection(issue_key: IssueKey) -> None:
    _, issued = issue_key()
    prefix = issued.api_key.prefix

    _assert_rejected("garbage")
    _assert_rejected(f"sntl_{prefix}_" + "A" * 43)  # right prefix, wrong secret
    _assert_rejected("sntl_ZZZZZZZZ_" + "A" * 43)  # unknown prefix


def test_revoked_expired_and_disabled_keys_stop_working(
    issue_key: IssueKey, admin_user: User, client_for: ClientFor
) -> None:
    _, revoked = issue_key()
    revoked.api_key.revoked_at = timezone.now()
    revoked.api_key.save()
    _assert_rejected(revoked.raw_key)

    _, expiring = issue_key(expires_at=timezone.now() + timedelta(hours=1))
    with time_machine.travel(timezone.now() + timedelta(hours=2), tick=False):
        _assert_rejected(expiring.raw_key)

    account, disabled = issue_key()
    client_for(admin_user).patch(f"{SA_URL}{account.pk}/", {"is_active": False}, format="json")
    _assert_rejected(disabled.raw_key)


def test_revocation_endpoint_is_immediate_idempotent_and_scoped(
    admin_user: User, client_for: ClientFor, issue_key: IssueKey
) -> None:
    account, issued = issue_key()
    other_account, _ = issue_key()
    client = client_for(admin_user)
    revoke_url = f"{_keys_url(account)}{issued.api_key.pk}/revoke/"

    first = client.post(revoke_url)
    second = client.post(revoke_url)
    cross_account = client.post(f"{_keys_url(other_account)}{issued.api_key.pk}/revoke/")

    assert first.status_code == 200
    assert first.json()["is_active"] is False
    assert second.json()["revoked_at"] == first.json()["revoked_at"]
    assert cross_account.status_code == 404
    _assert_rejected(issued.raw_key)


def test_api_keys_and_jwts_do_not_unlock_each_others_endpoints(
    issue_key: IssueKey, admin_user: User, client_for: ClientFor
) -> None:
    _, issued = issue_key(scopes=["users:read"])

    with_key = APIClient().get("/api/v1/accounts/users/", HTTP_X_API_KEY=issued.raw_key)
    with_jwt = client_for(admin_user).get(INTROSPECT_URL)

    assert with_key.status_code == 401
    assert with_jwt.status_code == 401


def test_last_used_is_recorded_but_not_on_every_request(issue_key: IssueKey) -> None:
    _, issued = issue_key()
    key = issued.api_key

    APIClient().get(INTROSPECT_URL, HTTP_X_API_KEY=issued.raw_key)
    key.refresh_from_db()
    first_use = key.last_used_at
    APIClient().get(INTROSPECT_URL, HTTP_X_API_KEY=issued.raw_key)
    key.refresh_from_db()

    assert first_use is not None
    assert key.last_used_at == first_use

    with time_machine.travel(timezone.now() + timedelta(seconds=61), tick=False):
        APIClient().get(INTROSPECT_URL, HTTP_X_API_KEY=issued.raw_key)
    key.refresh_from_db()
    assert key.last_used_at is not None
    assert key.last_used_at > first_use


def test_raw_keys_never_reach_the_logs(
    admin_user: User, client_for: ClientFor, issue_key: IssueKey, caplog: pytest.LogCaptureFixture
) -> None:
    account, _ = issue_key()
    with caplog.at_level(logging.DEBUG):
        raw = (
            client_for(admin_user)
            .post(_keys_url(account), {"name": "x", "scopes": ["audit:write"]}, format="json")
            .json()["key"]
        )
        APIClient().get(INTROSPECT_URL, HTTP_X_API_KEY=raw)
        APIClient().get(INTROSPECT_URL, HTTP_X_API_KEY=raw[:-2] + "zz")

    for record in caplog.records:
        assert raw not in record.getMessage()
        assert raw not in str(record.__dict__)


def test_unknown_service_account_is_404(admin_user: User, client_for: ClientFor) -> None:
    assert client_for(admin_user).get(f"{SA_URL}{uuid.uuid4()}/").status_code == 404
