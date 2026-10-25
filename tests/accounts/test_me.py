from __future__ import annotations

from collections.abc import Callable

import pytest
from rest_framework.test import APIClient

from apps.accounts.catalog import PermissionCode
from apps.accounts.models import ServiceAccount, User
from apps.accounts.services import IssuedAPIKey

pytestmark = pytest.mark.django_db
ME_URL = "/api/v1/accounts/me/"


def test_me_returns_profile_roles_and_flattened_permissions(
    make_user: Callable[..., User], client_for: Callable[[User], APIClient]
) -> None:
    user = make_user(email="nina@example.test", roles=["security_analyst", "auditor"])

    response = client_for(user).get(ME_URL)

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(user.pk)
    assert body["email"] == "nina@example.test"
    assert body["roles"] == ["auditor", "security_analyst"]
    # audit:read comes from both roles but appears once; the list is sorted.
    assert body["permissions"] == sorted(
        ["audit:read", "roles:read", "service_accounts:read", "users:read", "webhooks:read"]
    )
    assert set(body) == {
        "id",
        "email",
        "full_name",
        "is_superuser",
        "date_joined",
        "last_login",
        "roles",
        "permissions",
    }


def test_superusers_hold_the_whole_catalog(
    superuser: User, client_for: Callable[[User], APIClient]
) -> None:
    body = client_for(superuser).get(ME_URL).json()

    assert body["permissions"] == sorted(str(code) for code in PermissionCode)
    assert body["roles"] == []


def test_users_without_roles_have_no_permissions(
    make_user: Callable[..., User], client_for: Callable[[User], APIClient]
) -> None:
    assert client_for(make_user()).get(ME_URL).json()["permissions"] == []


def test_profile_update_changes_only_the_name(
    make_user: Callable[..., User], client_for: Callable[[User], APIClient]
) -> None:
    user = make_user()

    response = client_for(user).patch(ME_URL, {"full_name": "New Name"}, format="json")

    assert response.status_code == 200
    assert response.json()["full_name"] == "New Name"


@pytest.mark.parametrize(
    "payload",
    [
        {"full_name": "x", "is_superuser": True},
        {"full_name": "x", "is_staff": True},
        {"full_name": "x", "email": "takeover@example.test"},
    ],
)
def test_privileged_fields_cannot_be_mass_assigned(
    make_user: Callable[..., User],
    client_for: Callable[[User], APIClient],
    payload: dict[str, object],
) -> None:
    user = make_user(full_name="Original")

    response = client_for(user).patch(ME_URL, payload, format="json")

    assert response.status_code == 400
    rejected = {error["field"] for error in response.json()["errors"]}
    assert rejected == set(payload) - {"full_name"}
    user.refresh_from_db()
    assert (user.full_name, user.is_superuser, user.is_staff) == ("Original", False, False)
    assert user.email != "takeover@example.test"


def test_me_requires_a_user_token(
    api_client: APIClient, issue_key: Callable[..., tuple[ServiceAccount, IssuedAPIKey]]
) -> None:
    assert api_client.get(ME_URL).status_code == 401

    _, issued = issue_key()
    response = api_client.get(ME_URL, HTTP_X_API_KEY=issued.raw_key)
    # API keys are not accepted on human endpoints: the header is simply not an option here.
    assert response.status_code == 401
