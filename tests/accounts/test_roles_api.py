from __future__ import annotations

from collections.abc import Callable

import pytest
from rest_framework.test import APIClient

from apps.accounts.catalog import PermissionCode
from apps.accounts.models import Role, User

pytestmark = pytest.mark.django_db
ROLES_URL = "/api/v1/accounts/roles/"

ClientFor = Callable[[User], APIClient]
MakeUser = Callable[..., User]


def test_roles_and_catalog_are_readable_with_roles_read(
    make_user: MakeUser, client_for: ClientFor
) -> None:
    client = client_for(make_user(roles=["security_analyst"]))

    roles = client.get(ROLES_URL).json()
    catalog = client.get("/api/v1/accounts/permissions/").json()

    by_name = {role["name"]: role for role in roles}
    assert {"admin", "iam_manager", "security_analyst", "auditor"} <= set(by_name)
    assert by_name["auditor"]["permissions"] == ["audit:read"]
    assert by_name["auditor"]["is_system"] is True
    assert [p["code"] for p in catalog] == sorted(str(code) for code in PermissionCode)


def test_admin_creates_updates_and_deletes_custom_roles(
    admin_user: User, client_for: ClientFor
) -> None:
    client = client_for(admin_user)

    created = client.post(
        ROLES_URL,
        {"name": "soc-tier1", "description": "SOC", "permissions": ["audit:read", "webhooks:read"]},
        format="json",
    )
    updated = client.patch(f"{ROLES_URL}soc-tier1/", {"permissions": ["audit:read"]}, format="json")
    deleted = client.delete(f"{ROLES_URL}soc-tier1/")

    assert created.status_code == 201
    assert created.json()["permissions"] == ["audit:read", "webhooks:read"]
    assert updated.status_code == 200
    assert updated.json()["permissions"] == ["audit:read"]
    assert deleted.status_code == 204
    assert not Role.objects.filter(name="soc-tier1").exists()


def test_role_creation_validation(admin_user: User, client_for: ClientFor) -> None:
    client = client_for(admin_user)

    unknown = client.post(ROLES_URL, {"name": "r1", "permissions": ["audit:delete"]}, format="json")
    bad_name = client.post(ROLES_URL, {"name": "Bad Name", "permissions": []}, format="json")
    duplicate = client.post(ROLES_URL, {"name": "auditor", "permissions": []}, format="json")

    assert unknown.status_code == 400
    assert unknown.json()["errors"][0]["field"] == "permissions"
    assert bad_name.status_code == 400
    assert duplicate.status_code == 409


def test_role_managers_cannot_create_roles_beyond_their_permissions(
    make_user: MakeUser, client_for: ClientFor
) -> None:
    client = client_for(make_user(roles=["iam_manager"]))

    response = client.post(
        ROLES_URL, {"name": "sneaky", "permissions": ["audit:write"]}, format="json"
    )
    allowed = client.post(
        ROLES_URL, {"name": "helpdesk", "permissions": ["users:read"]}, format="json"
    )

    assert response.status_code == 403
    assert allowed.status_code == 201


def test_role_managers_cannot_change_roles_they_do_not_fully_hold(
    make_user: MakeUser, client_for: ClientFor, make_role: Callable[..., Role]
) -> None:
    make_role("analyst-plus", ["audit:read", "users:read"])
    client = client_for(make_user(roles=["iam_manager"]))

    # Removing audit:read would demote every holder: also forbidden.
    response = client.patch(
        f"{ROLES_URL}analyst-plus/", {"permissions": ["users:read"]}, format="json"
    )

    assert response.status_code == 403


@pytest.mark.parametrize("method", ["patch", "delete"])
def test_built_in_roles_are_immutable(admin_user: User, client_for: ClientFor, method: str) -> None:
    client = client_for(admin_user)

    response = getattr(client, method)(f"{ROLES_URL}auditor/", {"description": "x"}, format="json")

    assert response.status_code == 403
    assert Role.objects.get(name="auditor").description == "Read-only access to audit events."


def test_assigned_roles_cannot_be_deleted(
    admin_user: User, client_for: ClientFor, make_role: Callable[..., Role], make_user: MakeUser
) -> None:
    make_role("on-call", ["audit:read"])
    make_user(roles=["on-call"])

    response = client_for(admin_user).delete(f"{ROLES_URL}on-call/")

    assert response.status_code == 409
    assert response.json()["type"] == "urn:sentinel:problem:conflict"
