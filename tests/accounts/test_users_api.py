from __future__ import annotations

import uuid
from collections.abc import Callable

import pytest
from rest_framework.test import APIClient

from apps.accounts.models import Role, User, UserRole

pytestmark = pytest.mark.django_db
USERS_URL = "/api/v1/accounts/users/"

ClientFor = Callable[[User], APIClient]
MakeUser = Callable[..., User]


def _roles_url(user: User, role: str | None = None) -> str:
    base = f"{USERS_URL}{user.pk}/roles/"
    return f"{base}{role}/" if role else base


# --------------------------------------------------------------------------------------
# Listing and reading
# --------------------------------------------------------------------------------------
def test_listing_users_requires_users_read(
    api_client: APIClient, make_user: MakeUser, client_for: ClientFor
) -> None:
    assert api_client.get(USERS_URL).status_code == 401
    assert client_for(make_user(roles=["auditor"])).get(USERS_URL).status_code == 403
    assert client_for(make_user(roles=["security_analyst"])).get(USERS_URL).status_code == 200


def test_user_list_is_cursor_paginated_without_overlap(
    make_user: MakeUser, client_for: ClientFor
) -> None:
    reader = make_user(roles=["security_analyst"])
    for _ in range(4):
        make_user()
    client = client_for(reader)

    first = client.get(USERS_URL, {"page_size": 3}).json()
    second = client.get(first["next"]).json()

    ids = [u["id"] for u in first["results"]] + [u["id"] for u in second["results"]]
    assert len(first["results"]) == 3
    assert len(ids) == len(set(ids)) == 5
    assert second["next"] is None


def test_user_list_filters(make_user: MakeUser, client_for: ClientFor) -> None:
    reader = make_user(roles=["security_analyst"])
    make_user(email="olga@corp.test", roles=["auditor"])
    make_user(email="pete@corp.test", is_active=False)
    client = client_for(reader)

    by_role = client.get(USERS_URL, {"role": "auditor"}).json()["results"]
    by_email = client.get(USERS_URL, {"email": "CORP.test"}).json()["results"]
    inactive = client.get(USERS_URL, {"is_active": "false"}).json()["results"]

    assert [u["email"] for u in by_role] == ["olga@corp.test"]
    assert {u["email"] for u in by_email} == {"olga@corp.test", "pete@corp.test"}
    assert [u["email"] for u in inactive] == ["pete@corp.test"]


def test_reading_another_user_needs_permission_not_just_a_valid_id(
    make_user: MakeUser, client_for: ClientFor
) -> None:
    victim = make_user()
    outsider = make_user(roles=["auditor"])

    response = client_for(outsider).get(f"{USERS_URL}{victim.pk}/")

    assert response.status_code == 403


def test_unknown_user_is_404(make_user: MakeUser, client_for: ClientFor) -> None:
    client = client_for(make_user(roles=["security_analyst"]))

    response = client.get(f"{USERS_URL}{uuid.uuid4()}/")

    assert response.status_code == 404
    assert response.json()["type"] == "urn:sentinel:problem:not-found"


# --------------------------------------------------------------------------------------
# Creating and updating
# --------------------------------------------------------------------------------------
def test_iam_manager_creates_users_with_normalized_email(
    make_user: MakeUser, client_for: ClientFor
) -> None:
    client = client_for(make_user(roles=["iam_manager"]))

    response = client.post(
        USERS_URL,
        {"email": "Quinn@Example.TEST", "full_name": "Quinn", "password": "Long-enough-pass-42"},
        format="json",
    )

    assert response.status_code == 201
    assert response.json()["email"] == "quinn@example.test"
    assert User.objects.get(email="quinn@example.test").check_password("Long-enough-pass-42")


def test_create_user_validation_and_conflicts(make_user: MakeUser, client_for: ClientFor) -> None:
    make_user(email="rita@example.test")
    client = client_for(make_user(roles=["iam_manager"]))

    duplicate = client.post(
        USERS_URL, {"email": "RITA@example.test", "password": "Long-enough-pass-42"}, format="json"
    )
    weak = client.post(USERS_URL, {"email": "new@example.test", "password": "short"}, format="json")
    escalation = client.post(
        USERS_URL,
        {"email": "x@example.test", "password": "Long-enough-pass-42", "is_superuser": True},
        format="json",
    )

    assert duplicate.status_code == 409
    assert weak.status_code == 400
    assert {e["field"] for e in weak.json()["errors"]} == {"password"}
    assert escalation.status_code == 400
    assert not User.objects.filter(email="x@example.test").exists()


def test_readers_cannot_create_users(make_user: MakeUser, client_for: ClientFor) -> None:
    response = client_for(make_user(roles=["security_analyst"])).post(
        USERS_URL, {"email": "s@example.test", "password": "Long-enough-pass-42"}, format="json"
    )

    assert response.status_code == 403


def test_users_cannot_deactivate_themselves(make_user: MakeUser, client_for: ClientFor) -> None:
    manager = make_user(roles=["iam_manager"])

    response = client_for(manager).patch(
        f"{USERS_URL}{manager.pk}/", {"is_active": False}, format="json"
    )

    assert response.status_code == 403


def test_managers_cannot_manage_more_privileged_users(
    make_user: MakeUser, client_for: ClientFor, admin_user: User, superuser: User
) -> None:
    client = client_for(make_user(roles=["iam_manager"]))

    for target in (admin_user, superuser):
        response = client.patch(f"{USERS_URL}{target.pk}/", {"is_active": False}, format="json")
        assert response.status_code == 403
        target.refresh_from_db()
        assert target.is_active


# --------------------------------------------------------------------------------------
# Role assignment and privilege escalation
# --------------------------------------------------------------------------------------
def test_admin_assigns_roles_idempotently(
    make_user: MakeUser, client_for: ClientFor, admin_user: User
) -> None:
    target = make_user()
    client = client_for(admin_user)

    first = client.post(_roles_url(target), {"role": "auditor"}, format="json")
    again = client.post(_roles_url(target), {"role": "auditor"}, format="json")

    assert (first.status_code, again.status_code) == (201, 200)
    assert first.json()["roles"] == ["auditor"]
    assignment = UserRole.objects.get(user=target)
    assert assignment.granted_by == admin_user


def test_role_managers_cannot_grant_permissions_they_lack(
    make_user: MakeUser, client_for: ClientFor
) -> None:
    target = make_user()
    client = client_for(make_user(roles=["iam_manager"]))

    response = client.post(_roles_url(target), {"role": "admin"}, format="json")

    assert response.status_code == 403
    assert "audit:read" in response.json()["detail"]
    assert not UserRole.objects.filter(user=target).exists()


def test_role_managers_cannot_assign_roles_to_themselves(
    make_user: MakeUser, client_for: ClientFor
) -> None:
    manager = make_user(roles=["iam_manager"])

    response = client_for(manager).post(_roles_url(manager), {"role": "iam_manager"}, format="json")

    assert response.status_code == 403


def test_role_managers_cannot_strip_roles_they_could_not_grant(
    make_user: MakeUser, client_for: ClientFor
) -> None:
    analyst = make_user(roles=["security_analyst"])
    client = client_for(make_user(roles=["iam_manager"]))

    response = client.delete(_roles_url(analyst, "security_analyst"))

    assert response.status_code == 403
    assert UserRole.objects.filter(user=analyst, role__name="security_analyst").exists()


def test_revoking_roles(make_user: MakeUser, client_for: ClientFor, admin_user: User) -> None:
    target = make_user(roles=["auditor"])
    client = client_for(admin_user)

    assert client.delete(_roles_url(target, "auditor")).status_code == 204
    assert client.delete(_roles_url(target, "auditor")).status_code == 404
    assert client.delete(_roles_url(target, "no-such-role")).status_code == 404
    assert not Role.objects.get(name="auditor").assignments.exists()


def test_assigning_requires_roles_manage(make_user: MakeUser, client_for: ClientFor) -> None:
    target = make_user()
    client = client_for(make_user(roles=["security_analyst"]))

    assert client.post(_roles_url(target), {"role": "auditor"}, format="json").status_code == 403
