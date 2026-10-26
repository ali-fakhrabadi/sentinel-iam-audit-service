"""Unit tests for the RBAC permission classes (deny-by-default behavior)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Any

import pytest
from django.contrib.auth.models import AnonymousUser
from django.utils import timezone
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory

from apps.accounts.models import APIKey, ServiceAccount, User
from apps.accounts.permissions import (
    HasRequiredPermissions,
    IsHumanUser,
    IsServicePrincipal,
    principal_permission_codes,
)


class _View:
    """A view offering GET, POST and DELETE, but only mapping GET and POST."""

    required_permissions = {"GET": ("audit:read",), "POST": ("audit:write",)}

    def get(self) -> None: ...

    def post(self) -> None: ...

    def delete(self) -> None: ...


class _ReadOnlyView:
    required_permissions = {"GET": ("audit:read",)}

    def get(self) -> None: ...


def _request(method: str = "GET", *, user: Any = None, auth: Any = None) -> Request:
    raw = APIRequestFactory().generic(method, "/resource/")
    request = Request(raw)
    request.user = user if user is not None else AnonymousUser()
    request.auth = auth
    return request


def _api_key(scopes: list[str]) -> APIKey:
    account = ServiceAccount(name="unit-test")
    return APIKey(
        service_account=account,
        name="k",
        prefix="Abcd1234",
        key_hash="0" * 64,
        scopes=scopes,
        expires_at=timezone.now() + timedelta(days=1),
    )


def test_views_without_a_mapping_deny_everything() -> None:
    assert (
        HasRequiredPermissions().has_permission(_request(auth=_api_key(["audit:read"])), object())
        is False
    )


def test_methods_missing_from_the_mapping_are_denied() -> None:
    request = _request("DELETE", auth=_api_key(["audit:read", "audit:write"]))
    assert HasRequiredPermissions().has_permission(request, _View()) is False


def test_methods_the_view_does_not_implement_fall_through_to_405() -> None:
    # Permission checks run before handler lookup; letting them pass for methods the
    # view lacks makes DRF answer 405 instead of a misleading 403.
    request = _request("PUT", auth=_api_key([]))
    assert HasRequiredPermissions().has_permission(request, _ReadOnlyView()) is True


def test_head_is_authorized_like_get() -> None:
    assert HasRequiredPermissions().has_permission(
        _request("HEAD", auth=_api_key(["audit:read"])), _View()
    )


@pytest.mark.parametrize(
    ("method", "scopes", "allowed"),
    [
        ("GET", ["audit:read"], True),
        ("GET", ["audit:write"], False),
        ("POST", ["audit:write"], True),
        ("POST", [], False),
    ],
)
def test_api_key_scopes_drive_authorization(method: str, scopes: list[str], allowed: bool) -> None:
    request = _request(method, auth=_api_key(scopes))
    assert HasRequiredPermissions().has_permission(request, _View()) is allowed


def test_anonymous_callers_hold_no_permissions() -> None:
    request = _request()
    assert principal_permission_codes(request) == frozenset()
    assert HasRequiredPermissions().has_permission(request, _View()) is False


@pytest.mark.django_db
def test_users_are_authorized_through_their_roles(make_user: Callable[..., User]) -> None:
    auditor = make_user(roles=["auditor"])

    assert HasRequiredPermissions().has_permission(_request(user=auditor), _View()) is True
    assert HasRequiredPermissions().has_permission(_request("POST", user=auditor), _View()) is False


@pytest.mark.django_db
def test_principal_type_guards(make_user: Callable[..., User]) -> None:
    user = make_user()
    key = _api_key(["audit:read"])

    assert IsHumanUser().has_permission(_request(user=user), None)
    assert not IsHumanUser().has_permission(_request(user=key.service_account, auth=key), None)
    assert IsServicePrincipal().has_permission(_request(user=key.service_account, auth=key), None)
    assert not IsServicePrincipal().has_permission(_request(user=user), None)


@pytest.mark.django_db
def test_inactive_users_hold_no_permissions(make_user: Callable[..., User]) -> None:
    user = make_user(roles=["admin"], is_active=False)

    assert principal_permission_codes(_request(user=user)) == frozenset()
    assert not IsHumanUser().has_permission(_request(user=user), None)
