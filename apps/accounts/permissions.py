"""DRF permission classes implementing Sentinel RBAC.

Views declare what each HTTP method requires::

    required_permissions = {
        "GET": (PermissionCode.USERS_READ,),
        "POST": (PermissionCode.USERS_MANAGE,),
    }

A method missing from the mapping is denied (deny by default). Authentication only
establishes who the caller is; these classes decide what the caller may do.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from rest_framework.permissions import BasePermission
from rest_framework.request import Request

from apps.accounts import selectors
from apps.accounts.models import APIKey, User


def principal_permission_codes(request: Request) -> frozenset[str]:
    """Permission codes of the caller: API key scopes or the user's role grants."""
    if isinstance(request.auth, APIKey):
        return frozenset(request.auth.scopes)
    user = request.user
    if isinstance(user, User) and user.is_authenticated:
        return selectors.user_permission_codes(user)
    return frozenset()


class IsHumanUser(BasePermission):
    """Only interactive users (JWT), never service accounts."""

    message = "This endpoint requires a user access token."

    def has_permission(self, request: Request, view: Any) -> bool:
        user = request.user
        return isinstance(user, User) and user.is_authenticated and user.is_active


class IsServicePrincipal(BasePermission):
    """Only service accounts authenticated with an API key."""

    message = "This endpoint requires an API key."

    def has_permission(self, request: Request, view: Any) -> bool:
        return isinstance(request.auth, APIKey)


class HasRequiredPermissions(BasePermission):
    message = "You do not have permission to perform this action."

    def has_permission(self, request: Request, view: Any) -> bool:
        mapping: Mapping[str, Sequence[str]] | None = getattr(view, "required_permissions", None)
        if not mapping:
            return False
        method = "GET" if request.method == "HEAD" else str(request.method)
        required = mapping.get(method)
        if required is None:
            return False
        return set(required) <= principal_permission_codes(request)
