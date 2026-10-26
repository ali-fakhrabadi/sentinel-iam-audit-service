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


class AllowedPrincipalTypes(BasePermission):
    """Per-method choice of credential type, for endpoints shared by people and machines::

    allowed_principals = {"GET": {"user", "service"}, "POST": {"service"}}
    """

    message = "This credential type cannot be used for this operation."

    def has_permission(self, request: Request, view: Any) -> bool:
        mapping: Mapping[str, set[str]] | None = getattr(view, "allowed_principals", None)
        if not mapping:
            return False
        method = _effective_method(request)
        allowed = mapping.get(method)
        if allowed is None:
            return not _implements(view, method)
        if isinstance(request.auth, APIKey):
            return "service" in allowed
        user = request.user
        return isinstance(user, User) and user.is_active and "user" in allowed


class HasRequiredPermissions(BasePermission):
    message = "You do not have permission to perform this action."

    def has_permission(self, request: Request, view: Any) -> bool:
        mapping: Mapping[str, Sequence[str]] | None = getattr(view, "required_permissions", None)
        if not mapping:
            return False
        method = _effective_method(request)
        required = mapping.get(method)
        if required is None:
            return not _implements(view, method)
        return set(required) <= principal_permission_codes(request)


def _effective_method(request: Request) -> str:
    return "GET" if request.method == "HEAD" else str(request.method)


def _implements(view: Any, method: str) -> bool:
    """Whether the view has a handler for ``method``.

    DRF checks permissions before it looks up the handler, so without this a request
    for a method the view does not offer (e.g. DELETE on an audit event) would get a
    misleading 403 instead of 405. Implemented methods missing from a mapping are
    still denied.
    """
    return callable(getattr(view, method.lower(), None))
