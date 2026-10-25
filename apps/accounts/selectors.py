"""Read-side queries for accounts. Views and services read data only through here."""

from __future__ import annotations

import uuid

from django.db.models import Count, Prefetch, Q, QuerySet
from django.shortcuts import get_object_or_404

from apps.accounts.models import APIKey, Permission, Role, ServiceAccount, User


def user_permission_codes(user: User) -> frozenset[str]:
    """Flattened permission codes granted to ``user`` through its roles.

    Inactive users hold no permissions. Superusers hold the whole catalog so a
    fresh installation can be bootstrapped from ``createsuperuser``.
    """
    if not user.is_active:
        return frozenset()
    queryset = Permission.objects.all()
    if not user.is_superuser:
        queryset = queryset.filter(roles__assignments__user=user)
    return frozenset(queryset.values_list("code", flat=True).distinct())


def user_role_names(user: User) -> list[str]:
    return list(
        Role.objects.filter(assignments__user=user).order_by("name").values_list("name", flat=True)
    )


def role_permission_codes(role: Role) -> frozenset[str]:
    return frozenset(role.permissions.values_list("code", flat=True))


def user_list() -> QuerySet[User]:
    return User.objects.prefetch_related(
        Prefetch("roles", queryset=Role.objects.order_by("name"))
    ).order_by("-date_joined", "-id")


def user_get(user_id: uuid.UUID) -> User:
    user: User = get_object_or_404(user_list(), pk=user_id)
    return user


def role_list() -> QuerySet[Role]:
    return Role.objects.prefetch_related(
        Prefetch("permissions", queryset=Permission.objects.order_by("code"))
    ).order_by("name")


def role_get(name: str) -> Role:
    role: Role = get_object_or_404(role_list(), name=name)
    return role


def roles_by_name(names: list[str]) -> list[Role]:
    return list(Role.objects.filter(name__in=names))


def permission_list() -> QuerySet[Permission]:
    return Permission.objects.order_by("code")


def permissions_by_code(codes: set[str]) -> list[Permission]:
    return list(Permission.objects.filter(code__in=codes))


def service_account_list() -> QuerySet[ServiceAccount]:
    return ServiceAccount.objects.annotate(
        active_key_count=Count("api_keys", filter=Q(api_keys__revoked_at__isnull=True))
    ).order_by("name")


def service_account_get(service_account_id: uuid.UUID) -> ServiceAccount:
    service_account: ServiceAccount = get_object_or_404(
        service_account_list(), pk=service_account_id
    )
    return service_account


def api_key_list(service_account: ServiceAccount) -> QuerySet[APIKey]:
    return (
        APIKey.objects.filter(service_account=service_account)
        .select_related("service_account")
        .order_by("-created_at", "-id")
    )


def api_key_get(service_account: ServiceAccount, key_id: uuid.UUID) -> APIKey:
    """Scoped to the service account in the URL, so key IDs cannot be used across accounts."""
    api_key: APIKey = get_object_or_404(api_key_list(service_account), pk=key_id)
    return api_key


def api_key_for_authentication(prefix: str) -> APIKey | None:
    return APIKey.objects.select_related("service_account").filter(prefix=prefix).first()
