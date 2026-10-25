"""Write-side business operations for identities, roles and machine credentials.

Privilege-escalation rule, applied to every operation that touches privileges:
an actor may only grant, revoke or manage permissions it holds itself (superusers
excepted). Holding ``roles:manage`` therefore never lets someone hand out ``admin``.

Services raise Django exceptions (``ValidationError``, ``PermissionDenied``,
``Http404``) or ``Conflict``; the API layer renders them as RFC 7807 problems.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import NoReturn

from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import IntegrityError, transaction
from django.http import Http404
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken

from apps.accounts import selectors
from apps.accounts.api_keys import generate_api_key, hash_api_key, parse_prefix, verify_api_key
from apps.accounts.models import (
    APIKey,
    Permission,
    Role,
    ServiceAccount,
    User,
    UserRole,
    normalize_email_address,
)
from config.exceptions import Conflict

logger = logging.getLogger("sentinel.accounts")

_KEY_ISSUE_ATTEMPTS = 3


# --------------------------------------------------------------------------------------
# Authorization guards
# --------------------------------------------------------------------------------------
def _ensure_holds(actor: User, codes: Iterable[str], *, action: str) -> None:
    if actor.is_superuser:
        return
    missing = set(codes) - selectors.user_permission_codes(actor)
    if missing:
        raise PermissionDenied(
            f"You cannot {action}: it requires permissions you do not hold "
            f"({', '.join(sorted(missing))})."
        )


def _ensure_can_manage_user(actor: User, target: User) -> None:
    if target.is_superuser and not actor.is_superuser:
        raise PermissionDenied("Only superusers can manage superuser accounts.")
    _ensure_holds(actor, selectors.user_permission_codes(target), action="manage this user")


def _resolve_permissions(codes: Iterable[str], *, field: str) -> list[Permission]:
    requested = set(codes)
    permissions = selectors.permissions_by_code(requested)
    unknown = requested - {permission.code for permission in permissions}
    if unknown:
        raise ValidationError(
            {field: [f"Unknown permission code: {code}." for code in sorted(unknown)]}
        )
    return permissions


def _validate_new_password(password: str, user: User, *, field: str) -> None:
    try:
        validate_password(password, user=user)
    except ValidationError as exc:
        raise ValidationError({field: exc.messages}) from exc


def _revoke_refresh_tokens(user: User) -> None:
    """Blacklist every outstanding refresh token of ``user`` (sign out everywhere)."""
    outstanding = OutstandingToken.objects.filter(user=user, blacklistedtoken__isnull=True)
    BlacklistedToken.objects.bulk_create(
        [BlacklistedToken(token=token) for token in outstanding], ignore_conflicts=True
    )


# --------------------------------------------------------------------------------------
# Users
# --------------------------------------------------------------------------------------
def user_create(*, actor: User, email: str, password: str, full_name: str = "") -> User:
    user = User(email=normalize_email_address(email), full_name=full_name)
    user.full_clean(exclude=["password"], validate_unique=False)
    if User.objects.filter(email=user.email).exists():
        raise Conflict("A user with this email address already exists.")
    _validate_new_password(password, user, field="password")
    user.set_password(password)
    try:
        with transaction.atomic():
            user.save()
    except IntegrityError as exc:  # concurrent registration of the same email
        raise Conflict("A user with this email address already exists.") from exc
    logger.info("User created", extra={"target_user_id": str(user.pk), "actor_id": str(actor.pk)})
    return user


@transaction.atomic
def user_update(
    *,
    actor: User,
    user: User,
    full_name: str | None = None,
    is_active: bool | None = None,
) -> User:
    if user.pk == actor.pk and is_active is False:
        raise PermissionDenied("You cannot deactivate your own account.")
    if user.pk != actor.pk:
        _ensure_can_manage_user(actor, user)

    if full_name is not None:
        user.full_name = full_name
    if is_active is not None:
        user.is_active = is_active
    user.full_clean(exclude=["password"], validate_unique=False)
    user.save(update_fields=["full_name", "is_active", "updated_at"])
    if is_active is False:
        _revoke_refresh_tokens(user)
    logger.info(
        "User updated",
        extra={
            "target_user_id": str(user.pk),
            "actor_id": str(actor.pk),
            "is_active": user.is_active,
        },
    )
    return user


def profile_update(*, user: User, full_name: str) -> User:
    """Self-service profile change. Only non-privileged fields are accepted."""
    user.full_name = full_name
    user.full_clean(exclude=["password"], validate_unique=False)
    user.save(update_fields=["full_name", "updated_at"])
    return user


@transaction.atomic
def password_change(*, user: User, current_password: str, new_password: str) -> None:
    """Change the password and sign the user out of every session.

    Access tokens carry a hash of the password (SimpleJWT CHECK_REVOKE_TOKEN), so
    they stop working immediately; refresh tokens are blacklisted.
    """
    if not user.check_password(current_password):
        raise ValidationError({"current_password": ["The current password is incorrect."]})
    _validate_new_password(new_password, user, field="new_password")
    user.set_password(new_password)
    user.save(update_fields=["password", "updated_at"])
    _revoke_refresh_tokens(user)
    logger.info("Password changed", extra={"target_user_id": str(user.pk)})


# --------------------------------------------------------------------------------------
# Roles
# --------------------------------------------------------------------------------------
def role_assign(*, actor: User, user: User, role: Role) -> tuple[UserRole, bool]:
    """Grant ``role`` to ``user``. Idempotent: returns ``(assignment, created)``."""
    if user.pk == actor.pk:
        raise PermissionDenied("You cannot change your own role assignments.")
    _ensure_can_manage_user(actor, user)
    _ensure_holds(actor, selectors.role_permission_codes(role), action="assign this role")
    assignment, created = UserRole.objects.get_or_create(
        user=user, role=role, defaults={"granted_by": actor}
    )
    if created:
        logger.info(
            "Role assigned",
            extra={"target_user_id": str(user.pk), "role": role.name, "actor_id": str(actor.pk)},
        )
    return assignment, created


def role_revoke(*, actor: User, user: User, role: Role) -> None:
    if user.pk == actor.pk:
        raise PermissionDenied("You cannot change your own role assignments.")
    _ensure_can_manage_user(actor, user)
    _ensure_holds(actor, selectors.role_permission_codes(role), action="revoke this role")
    deleted, _ = UserRole.objects.filter(user=user, role=role).delete()
    if not deleted:
        raise Http404("The user does not hold this role.")
    logger.info(
        "Role revoked",
        extra={"target_user_id": str(user.pk), "role": role.name, "actor_id": str(actor.pk)},
    )


@transaction.atomic
def role_create(
    *, actor: User, name: str, description: str, permission_codes: Iterable[str]
) -> Role:
    codes = set(permission_codes)
    permissions = _resolve_permissions(codes, field="permissions")
    _ensure_holds(actor, codes, action="create a role with these permissions")
    role = Role(name=name, description=description)
    role.full_clean(validate_unique=False)
    if Role.objects.filter(name=name).exists():
        raise Conflict("A role with this name already exists.")
    role.save()
    role.permissions.set(permissions)
    logger.info("Role created", extra={"role": role.name, "actor_id": str(actor.pk)})
    return role


@transaction.atomic
def role_update(
    *,
    actor: User,
    role: Role,
    description: str | None = None,
    permission_codes: Iterable[str] | None = None,
) -> Role:
    if role.is_system:
        raise PermissionDenied("Built-in roles cannot be modified.")
    if description is not None:
        role.description = description
        role.full_clean(validate_unique=False)
        role.save(update_fields=["description", "updated_at"])
    if permission_codes is not None:
        codes = set(permission_codes)
        permissions = _resolve_permissions(codes, field="permissions")
        # Changing a role changes every holder, so the actor must hold both the
        # permissions being added and the ones being taken away.
        _ensure_holds(
            actor, codes | selectors.role_permission_codes(role), action="change this role"
        )
        role.permissions.set(permissions)
        role.save(update_fields=["updated_at"])
    logger.info("Role updated", extra={"role": role.name, "actor_id": str(actor.pk)})
    return role


@transaction.atomic
def role_delete(*, actor: User, role: Role) -> None:
    if role.is_system:
        raise PermissionDenied("Built-in roles cannot be deleted.")
    _ensure_holds(actor, selectors.role_permission_codes(role), action="delete this role")
    if role.assignments.exists():
        raise Conflict("The role is still assigned to users; revoke it before deleting.")
    name = role.name
    role.delete()
    logger.info("Role deleted", extra={"role": name, "actor_id": str(actor.pk)})


# --------------------------------------------------------------------------------------
# Service accounts and API keys
# --------------------------------------------------------------------------------------
def service_account_create(*, actor: User, name: str, description: str = "") -> ServiceAccount:
    service_account = ServiceAccount(name=name, description=description, created_by=actor)
    service_account.full_clean(validate_unique=False)
    if ServiceAccount.objects.filter(name=name).exists():
        raise Conflict("A service account with this name already exists.")
    service_account.save()
    logger.info(
        "Service account created",
        extra={"service_account_id": str(service_account.pk), "actor_id": str(actor.pk)},
    )
    return service_account


def service_account_update(
    *,
    actor: User,
    service_account: ServiceAccount,
    description: str | None = None,
    is_active: bool | None = None,
) -> ServiceAccount:
    if description is not None:
        service_account.description = description
    if is_active is not None:
        service_account.is_active = is_active
    service_account.full_clean(validate_unique=False)
    service_account.save(update_fields=["description", "is_active", "updated_at"])
    logger.info(
        "Service account updated",
        extra={
            "service_account_id": str(service_account.pk),
            "actor_id": str(actor.pk),
            "is_active": service_account.is_active,
        },
    )
    return service_account


@dataclass(frozen=True, slots=True)
class IssuedAPIKey:
    api_key: APIKey
    raw_key: str

    def __repr__(self) -> str:
        return f"IssuedAPIKey(api_key={self.api_key!r}, raw_key=<redacted>)"


def api_key_issue(
    *,
    actor: User,
    service_account: ServiceAccount,
    name: str,
    scopes: Iterable[str],
    expires_at: datetime | None = None,
) -> IssuedAPIKey:
    """Create a key and return it together with the raw secret (shown only once)."""
    if not service_account.is_active:
        raise ValidationError("Inactive service accounts cannot receive new API keys.")
    requested = set(scopes)
    if not requested:
        raise ValidationError({"scopes": ["Grant at least one scope (least privilege)."]})
    _resolve_permissions(requested, field="scopes")
    _ensure_holds(actor, requested, action="issue a key with these scopes")

    now = timezone.now()
    latest_allowed = now + timedelta(days=settings.API_KEY_MAX_LIFETIME_DAYS)
    expiry = expires_at or now + timedelta(days=settings.API_KEY_DEFAULT_LIFETIME_DAYS)
    if expiry <= now:
        raise ValidationError({"expires_at": ["The expiry must be in the future."]})
    if expiry > latest_allowed:
        raise ValidationError(
            {"expires_at": [f"Keys can live at most {settings.API_KEY_MAX_LIFETIME_DAYS} days."]}
        )

    for attempt in range(1, _KEY_ISSUE_ATTEMPTS + 1):
        generated = generate_api_key()
        try:
            with transaction.atomic():
                api_key = APIKey.objects.create(
                    service_account=service_account,
                    name=name,
                    prefix=generated.prefix,
                    key_hash=generated.key_hash,
                    scopes=sorted(requested),
                    created_by=actor,
                    created_at=now,
                    expires_at=expiry,
                )
        except IntegrityError:  # prefix collision (62^8 space); retry with a new key
            if attempt == _KEY_ISSUE_ATTEMPTS:
                raise
            continue
        logger.info(
            "API key issued",
            extra={
                "key_id": str(api_key.pk),
                "key_prefix": api_key.prefix,
                "service_account_id": str(service_account.pk),
                "scopes": api_key.scopes,
                "actor_id": str(actor.pk),
            },
        )
        return IssuedAPIKey(api_key=api_key, raw_key=generated.raw)
    raise AssertionError("unreachable")  # pragma: no cover


def api_key_revoke(*, actor: User, api_key: APIKey) -> APIKey:
    """Revoke a key. Idempotent: revoking a revoked key keeps the original timestamp."""
    if api_key.revoked_at is None:
        api_key.revoked_at = timezone.now()
        api_key.revoked_by = actor
        api_key.save(update_fields=["revoked_at", "revoked_by"])
        logger.info(
            "API key revoked",
            extra={
                "key_id": str(api_key.pk),
                "key_prefix": api_key.prefix,
                "actor_id": str(actor.pk),
            },
        )
    return api_key


def _reject_api_key(reason: str, prefix: str | None) -> NoReturn:
    # One generic message for every failure, so callers cannot probe which keys exist.
    logger.info("API key rejected", extra={"reason": reason, "key_prefix": prefix})
    raise AuthenticationFailed("Invalid API key.")


def api_key_authenticate(raw_key: str) -> APIKey:
    """Validate a presented key and return it with its service account loaded."""
    prefix = parse_prefix(raw_key)
    if prefix is None:
        _reject_api_key("malformed", None)
    api_key = selectors.api_key_for_authentication(prefix)
    if api_key is None:
        hash_api_key(raw_key)  # same work as a real check, so timing does not reveal prefixes
        _reject_api_key("unknown_prefix", prefix)
    if not verify_api_key(raw_key, api_key.key_hash):
        _reject_api_key("hash_mismatch", prefix)
    now = timezone.now()
    if api_key.revoked_at is not None:
        _reject_api_key("revoked", prefix)
    if api_key.expires_at <= now:
        _reject_api_key("expired", prefix)
    if not api_key.service_account.is_active:
        _reject_api_key("service_account_inactive", prefix)
    _record_api_key_use(api_key, now)
    return api_key


def _record_api_key_use(api_key: APIKey, now: datetime) -> None:
    """Update ``last_used_at`` at most once per interval to avoid a write per request."""
    interval = timedelta(seconds=settings.API_KEY_LAST_USED_UPDATE_SECONDS)
    if api_key.last_used_at is None or now - api_key.last_used_at >= interval:
        APIKey.objects.filter(pk=api_key.pk).update(last_used_at=now)
        api_key.last_used_at = now
