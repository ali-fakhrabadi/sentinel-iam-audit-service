from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta

import pytest
from django.db import IntegrityError, connection, transaction
from django.utils import timezone

import config.settings as project_settings
from apps.accounts.catalog import PERMISSION_DESCRIPTIONS, SYSTEM_ROLES
from apps.accounts.models import APIKey, Permission, Role, ServiceAccount, User
from tests.factories import create_service_account

pytestmark = pytest.mark.django_db


def test_catalog_in_database_matches_code() -> None:
    stored = dict(Permission.objects.values_list("code", "description"))
    assert stored == {str(code): text for code, text in PERMISSION_DESCRIPTIONS.items()}

    for name, (description, codes) in SYSTEM_ROLES.items():
        role = Role.objects.get(name=name)
        assert role.is_system is True
        assert role.description == description
        assert set(role.permissions.values_list("code", flat=True)) == {str(c) for c in codes}


def test_emails_are_normalized_and_lookups_are_case_insensitive() -> None:
    user = User.objects.create_user("  Alice@Example.TEST ", "S3cure-Passphrase!")

    assert user.email == "alice@example.test"
    assert User.objects.get_by_natural_key("ALICE@example.test") == user


def test_database_rejects_mixed_case_emails() -> None:
    user = User.objects.create_user("bob@example.test", None)

    with pytest.raises(IntegrityError), transaction.atomic(), connection.cursor() as cursor:
        cursor.execute(
            "UPDATE accounts_user SET email = 'Bob@Example.test' WHERE id = %s", [user.pk]
        )


def test_superuser_requires_admin_flags() -> None:
    root = User.objects.create_superuser("root@example.test", "Root-Password-12345")
    assert root.is_staff
    assert root.is_superuser
    with pytest.raises(ValueError, match="is_superuser"):
        User.objects.create_superuser("x@example.test", "pw-123456789012", is_superuser=False)


def test_users_without_password_cannot_log_in() -> None:
    user = User.objects.create_user("nopass@example.test")
    assert not user.has_usable_password()


@pytest.mark.parametrize("code", ["Audit:Read", "audit", "audit:read:extra", ":read"])
def test_database_enforces_permission_code_format(code: str) -> None:
    with pytest.raises(IntegrityError), transaction.atomic():
        Permission.objects.create(code=code, description="x")


def test_database_enforces_role_name_format() -> None:
    with pytest.raises(IntegrityError), transaction.atomic():
        Role.objects.create(name="Not Valid")


def test_role_in_use_cannot_be_deleted_at_database_level(
    make_user: Callable[..., User],
) -> None:
    make_user(roles=["auditor"])

    with pytest.raises(Exception, match="protected"):
        Role.objects.get(name="auditor").delete()


def _key(**overrides: object) -> APIKey:
    fields: dict[str, object] = {
        "service_account": create_service_account(),
        "name": "k",
        "prefix": "Abcd1234",
        "key_hash": "a" * 64,
        "scopes": ["audit:write"],
        "expires_at": timezone.now() + timedelta(days=1),
    }
    fields.update(overrides)
    return APIKey.objects.create(**fields)


@pytest.mark.parametrize(
    "overrides",
    [
        {"prefix": "short"},
        {"prefix": "bad-pref"},
        {"key_hash": "not-a-hash"},
        {"expires_at": timezone.now() - timedelta(days=1)},
    ],
)
def test_database_enforces_api_key_invariants(overrides: dict[str, object]) -> None:
    with pytest.raises(IntegrityError), transaction.atomic():
        _key(**overrides)


def test_api_key_usability() -> None:
    key = _key()
    assert key.is_usable()
    assert not key.is_usable(at=key.expires_at)

    key.revoked_at = timezone.now()
    assert not key.is_usable()

    key.revoked_at = None
    key.service_account.is_active = False
    assert not key.is_usable()


def test_service_accounts_behave_as_authenticated_principals() -> None:
    account: ServiceAccount = create_service_account()
    assert account.is_authenticated is True
    assert account.is_anonymous is False
    assert account.is_staff is False


def test_production_password_hasher_is_argon2() -> None:
    # Tests switch to MD5 for speed; the shipped configuration must stay Argon2.
    assert project_settings.PASSWORD_HASHERS[0].endswith("Argon2PasswordHasher")
