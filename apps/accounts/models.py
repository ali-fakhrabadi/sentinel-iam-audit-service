"""Identity, RBAC and machine-credential models.

Two permission systems coexist on purpose:
* Django's built-in ``is_staff`` / ``is_superuser`` / model permissions only govern
  the Django admin site.
* Every API endpoint is authorized through Sentinel RBAC: users receive permission
  codes through roles, service accounts through API key scopes.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, ClassVar

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.contrib.postgres.fields import ArrayField
from django.core.validators import RegexValidator
from django.db import models
from django.db.models import F, Q
from django.db.models.functions import Lower
from django.utils import timezone

PERMISSION_CODE_PATTERN = r"^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$"
SLUG_NAME_PATTERN = r"^[a-z][a-z0-9_-]{1,63}$"

_slug_name_validator = RegexValidator(
    SLUG_NAME_PATTERN,
    "Use 2-64 lowercase letters, digits, hyphens or underscores, starting with a letter.",
)


def normalize_email_address(email: str) -> str:
    """Emails are stored fully lowercased, so lookups and uniqueness are case-insensitive."""
    return email.strip().lower()


if TYPE_CHECKING:
    # The stubs make the manager generic; Django's runtime class is not subscriptable.
    _UserManagerBase = BaseUserManager["User"]
else:
    _UserManagerBase = BaseUserManager


class UserManager(_UserManagerBase):
    use_in_migrations = True

    def get_by_natural_key(self, username: str | None) -> User:
        return self.get(email=normalize_email_address(username or ""))

    def _create_user(self, email: str, password: str | None, **extra_fields: Any) -> User:
        if not email:
            raise ValueError("An email address is required.")
        user = self.model(email=normalize_email_address(email), **extra_fields)
        user.set_password(password)  # None stores an unusable password
        user.save(using=self._db)
        return user

    def create_user(self, email: str, password: str | None = None, **extra_fields: Any) -> User:
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(
        self, email: str, password: str | None = None, **extra_fields: Any
    ) -> User:
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        if extra_fields["is_staff"] is not True or extra_fields["is_superuser"] is not True:
            raise ValueError("A superuser must have is_staff=True and is_superuser=True.")
        return self._create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField("email address", max_length=254, unique=True)
    full_name = models.CharField(max_length=150, blank=True)
    is_active = models.BooleanField(
        default=True, help_text="Inactive users cannot log in and their tokens stop working."
    )
    is_staff = models.BooleanField(
        default=False, help_text="Can log in to the Django admin site. Does not grant API access."
    )
    date_joined = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    roles: models.ManyToManyField[Role, UserRole] = models.ManyToManyField(
        "Role",
        through="UserRole",
        through_fields=("user", "role"),
        related_name="users",
        blank=True,
    )

    objects = UserManager()

    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"
    REQUIRED_FIELDS: ClassVar[list[str]] = []

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            # Defense in depth: rows written outside the manager must still be lowercase.
            models.CheckConstraint(
                condition=Q(email=Lower("email")), name="accounts_user_email_lowercase"
            ),
        ]

    def clean(self) -> None:
        super().clean()
        self.email = normalize_email_address(self.email)

    def __str__(self) -> str:
        return self.email


class Permission(models.Model):
    """A capability such as ``audit:read``. The catalog is defined in ``catalog.py``."""

    code = models.CharField(
        max_length=64,
        unique=True,
        validators=[RegexValidator(PERMISSION_CODE_PATTERN, "Use the form resource:action.")],
    )
    description = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering: ClassVar[list[str]] = ["code"]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(
                condition=Q(code__regex=PERMISSION_CODE_PATTERN),
                name="accounts_permission_code_format",
            ),
        ]

    def __str__(self) -> str:
        return self.code


class Role(models.Model):
    name = models.CharField(max_length=64, unique=True, validators=[_slug_name_validator])
    description = models.CharField(max_length=255, blank=True)
    is_system = models.BooleanField(
        default=False, help_text="Built-in roles cannot be changed or deleted through the API."
    )
    permissions = models.ManyToManyField(Permission, related_name="roles", blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering: ClassVar[list[str]] = ["name"]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(
                condition=Q(name__regex=SLUG_NAME_PATTERN), name="accounts_role_name_format"
            ),
        ]

    def __str__(self) -> str:
        return self.name


class UserRole(models.Model):
    """A role granted to a user, with provenance for audits."""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="role_assignments")
    # PROTECT: a role cannot disappear while users still hold it.
    role = models.ForeignKey(Role, on_delete=models.PROTECT, related_name="assignments")
    granted_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    granted_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(fields=["user", "role"], name="accounts_userrole_unique"),
        ]

    def __str__(self) -> str:
        return f"{self.user_id} -> {self.role_id}"


class ServiceAccount(models.Model):
    """A non-human principal (CI job, log shipper, SIEM connector) that uses API keys.

    When an API key authenticates, DRF exposes its service account as
    ``request.user``; the attributes below make it behave like an authenticated
    principal without granting Django admin access.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=64, unique=True, validators=[_slug_name_validator])
    description = models.CharField(max_length=255, blank=True)
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    is_staff = False
    is_superuser = False

    class Meta:
        ordering: ClassVar[list[str]] = ["name"]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(
                condition=Q(name__regex=SLUG_NAME_PATTERN),
                name="accounts_serviceaccount_name_format",
            ),
        ]

    def __str__(self) -> str:
        return self.name

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def is_anonymous(self) -> bool:
        return False


class APIKey(models.Model):
    """A hashed machine credential. The raw key is shown once, at creation time.

    Format: ``sntl_<prefix>_<secret>``. The 8-character prefix is not secret and is
    used to find the row; only the SHA-256 digest of the full key is stored.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    service_account = models.ForeignKey(
        ServiceAccount, on_delete=models.CASCADE, related_name="api_keys"
    )
    name = models.CharField(max_length=64)
    prefix = models.CharField(max_length=8, unique=True, editable=False)
    key_hash = models.CharField(max_length=64, editable=False)
    scopes = ArrayField(models.CharField(max_length=64), default=list)
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "API key"
        indexes: ClassVar[list[models.Index]] = [
            models.Index(
                fields=["service_account", "-created_at"], name="accounts_apikey_sa_created"
            ),
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(
                condition=Q(prefix__regex=r"^[A-Za-z0-9]{8}$"), name="accounts_apikey_prefix_format"
            ),
            models.CheckConstraint(
                condition=Q(key_hash__regex=r"^[0-9a-f]{64}$"), name="accounts_apikey_hash_format"
            ),
            models.CheckConstraint(
                condition=Q(expires_at__gt=F("created_at")),
                name="accounts_apikey_expiry_after_creation",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.name} ({self.prefix})"

    def is_usable(self, at: datetime | None = None) -> bool:
        moment = at or timezone.now()
        return (
            self.revoked_at is None and self.expires_at > moment and self.service_account.is_active
        )
