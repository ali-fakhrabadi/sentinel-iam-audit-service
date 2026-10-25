"""Request and response shapes for the accounts API.

Input and output serializers are separate classes. Inputs list only the fields a
caller may set, which rules out mass assignment (e.g. sending ``is_superuser``);
unknown fields are rejected instead of silently ignored.
"""

from __future__ import annotations

from typing import Any

from rest_framework import serializers

from apps.accounts import selectors
from apps.accounts.models import APIKey, Permission, Role, ServiceAccount, User


class StrictInputSerializer(serializers.Serializer):
    """Rejects fields that are not declared, so typos and privilege fields fail loudly."""

    def to_internal_value(self, data: Any) -> Any:
        if isinstance(data, dict):
            unknown = sorted(set(data) - set(self.fields))
            if unknown:
                raise serializers.ValidationError(
                    {name: ["This field is not allowed."] for name in unknown}
                )
        return super().to_internal_value(data)


# --------------------------------------------------------------------------------------
# Current user
# --------------------------------------------------------------------------------------
class MeSerializer(serializers.Serializer):
    """Everything a SPA needs to bootstrap auth state and role-based UI."""

    id = serializers.UUIDField()
    email = serializers.EmailField()
    full_name = serializers.CharField()
    is_superuser = serializers.BooleanField()
    date_joined = serializers.DateTimeField()
    last_login = serializers.DateTimeField(allow_null=True)
    roles = serializers.ListField(child=serializers.CharField(), help_text="Active role names")
    permissions = serializers.ListField(
        child=serializers.CharField(),
        help_text="Flattened, sorted permission codes, e.g. audit:read",
    )

    @staticmethod
    def build(user: User) -> dict[str, Any]:
        return {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "is_superuser": user.is_superuser,
            "date_joined": user.date_joined,
            "last_login": user.last_login,
            "roles": selectors.user_role_names(user),
            "permissions": sorted(selectors.user_permission_codes(user)),
        }


class ProfileUpdateSerializer(StrictInputSerializer):
    full_name = serializers.CharField(max_length=150, allow_blank=True)


class PasswordChangeSerializer(StrictInputSerializer):
    current_password = serializers.CharField(write_only=True, trim_whitespace=False)
    new_password = serializers.CharField(write_only=True, trim_whitespace=False, max_length=128)


# --------------------------------------------------------------------------------------
# Users
# --------------------------------------------------------------------------------------
class UserSerializer(serializers.ModelSerializer):
    roles: serializers.SlugRelatedField[Role] = serializers.SlugRelatedField(
        many=True, read_only=True, slug_field="name"
    )

    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "full_name",
            "is_active",
            "is_superuser",
            "date_joined",
            "last_login",
            "roles",
        )
        read_only_fields = fields


class UserCreateSerializer(StrictInputSerializer):
    email = serializers.EmailField(max_length=254)
    full_name = serializers.CharField(max_length=150, allow_blank=True, required=False, default="")
    password = serializers.CharField(write_only=True, trim_whitespace=False, max_length=128)


class UserUpdateSerializer(StrictInputSerializer):
    full_name = serializers.CharField(max_length=150, allow_blank=True, required=False)
    is_active = serializers.BooleanField(required=False)


class RoleAssignmentSerializer(StrictInputSerializer):
    role = serializers.SlugField(max_length=64, help_text="Role name, e.g. security_analyst")


# --------------------------------------------------------------------------------------
# Roles and permissions
# --------------------------------------------------------------------------------------
class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ("code", "description")
        read_only_fields = fields


class RoleSerializer(serializers.ModelSerializer):
    permissions: serializers.SlugRelatedField[Permission] = serializers.SlugRelatedField(
        many=True, read_only=True, slug_field="code"
    )

    class Meta:
        model = Role
        fields = ("name", "description", "is_system", "permissions", "created_at", "updated_at")
        read_only_fields = fields


class RoleCreateSerializer(StrictInputSerializer):
    name = serializers.SlugField(max_length=64)
    description = serializers.CharField(
        max_length=255, allow_blank=True, required=False, default=""
    )
    permissions = serializers.ListField(
        child=serializers.CharField(max_length=64), allow_empty=True, max_length=100
    )


class RoleUpdateSerializer(StrictInputSerializer):
    description = serializers.CharField(max_length=255, allow_blank=True, required=False)
    permissions = serializers.ListField(
        child=serializers.CharField(max_length=64), allow_empty=True, max_length=100, required=False
    )


# --------------------------------------------------------------------------------------
# Service accounts and API keys
# --------------------------------------------------------------------------------------
class ServiceAccountSerializer(serializers.ModelSerializer):
    active_key_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = ServiceAccount
        fields = (
            "id",
            "name",
            "description",
            "is_active",
            "active_key_count",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields


class ServiceAccountCreateSerializer(StrictInputSerializer):
    name = serializers.SlugField(max_length=64)
    description = serializers.CharField(
        max_length=255, allow_blank=True, required=False, default=""
    )


class ServiceAccountUpdateSerializer(StrictInputSerializer):
    description = serializers.CharField(max_length=255, allow_blank=True, required=False)
    is_active = serializers.BooleanField(required=False)


class APIKeySerializer(serializers.ModelSerializer):
    """Key metadata. Neither the raw key nor its hash is ever returned here."""

    is_active = serializers.SerializerMethodField()

    class Meta:
        model = APIKey
        fields: tuple[str, ...] = (
            "id",
            "name",
            "prefix",
            "scopes",
            "is_active",
            "created_at",
            "expires_at",
            "revoked_at",
            "last_used_at",
        )
        read_only_fields: tuple[str, ...] = fields

    def get_is_active(self, obj: APIKey) -> bool:
        return obj.revoked_at is None and obj.is_usable()


class APIKeyIssuedSerializer(APIKeySerializer):
    key = serializers.CharField(
        read_only=True,
        help_text="The raw API key. It is shown only in this response; store it now.",
    )

    class Meta(APIKeySerializer.Meta):
        fields = (*APIKeySerializer.Meta.fields, "key")
        read_only_fields = fields


class APIKeyCreateSerializer(StrictInputSerializer):
    name = serializers.CharField(max_length=64)
    scopes = serializers.ListField(
        child=serializers.CharField(max_length=64), allow_empty=False, max_length=50
    )
    expires_at = serializers.DateTimeField(
        required=False, help_text="Defaults to 90 days from now; at most 365 days."
    )


class APIKeyIntrospectionSerializer(serializers.Serializer):
    service_account_id = serializers.UUIDField()
    service_account_name = serializers.CharField()
    key_id = serializers.UUIDField()
    key_name = serializers.CharField()
    prefix = serializers.CharField()
    scopes = serializers.ListField(child=serializers.CharField())
    expires_at = serializers.DateTimeField()


class TokenPairSerializer(serializers.Serializer):
    """Response of the token endpoints (refresh tokens rotate on every refresh)."""

    access = serializers.CharField(help_text="Short-lived access token (Bearer)")
    refresh = serializers.CharField(help_text="Refresh token; single use when rotated")
