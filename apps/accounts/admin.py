"""Django admin for operators. API keys are issued only through the API, because the
raw key must be shown exactly once to the caller who requested it."""

from __future__ import annotations

from typing import Any

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.contrib.auth.forms import BaseUserCreationForm, UserChangeForm
from django.db.models import QuerySet
from django.http import HttpRequest
from django.utils import timezone

from apps.accounts.models import APIKey, Permission, Role, ServiceAccount, User, UserRole


class SentinelUserCreationForm(BaseUserCreationForm):
    class Meta:
        model = User
        fields = ("email", "full_name")


class SentinelUserChangeForm(UserChangeForm):
    class Meta:
        model = User
        fields = ("email", "password", "full_name", "is_active", "is_staff", "is_superuser")


class UserRoleInline(admin.TabularInline):
    model = UserRole
    fk_name = "user"
    extra = 0
    autocomplete_fields = ("role",)
    readonly_fields = ("granted_by", "granted_at")


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    form = SentinelUserChangeForm
    add_form = SentinelUserCreationForm
    ordering = ("email",)
    list_display = ("email", "full_name", "is_active", "is_staff", "is_superuser", "date_joined")
    list_filter = ("is_active", "is_staff", "is_superuser")
    search_fields = ("email", "full_name")
    readonly_fields = ("date_joined", "last_login", "updated_at")
    inlines = (UserRoleInline,)
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Profile", {"fields": ("full_name",)}),
        ("Admin site access", {"fields": ("is_active", "is_staff", "is_superuser")}),
        ("Dates", {"fields": ("date_joined", "last_login", "updated_at")}),
    )
    add_fieldsets = (
        (None, {"classes": ("wide",), "fields": ("email", "full_name", "password1", "password2")}),
    )
    filter_horizontal = ()


@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    """The catalog is managed by migrations, so it is read-only here."""

    list_display = ("code", "description")
    search_fields = ("code",)

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False

    def has_delete_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ("name", "is_system", "description", "updated_at")
    search_fields = ("name",)
    filter_horizontal = ("permissions",)
    readonly_fields = ("is_system", "created_at", "updated_at")

    def has_delete_permission(self, request: HttpRequest, obj: Role | None = None) -> bool:
        return obj is None or not obj.is_system


class APIKeyInline(admin.TabularInline):
    model = APIKey
    extra = 0
    can_delete = False
    fields = ("name", "prefix", "scopes", "created_at", "expires_at", "revoked_at", "last_used_at")
    readonly_fields = fields

    def has_add_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False


@admin.register(ServiceAccount)
class ServiceAccountAdmin(admin.ModelAdmin):
    list_display = ("name", "is_active", "description", "created_at")
    list_filter = ("is_active",)
    search_fields = ("name",)
    readonly_fields = ("created_by", "created_at", "updated_at")
    inlines = (APIKeyInline,)


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = ("prefix", "name", "service_account", "expires_at", "revoked_at", "last_used_at")
    list_filter = ("revoked_at",)
    search_fields = ("prefix", "name", "service_account__name")
    readonly_fields = (
        "service_account",
        "name",
        "prefix",
        "scopes",
        "created_by",
        "created_at",
        "expires_at",
        "revoked_at",
        "revoked_by",
        "last_used_at",
    )
    exclude = ("key_hash",)
    actions = ["revoke_selected"]

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    @admin.action(description="Revoke selected API keys")
    def revoke_selected(self, request: HttpRequest, queryset: QuerySet[APIKey]) -> None:
        user = request.user if isinstance(request.user, User) else None
        updated = queryset.filter(revoked_at__isnull=True).update(
            revoked_at=timezone.now(), revoked_by=user
        )
        self.message_user(request, f"Revoked {updated} API key(s).")
