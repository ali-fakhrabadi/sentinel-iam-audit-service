"""Read-only admin views; the database rejects edits to audit events anyway."""

from __future__ import annotations

from typing import Any

from django.contrib import admin
from django.http import HttpRequest

from apps.audit_logs.models import AuditEvent, OutboxMessage


class _ReadOnlyAdmin(admin.ModelAdmin):
    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False

    def has_delete_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False


@admin.register(AuditEvent)
class AuditEventAdmin(_ReadOnlyAdmin):
    list_display = ("created_at", "severity", "action", "resource_type", "resource_id", "actor_id")
    list_filter = ("severity",)
    search_fields = ("action", "resource_type", "resource_id", "actor_id")
    date_hierarchy = "created_at"
    show_full_result_count = False  # COUNT(*) on a large audit table is expensive


@admin.register(OutboxMessage)
class OutboxMessageAdmin(_ReadOnlyAdmin):
    list_display = ("id", "topic", "status", "attempts", "created_at", "dispatched_at")
    list_filter = ("status",)
