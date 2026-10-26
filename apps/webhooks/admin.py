"""Operator views. Endpoints are created through the API, which returns the secret once."""

from __future__ import annotations

from typing import Any

from django.contrib import admin
from django.http import HttpRequest

from apps.webhooks.models import WebhookDelivery, WebhookEndpoint


@admin.register(WebhookEndpoint)
class WebhookEndpointAdmin(admin.ModelAdmin):
    list_display = ("name", "url", "is_active", "min_severity", "secret_rotated_at")
    list_filter = ("is_active", "min_severity")
    search_fields = ("name", "url")
    exclude = ("secret_ciphertext", "previous_secret_ciphertext")
    readonly_fields = (
        "previous_secret_expires_at",
        "secret_rotated_at",
        "created_by",
        "created_at",
        "updated_at",
    )

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False


@admin.register(WebhookDelivery)
class WebhookDeliveryAdmin(admin.ModelAdmin):
    list_display = ("id", "endpoint", "status", "attempt_count", "last_error", "next_attempt_at")
    list_filter = ("status",)
    readonly_fields = (
        "endpoint",
        "event",
        "status",
        "attempt_count",
        "next_attempt_at",
        "last_attempt_at",
        "last_status_code",
        "last_error",
        "created_at",
        "completed_at",
    )

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False
