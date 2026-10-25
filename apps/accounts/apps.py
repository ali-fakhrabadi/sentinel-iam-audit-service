from __future__ import annotations

from django.apps import AppConfig


class AccountsConfig(AppConfig):
    name = "apps.accounts"
    label = "accounts"
    verbose_name = "Identity & access"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        # Registers the OpenAPI security scheme for API key authentication.
        from apps.accounts import schema  # noqa: F401, PLC0415
