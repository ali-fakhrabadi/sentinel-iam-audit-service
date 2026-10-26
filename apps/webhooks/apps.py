from __future__ import annotations

from django.apps import AppConfig


class WebhooksConfig(AppConfig):
    name = "apps.webhooks"
    label = "webhooks"
    verbose_name = "Webhooks"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        # Registers the system check that validates the secret encryption keys.
        from apps.webhooks import checks  # noqa: F401, PLC0415
