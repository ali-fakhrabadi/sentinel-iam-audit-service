"""System check: fail ``manage.py check`` (and container start-up) on bad encryption keys."""

from __future__ import annotations

from typing import Any

from cryptography.fernet import Fernet
from django.conf import settings
from django.core.checks import CheckMessage, Error, register


@register()
def check_webhook_encryption_keys(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    keys: list[str] = settings.WEBHOOK_SECRET_ENCRYPTION_KEYS
    if not keys:
        return [
            Error(
                "WEBHOOK_SECRET_ENCRYPTION_KEYS is empty.",
                hint="Generate one with: python -c 'from cryptography.fernet import Fernet; "
                "print(Fernet.generate_key().decode())'",
                id="webhooks.E001",
            )
        ]
    errors: list[CheckMessage] = []
    for position, key in enumerate(keys):
        try:
            Fernet(key.encode())
        except ValueError:
            errors.append(
                Error(
                    f"WEBHOOK_SECRET_ENCRYPTION_KEYS entry #{position + 1} "
                    "is not a valid Fernet key.",
                    id="webhooks.E002",
                )
            )
    return errors
