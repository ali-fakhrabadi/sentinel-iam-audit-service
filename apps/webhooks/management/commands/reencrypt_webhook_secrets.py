"""Re-encrypt stored webhook signing secrets with the current primary Fernet key.

Encryption-key rotation:
1. prepend a new key to WEBHOOK_SECRET_ENCRYPTION_KEYS and deploy (old key still decrypts);
2. run ``python manage.py reencrypt_webhook_secrets``;
3. remove the old key and deploy again.
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand
from django.db import transaction

from apps.webhooks.crypto import rotate_ciphertext
from apps.webhooks.models import WebhookEndpoint


class Command(BaseCommand):
    help = "Re-encrypt webhook secrets with the first key in WEBHOOK_SECRET_ENCRYPTION_KEYS."

    def handle(self, *args: Any, **options: Any) -> None:
        count = 0
        with transaction.atomic():
            for endpoint in WebhookEndpoint.objects.select_for_update().order_by("pk"):
                endpoint.secret_ciphertext = rotate_ciphertext(endpoint.secret_ciphertext)
                if endpoint.previous_secret_ciphertext:
                    endpoint.previous_secret_ciphertext = rotate_ciphertext(
                        endpoint.previous_secret_ciphertext
                    )
                endpoint.save(update_fields=["secret_ciphertext", "previous_secret_ciphertext"])
                count += 1
        self.stdout.write(f"Re-encrypted the secrets of {count} webhook endpoint(s).")
