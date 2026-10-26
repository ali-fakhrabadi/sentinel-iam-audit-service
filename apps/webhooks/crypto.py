"""Generation and at-rest encryption of webhook signing secrets.

Secrets must be recoverable to sign payloads, so they are encrypted rather than
hashed. ``WEBHOOK_SECRET_ENCRYPTION_KEYS`` holds Fernet keys (AES-128-CBC with
HMAC-SHA256); the first key encrypts, all keys decrypt, which allows key rotation:
add a new key in front, re-encrypt with ``rotate_ciphertext``, then drop the old one.
"""

from __future__ import annotations

import secrets
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

SECRET_PREFIX = "whsec_"  # noqa: S105 - a public marker, not a secret


class SecretUnavailableError(Exception):
    """The ciphertext cannot be decrypted with any configured key."""


@lru_cache(maxsize=4)
def _fernet(keys: tuple[str, ...]) -> MultiFernet:
    if not keys:
        raise ImproperlyConfigured("WEBHOOK_SECRET_ENCRYPTION_KEYS is not configured.")
    try:
        return MultiFernet([Fernet(key.encode()) for key in keys])
    except ValueError as exc:
        raise ImproperlyConfigured(
            "WEBHOOK_SECRET_ENCRYPTION_KEYS contains an invalid Fernet key."
        ) from exc


def _cipher() -> MultiFernet:
    return _fernet(tuple(settings.WEBHOOK_SECRET_ENCRYPTION_KEYS))


def generate_signing_secret() -> str:
    return f"{SECRET_PREFIX}{secrets.token_urlsafe(32)}"


def encrypt_secret(secret: str) -> str:
    return _cipher().encrypt(secret.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    try:
        return _cipher().decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise SecretUnavailableError(
            "Webhook secret cannot be decrypted with the configured keys"
        ) from exc


def rotate_ciphertext(ciphertext: str) -> str:
    """Re-encrypt with the current primary key (after adding a new encryption key)."""
    return _cipher().rotate(ciphertext.encode()).decode()
