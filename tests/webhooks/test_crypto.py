from __future__ import annotations

import pytest
from cryptography.fernet import Fernet
from pytest_django import Settings

from apps.webhooks.checks import check_webhook_encryption_keys
from apps.webhooks.crypto import (
    SecretUnavailableError,
    decrypt_secret,
    encrypt_secret,
    generate_signing_secret,
    rotate_ciphertext,
)
from config.logging import redact_text


def test_secrets_are_encrypted_and_recoverable() -> None:
    secret = generate_signing_secret()

    ciphertext = encrypt_secret(secret)

    assert secret not in ciphertext
    assert decrypt_secret(ciphertext) == secret


def test_generated_secrets_are_unique_prefixed_and_redacted_in_logs() -> None:
    secrets = {generate_signing_secret() for _ in range(20)}

    assert len(secrets) == 20
    assert all(s.startswith("whsec_") for s in secrets)
    sample = next(iter(secrets))
    assert sample not in redact_text(f"secret={sample}")


def test_encryption_keys_can_be_rotated(settings: Settings) -> None:
    old_key, new_key = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    settings.WEBHOOK_SECRET_ENCRYPTION_KEYS = [old_key]
    ciphertext = encrypt_secret("whsec_rotate-me")

    settings.WEBHOOK_SECRET_ENCRYPTION_KEYS = [new_key, old_key]
    assert decrypt_secret(ciphertext) == "whsec_rotate-me"
    rotated = rotate_ciphertext(ciphertext)

    settings.WEBHOOK_SECRET_ENCRYPTION_KEYS = [new_key]
    assert decrypt_secret(rotated) == "whsec_rotate-me"
    with pytest.raises(SecretUnavailableError):
        decrypt_secret(ciphertext)


@pytest.mark.parametrize(
    ("keys", "codes"),
    [
        ([], ["webhooks.E001"]),
        (["not-a-key"], ["webhooks.E002"]),
        ([Fernet.generate_key().decode()], []),
    ],
)
def test_system_check_validates_encryption_keys(
    settings: Settings, keys: list[str], codes: list[str]
) -> None:
    settings.WEBHOOK_SECRET_ENCRYPTION_KEYS = keys

    assert [message.id for message in check_webhook_encryption_keys(None)] == codes
