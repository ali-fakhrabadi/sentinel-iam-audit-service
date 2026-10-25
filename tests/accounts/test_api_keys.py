from __future__ import annotations

import hashlib
import re

import pytest

from apps.accounts.api_keys import generate_api_key, hash_api_key, parse_prefix, verify_api_key
from config.logging import redact_text


def test_generated_keys_have_the_documented_format() -> None:
    key = generate_api_key()

    assert re.fullmatch(r"sntl_[A-Za-z0-9]{8}_[A-Za-z0-9_-]{43}", key.raw)
    assert key.raw.split("_", 2)[1] == key.prefix
    assert key.key_hash == hashlib.sha256(key.raw.encode()).hexdigest()


def test_keys_are_unique_and_never_shown_in_repr() -> None:
    keys = [generate_api_key() for _ in range(50)]

    assert len({k.raw for k in keys}) == 50
    assert keys[0].raw not in repr(keys[0])


def test_parse_prefix_accepts_only_well_formed_keys() -> None:
    key = generate_api_key()
    assert parse_prefix(key.raw) == key.prefix


@pytest.mark.parametrize(
    "candidate",
    [
        "",
        "sntl_short_x",
        "sntl_Abcd1234_",
        "other_Abcd1234_" + "a" * 43,
        "sntl_Abcd1234_" + "a" * 42,
        "sntl_Abcd1234_" + "a" * 44,
        " sntl_Abcd1234_" + "a" * 43,
        "sntl_Abcd123!_" + "a" * 43,
    ],
)
def test_parse_prefix_rejects_malformed_input(candidate: str) -> None:
    assert parse_prefix(candidate) is None


def test_verification_detects_any_change() -> None:
    key = generate_api_key()
    assert verify_api_key(key.raw, key.key_hash)
    tampered = key.raw[:-1] + ("A" if key.raw[-1] != "A" else "B")
    assert not verify_api_key(tampered, key.key_hash)
    assert hash_api_key(tampered) != key.key_hash


def test_log_redaction_recognises_generated_keys() -> None:
    key = generate_api_key()
    assert key.raw not in redact_text(f"leaked {key.raw} here")
