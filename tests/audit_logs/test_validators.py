from __future__ import annotations

from typing import Any

import pytest
from django.core.exceptions import ValidationError
from pytest_django import Settings

from apps.audit_logs.validators import validate_metadata


def test_realistic_metadata_is_accepted() -> None:
    metadata = {
        "mfa": False,
        "attempts": 3,
        "risk_score": 0.93,
        "geo": {"country": "DE", "asn": 3320},
        "tags": ["vpn", "new-device"],
        "note": None,
    }

    assert validate_metadata(metadata) is metadata


@pytest.mark.parametrize("value", [[1, 2], "text", 3, None])
def test_metadata_must_be_an_object(value: Any) -> None:
    with pytest.raises(ValidationError, match="JSON object"):
        validate_metadata(value)


@pytest.mark.parametrize(
    ("metadata", "fragment"),
    [
        ({"password": "hunter2"}, "credentials"),
        ({"Authorization": "x"}, "credentials"),
        ({"context": {"api_key": "x"}}, "credentials"),
        ({"refresh_token": "x"}, "credentials"),
        ({"note": "Bearer abcdefghijklmnop"}, "credential"),
        ({"jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"}, "credential"),
        ({"leaked": "sntl_AbCd1234_" + "x" * 43}, "credential"),
        ({"bad key": 1}, "key"),
        ({"k" * 65: 1}, "key"),
        ({"n": float("nan")}, "NaN"),
        ({"n": float("inf")}, "NaN"),
        ({"n": 2**60}, "integers"),
        ({"s": "x" * 1025}, "strings"),
        ({"items": list(range(51))}, "lists"),
    ],
)
def test_unsafe_or_unbounded_metadata_is_rejected(metadata: dict[str, Any], fragment: str) -> None:
    with pytest.raises(ValidationError, match=fragment):
        validate_metadata(metadata)


def test_nesting_depth_is_limited(settings: Settings) -> None:
    settings.AUDIT_METADATA_MAX_DEPTH = 3

    validate_metadata({"a": {"b": {"c": 1}}})
    with pytest.raises(ValidationError, match="nesting"):
        validate_metadata({"a": {"b": {"c": {"d": 1}}}})


def test_serialized_size_is_limited(settings: Settings) -> None:
    settings.AUDIT_METADATA_MAX_BYTES = 300

    with pytest.raises(ValidationError, match="bytes"):
        validate_metadata({"s": "x" * 400})


def test_total_key_count_is_limited() -> None:
    with pytest.raises(ValidationError, match="more than 100 keys"):
        validate_metadata({f"k{i}": i for i in range(101)})
