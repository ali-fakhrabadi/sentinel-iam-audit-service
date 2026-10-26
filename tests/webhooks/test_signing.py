from __future__ import annotations

import hashlib
import hmac
import re

import pytest

from apps.webhooks.signing import (
    canonical_body,
    compute_signature,
    signature_header,
    verify_signature,
)

SECRET = "whsec_test-secret-value-0123456789"
OLD_SECRET = "whsec_previous-secret-value-98765"
EVENT_ID = "6f1c2c1e-7a0e-4a77-9a0d-6a3e6f5f0b11"
TIMESTAMP = 1_790_000_000


def test_canonical_body_is_deterministic_utf8_json() -> None:
    body = canonical_body({"b": 1, "a": {"d": 2, "c": "é"}})

    assert body == '{"a":{"c":"é","d":2},"b":1}'.encode()
    assert canonical_body({"a": {"c": "é", "d": 2}, "b": 1}) == body


def test_signature_matches_the_documented_construction() -> None:
    body = b'{"x":1}'
    expected = hmac.new(
        SECRET.encode(), f"{TIMESTAMP}.{EVENT_ID}.".encode() + body, hashlib.sha256
    ).hexdigest()

    assert compute_signature(SECRET, TIMESTAMP, EVENT_ID, body) == expected


def test_header_format_lists_one_signature_per_active_secret() -> None:
    header = signature_header([SECRET, OLD_SECRET], TIMESTAMP, EVENT_ID, b"{}")

    assert re.fullmatch(rf"t={TIMESTAMP},v1=[0-9a-f]{{64}},v1=[0-9a-f]{{64}}", header)


def test_verification_accepts_current_and_rotated_secrets() -> None:
    body = b'{"event":1}'
    header = signature_header([SECRET, OLD_SECRET], TIMESTAMP, EVENT_ID, body)

    assert verify_signature(SECRET, header, EVENT_ID, body, now=TIMESTAMP + 10)
    assert verify_signature(OLD_SECRET, header, EVENT_ID, body, now=TIMESTAMP + 10)


@pytest.mark.parametrize(
    ("secret", "event_id", "body", "now"),
    [
        ("whsec_wrong", EVENT_ID, b'{"event":1}', TIMESTAMP),
        (SECRET, EVENT_ID, b'{"event":2}', TIMESTAMP),  # body tampered
        (SECRET, "other-event", b'{"event":1}', TIMESTAMP),  # replayed for another event
        (SECRET, EVENT_ID, b'{"event":1}', TIMESTAMP + 301),  # too old
        (SECRET, EVENT_ID, b'{"event":1}', TIMESTAMP - 301),  # from the future
    ],
)
def test_verification_rejects_tampering_and_replays(
    secret: str, event_id: str, body: bytes, now: int
) -> None:
    header = signature_header([SECRET], TIMESTAMP, EVENT_ID, b'{"event":1}')

    assert not verify_signature(secret, header, event_id, body, now=now)


@pytest.mark.parametrize("header", ["", "v1=abc", f"t={TIMESTAMP}", "t=notanumber,v1=abc"])
def test_malformed_headers_are_rejected(header: str) -> None:
    assert not verify_signature(SECRET, header, EVENT_ID, b"{}", now=TIMESTAMP)
