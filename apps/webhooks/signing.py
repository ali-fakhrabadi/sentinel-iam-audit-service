"""Canonical HMAC-SHA256 signing of webhook payloads.

Wire format::

    X-Sentinel-Event-Id:  <audit event UUID>       (de-duplication key)
    X-Sentinel-Timestamp: <unix seconds>
    X-Sentinel-Signature: t=<unix seconds>,v1=<hex>[,v1=<hex>]

    signed message = f"{timestamp}.{event_id}.".encode() + <exact request body bytes>
    v1             = hex(HMAC_SHA256(secret, signed message))

Several ``v1`` entries appear while a rotated secret is in its grace period; a
receiver accepts the request if any of them matches its secret. Receivers should
reject timestamps outside a 5-minute window to stop replays.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections.abc import Mapping, Sequence
from typing import Any

EVENT_ID_HEADER = "X-Sentinel-Event-Id"
DELIVERY_ID_HEADER = "X-Sentinel-Delivery-Id"
TIMESTAMP_HEADER = "X-Sentinel-Timestamp"
SIGNATURE_HEADER = "X-Sentinel-Signature"
DEFAULT_TOLERANCE_SECONDS = 300


def canonical_body(payload: Mapping[str, Any]) -> bytes:
    """Deterministic JSON bytes: sorted keys, no insignificant whitespace, UTF-8."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode("utf-8")


def signed_message(timestamp: int, event_id: str, body: bytes) -> bytes:
    return f"{timestamp}.{event_id}.".encode() + body


def compute_signature(secret: str, timestamp: int, event_id: str, body: bytes) -> str:
    return hmac.new(
        secret.encode(), signed_message(timestamp, event_id, body), hashlib.sha256
    ).hexdigest()


def signature_header(
    signing_secrets: Sequence[str], timestamp: int, event_id: str, body: bytes
) -> str:
    signatures = [
        f"v1={compute_signature(secret, timestamp, event_id, body)}" for secret in signing_secrets
    ]
    return ",".join([f"t={timestamp}", *signatures])


def verify_signature(
    secret: str,
    header: str,
    event_id: str,
    body: bytes,
    *,
    tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
    now: float | None = None,
) -> bool:
    """Reference consumer-side check (the README shows the same logic standalone)."""
    timestamp: int | None = None
    candidates: list[str] = []
    for part in header.split(","):
        name, _, value = part.strip().partition("=")
        if name == "t" and value.isdigit():
            timestamp = int(value)
        elif name == "v1" and value:
            candidates.append(value)
    if timestamp is None or not candidates:
        return False
    current = time.time() if now is None else now
    if abs(current - timestamp) > tolerance_seconds:
        return False
    expected = compute_signature(secret, timestamp, event_id, body)
    return any(hmac.compare_digest(expected, candidate) for candidate in candidates)
