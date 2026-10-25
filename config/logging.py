"""Structured JSON logging with request correlation and secret redaction.

Each log line is one JSON object carrying the active request ID, so logs from
Gunicorn, Django and Celery can be joined in Loki or any log pipeline.

Redaction happens in two places:
* values stored under sensitive keys (``password``, ``authorization``, ...) are
  replaced, however deeply they are nested in the ``extra`` payload;
* well-known credential shapes (JWTs, Sentinel API keys, bearer tokens) are
  masked inside free-text messages and string values.
"""

from __future__ import annotations

import json
import logging
import re
import traceback
from collections.abc import Mapping
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

REDACTED = "[REDACTED]"
MAX_REDACTION_DEPTH = 8

request_id_var: ContextVar[str | None] = ContextVar("sentinel_request_id", default=None)

SENSITIVE_KEY_PATTERN = re.compile(
    r"(passw(or)?d|secret|token|authorization|cookie|api[_-]?key|signature|credential|"
    r"private[_-]?key|session)",
    re.IGNORECASE,
)

_SECRET_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    # JSON Web Tokens: three base64url segments, header and payload start with "eyJ".
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    # Sentinel API keys: sntl_<8-char prefix>_<secret>.
    re.compile(r"\bsntl_[A-Za-z0-9]{8}_[A-Za-z0-9_-]{16,}"),
    # Any bearer credential in free text, e.g. a copied Authorization header.
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
)

# Attributes every LogRecord has; anything else was passed through ``extra``.
_STANDARD_RECORD_ATTRS = frozenset(
    vars(logging.LogRecord("", logging.INFO, "", 0, "", None, None)).keys()
    | {"message", "asctime", "taskName", "request_id"}
)


def redact_text(value: str) -> str:
    """Mask credential-shaped substrings inside free text."""
    for pattern in _SECRET_VALUE_PATTERNS:
        value = pattern.sub(REDACTED, value)
    return value


def redact(value: Any, *, depth: int = 0) -> Any:
    """Return a JSON-safe copy of ``value`` with sensitive data removed."""
    if depth > MAX_REDACTION_DEPTH:
        return "[TRUNCATED]"
    if isinstance(value, Mapping):
        return {
            str(key): REDACTED
            if SENSITIVE_KEY_PATTERN.search(str(key))
            else redact(item, depth=depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, list | tuple | set | frozenset):
        return [redact(item, depth=depth + 1) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    if value is None or isinstance(value, bool | int | float):
        return value
    return redact_text(str(value))


def get_request_id() -> str | None:
    """Request ID of the HTTP request (or task) currently being processed."""
    return request_id_var.get()


class JsonFormatter(logging.Formatter):
    """Render records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_text(record.getMessage()),
        }
        request_id = getattr(record, "request_id", None) or get_request_id()
        if request_id:
            payload["request_id"] = request_id

        extra = {
            key: value
            for key, value in vars(record).items()
            if key not in _STANDARD_RECORD_ATTRS and not key.startswith("_")
        }
        if extra:
            payload.update(redact(extra))

        if record.exc_info and record.exc_info[0] is not None:
            payload["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": redact_text(str(record.exc_info[1])),
                "stacktrace": redact_text("".join(traceback.format_exception(*record.exc_info))),
            }
        return json.dumps(payload, ensure_ascii=False, default=str)
