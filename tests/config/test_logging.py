from __future__ import annotations

import json
import logging
import sys
from typing import Any

from config.logging import REDACTED, JsonFormatter, redact, redact_text, request_id_var

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJlLXZhbHVl"
API_KEY = "sntl_AbCd1234_k9Z-very-secret-key-material_x"


def _format(record: logging.LogRecord) -> dict[str, Any]:
    parsed: dict[str, Any] = json.loads(JsonFormatter().format(record))
    return parsed


def _record(message: str, *args: object, **extra: Any) -> logging.LogRecord:
    record = logging.LogRecord("sentinel.test", logging.INFO, __file__, 1, message, args, None)
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def test_output_is_single_line_json_with_core_fields() -> None:
    line = JsonFormatter().format(_record("user %s logged in", "alice"))

    assert "\n" not in line
    payload = json.loads(line)
    assert payload["message"] == "user alice logged in"
    assert payload["level"] == "INFO"
    assert payload["logger"] == "sentinel.test"
    assert payload["timestamp"].endswith("+00:00")


def test_request_id_comes_from_context() -> None:
    token = request_id_var.set("req-123")
    try:
        assert _format(_record("hello"))["request_id"] == "req-123"
    finally:
        request_id_var.reset(token)


def test_sensitive_keys_are_redacted_at_any_depth() -> None:
    payload = _format(
        _record(
            "login",
            password="hunter2",
            context={
                "Authorization": "Bearer abc",
                "api_key": "k",
                "safe": 1,
                "items": [{"refresh_token": "r", "ok": True}],
            },
        )
    )

    assert payload["password"] == REDACTED
    assert payload["context"]["Authorization"] == REDACTED
    assert payload["context"]["api_key"] == REDACTED
    assert payload["context"]["safe"] == 1
    assert payload["context"]["items"] == [{"refresh_token": REDACTED, "ok": True}]


def test_credential_shapes_are_masked_in_messages() -> None:
    line = JsonFormatter().format(
        _record("token=%s key=%s header=%s", JWT, API_KEY, "Bearer abcdefghijkl12345")
    )

    assert JWT not in line
    assert API_KEY not in line
    assert "abcdefghijkl12345" not in line
    assert line.count(REDACTED) == 3


def test_exceptions_are_serialized_and_redacted() -> None:
    try:
        raise ValueError(f"bad token {JWT}")
    except ValueError:
        record = logging.LogRecord(
            "sentinel.test", logging.ERROR, __file__, 1, "failed", (), sys.exc_info()
        )

    payload = _format(record)
    assert payload["exception"]["type"] == "ValueError"
    assert JWT not in json.dumps(payload)
    assert "Traceback" in payload["exception"]["stacktrace"]


def test_non_serializable_extra_values_become_strings() -> None:
    class Opaque:
        def __str__(self) -> str:
            return "opaque-object"

    assert _format(_record("x", thing=Opaque()))["thing"] == "opaque-object"


def test_redaction_depth_is_bounded() -> None:
    nested: dict[str, Any] = {}
    cursor = nested
    for _ in range(20):
        cursor["child"] = {}
        cursor = cursor["child"]

    assert "[TRUNCATED]" in json.dumps(redact(nested))


def test_redact_text_leaves_ordinary_text_alone() -> None:
    assert redact_text("GET /api/v1/audit/events/ 200") == "GET /api/v1/audit/events/ 200"
