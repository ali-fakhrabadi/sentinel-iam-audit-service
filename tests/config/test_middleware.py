from __future__ import annotations

import logging
import re

import pytest
from rest_framework.test import APIClient

from config.logging import get_request_id
from config.middleware import resolve_request_id

HEX_32 = re.compile(r"[0-9a-f]{32}")


def test_request_id_is_generated_when_missing(api_client: APIClient) -> None:
    response = api_client.get("/health/live/")

    assert HEX_32.fullmatch(response["X-Request-ID"])


def test_valid_caller_request_id_is_propagated(api_client: APIClient) -> None:
    response = api_client.get("/health/live/", HTTP_X_REQUEST_ID="frontend-7f3a.42")

    assert response["X-Request-ID"] == "frontend-7f3a.42"


@pytest.mark.parametrize(
    "candidate",
    ["", "has space", "x" * 129, "line\r\nInjected: header", "<script>", None],
)
def test_invalid_request_ids_are_replaced(candidate: str | None) -> None:
    assert HEX_32.fullmatch(resolve_request_id(candidate))


def test_request_context_is_cleared_after_the_response(api_client: APIClient) -> None:
    api_client.get("/health/live/", HTTP_X_REQUEST_ID="abc")

    assert get_request_id() is None


def test_access_log_has_structured_fields_and_no_query_string(
    api_client: APIClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="sentinel.access"):
        response = api_client.get("/api/schema/?token=super-secret", HTTP_USER_AGENT="pytest")

    records = [r for r in caplog.records if r.name == "sentinel.access"]
    assert len(records) == 1
    record = records[0]
    assert record.levelno == logging.INFO
    assert record.__dict__["path"] == "/api/schema/"
    assert record.__dict__["status_code"] == response.status_code
    assert record.__dict__["http_method"] == "GET"
    assert record.__dict__["user_agent"] == "pytest"
    assert isinstance(record.__dict__["duration_ms"], float)
    assert "super-secret" not in record.getMessage()
    assert "super-secret" not in str(record.__dict__)


def test_probe_requests_are_logged_at_debug(
    api_client: APIClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG, logger="sentinel.access"):
        api_client.get("/health/live/")

    records = [r for r in caplog.records if r.name == "sentinel.access"]
    assert [r.levelno for r in records] == [logging.DEBUG]
