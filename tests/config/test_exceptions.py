from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any

import pytest
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory
from pytest_django import Settings
from rest_framework.exceptions import ErrorDetail
from rest_framework.test import APIClient

from config import views
from config.exceptions import PROBLEM_CONTENT_TYPE, flatten_validation_errors

pytestmark = pytest.mark.urls("tests.config.urls")


def _assert_problem(response: Any, *, status: int, slug: str) -> dict[str, Any]:
    assert response.status_code == status
    assert response["Content-Type"].startswith(PROBLEM_CONTENT_TYPE)
    body: dict[str, Any] = response.json()
    assert body["type"] == f"urn:sentinel:problem:{slug}"
    assert body["status"] == status
    assert body["title"]
    assert body["detail"]
    assert body["request_id"] == response["X-Request-ID"]
    return body


def test_validation_errors_are_flattened_with_dotted_paths(api_client: APIClient) -> None:
    response = api_client.post(
        "/errors/validation/",
        {"name": "far-too-long", "events": [{"severity": "INFO"}, {"severity": "BOGUS"}]},
        format="json",
    )

    body = _assert_problem(response, status=400, slug="validation-error")
    assert body["instance"] == "/errors/validation/"
    errors = {(error["field"], error["code"]) for error in body["errors"]}
    assert ("name", "max_length") in errors
    assert ("events.1.severity", "invalid_choice") in errors
    assert not any(error["field"].startswith("events.0") for error in body["errors"])


def test_malformed_json_is_a_problem_response(api_client: APIClient) -> None:
    response = api_client.generic(
        "POST", "/errors/echo/", '{"name": ', content_type="application/json"
    )

    _assert_problem(response, status=400, slug="malformed-request")


def test_unsupported_media_type(api_client: APIClient) -> None:
    response = api_client.post(
        "/errors/echo/", "name=x", content_type="application/x-www-form-urlencoded"
    )

    _assert_problem(response, status=415, slug="unsupported-media-type")


def test_missing_credentials_return_401_with_challenge(api_client: APIClient) -> None:
    response = api_client.get("/errors/auth/")

    _assert_problem(response, status=401, slug="not-authenticated")
    assert response["WWW-Authenticate"].startswith("Bearer")


def test_invalid_jwt_returns_401_without_token_internals(api_client: APIClient) -> None:
    api_client.credentials(HTTP_AUTHORIZATION="Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.bad")

    response = api_client.get("/errors/auth/")

    body = _assert_problem(response, status=401, slug="invalid-token")
    assert "messages" not in body
    assert "token_class" not in response.content.decode()


@pytest.mark.parametrize("path", ["/errors/drf-forbidden/", "/errors/django-forbidden/"])
def test_permission_denied(api_client: APIClient, path: str) -> None:
    _assert_problem(api_client.get(path), status=403, slug="permission-denied")


def test_http404_from_a_view(api_client: APIClient) -> None:
    _assert_problem(api_client.get("/errors/missing/"), status=404, slug="not-found")


def test_unknown_url_uses_django_handler_with_same_format(api_client: APIClient) -> None:
    response = api_client.get("/no/such/route/")

    body = _assert_problem(response, status=404, slug="not-found")
    assert body["instance"] == "/no/such/route/"


def test_method_not_allowed(api_client: APIClient) -> None:
    response = api_client.delete("/errors/validation/")

    _assert_problem(response, status=405, slug="method-not-allowed")
    assert "POST" in response["Allow"]


def test_throttling_exposes_retry_after(api_client: APIClient) -> None:
    response = api_client.get("/errors/throttled/")

    body = _assert_problem(response, status=429, slug="rate-limited")
    assert body["retry_after"] == 17
    assert response["Retry-After"] == "17"


def test_unexpected_errors_are_logged_but_not_exposed(
    api_client: APIClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.ERROR, logger="sentinel.errors"):
        response = api_client.get("/errors/crash/")

    body = _assert_problem(response, status=500, slug="internal-error")
    raw = response.content.decode()
    assert "hunter2" not in raw
    assert "RuntimeError" not in raw
    assert "Traceback" not in raw
    logged = [r for r in caplog.records if r.name == "sentinel.errors"]
    assert logged
    assert logged[0].exc_info is not None
    assert body["request_id"]


def test_database_timeouts_become_503_and_are_logged(
    api_client: APIClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="sentinel.errors"):
        response = api_client.get("/errors/db-timeout/")

    _assert_problem(response, status=503, slug="service-unavailable")
    assert "statement timeout" not in response.content.decode()
    logged = [r for r in caplog.records if r.name == "sentinel.errors"]
    assert logged
    assert logged[0].exc_info is not None


def test_oversized_body_is_rejected_before_parsing(
    api_client: APIClient, settings: Settings
) -> None:
    settings.API_MAX_REQUEST_BYTES = 1024

    response = api_client.post("/errors/echo/", {"blob": "x" * 2048}, format="json")

    _assert_problem(response, status=413, slug="payload-too-large")


def test_invalid_content_length_header(api_client: APIClient) -> None:
    response = api_client.generic(
        "POST", "/errors/echo/", "{}", content_type="application/json", CONTENT_LENGTH="abc"
    )

    _assert_problem(response, status=400, slug="bad-request")


def test_suspicious_operations_become_400_without_details(api_client: APIClient) -> None:
    response = api_client.get("/errors/suspicious/")

    _assert_problem(response, status=400, slug="bad-request")
    assert "10.0.0.7" not in response.content.decode()


def test_request_data_too_big_becomes_413(api_client: APIClient) -> None:
    _assert_problem(api_client.get("/errors/too-big/"), status=413, slug="payload-too-large")


@pytest.mark.parametrize(
    ("handler", "status", "slug"),
    [
        (views.bad_request, 400, "bad-request"),
        (views.permission_denied, 403, "permission-denied"),
        (views.page_not_found, 404, "not-found"),
    ],
)
def test_django_error_handlers_render_problems(
    handler: Callable[[HttpRequest, Exception], HttpResponse], status: int, slug: str
) -> None:
    request = RequestFactory().get("/admin/secret/")

    response = handler(request, Exception("internal detail"))

    assert response.status_code == status
    assert response["Content-Type"] == PROBLEM_CONTENT_TYPE
    body = json.loads(response.content)
    assert body["type"] == f"urn:sentinel:problem:{slug}"
    assert body["instance"] == "/admin/secret/"
    assert "internal detail" not in response.content.decode()


def test_django_500_handler_renders_a_generic_problem() -> None:
    response = views.server_error(RequestFactory().get("/boom/"))

    assert response.status_code == 500
    assert json.loads(response.content)["type"] == "urn:sentinel:problem:internal-error"


def test_flatten_handles_non_field_and_nested_errors() -> None:
    detail = {
        "non_field_errors": [ErrorDetail("Bad combination.", code="invalid")],
        "events": [{}, {"metadata": {"depth": [ErrorDetail("Too deep.", code="max_depth")]}}],
    }

    assert flatten_validation_errors(detail) == [
        {"field": "non_field_errors", "message": "Bad combination.", "code": "invalid"},
        {"field": "events.1.metadata.depth", "message": "Too deep.", "code": "max_depth"},
    ]


def test_flatten_top_level_list() -> None:
    assert flatten_validation_errors([ErrorDetail("Nope.", code="invalid")]) == [
        {"field": "non_field_errors", "message": "Nope.", "code": "invalid"}
    ]
