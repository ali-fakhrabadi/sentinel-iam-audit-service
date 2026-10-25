from __future__ import annotations

from django.conf import settings
from rest_framework.test import APIClient

ALLOWED = "http://localhost:5173"


def test_preflight_from_allowed_origin(api_client: APIClient) -> None:
    response = api_client.options(
        "/api/schema/",
        HTTP_ORIGIN=ALLOWED,
        HTTP_ACCESS_CONTROL_REQUEST_METHOD="POST",
        HTTP_ACCESS_CONTROL_REQUEST_HEADERS="authorization, content-type, x-api-key",
    )

    assert response.status_code == 200
    assert response["Access-Control-Allow-Origin"] == ALLOWED
    assert response["Access-Control-Allow-Credentials"] == "true"
    allowed_headers = response["Access-Control-Allow-Headers"].lower()
    for header in ("authorization", "content-type", "x-api-key", "x-request-id"):
        assert header in allowed_headers
    assert response["Access-Control-Max-Age"] == "3600"


def test_unknown_origin_gets_no_cors_headers(api_client: APIClient) -> None:
    response = api_client.options(
        "/api/schema/",
        HTTP_ORIGIN="https://evil.example",
        HTTP_ACCESS_CONTROL_REQUEST_METHOD="GET",
    )

    assert "Access-Control-Allow-Origin" not in response


def test_custom_headers_are_exposed_to_browsers(api_client: APIClient) -> None:
    response = api_client.get("/api/schema/", HTTP_ORIGIN=ALLOWED)

    assert response["Access-Control-Allow-Origin"] == ALLOWED
    exposed = {h.strip() for h in response["Access-Control-Expose-Headers"].split(",")}
    assert {"X-Request-ID", "X-Sentinel-Signature"} <= exposed


def test_cors_is_limited_to_api_routes(api_client: APIClient) -> None:
    response = api_client.get("/health/live/", HTTP_ORIGIN=ALLOWED)

    assert "Access-Control-Allow-Origin" not in response


def test_cors_configuration_is_safe() -> None:
    assert settings.MIDDLEWARE[0] == "corsheaders.middleware.CorsMiddleware"
    assert getattr(settings, "CORS_ALLOW_ALL_ORIGINS", False) is False
    assert "*" not in settings.CORS_ALLOWED_ORIGINS
