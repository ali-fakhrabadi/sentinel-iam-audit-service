from __future__ import annotations

import pytest
from pytest_django import Settings
from rest_framework.test import APIClient

TOKEN = "metrics-test-token-0123456789"


@pytest.fixture(autouse=True)
def _metrics_token(settings: Settings) -> None:
    settings.METRICS_AUTH_TOKEN = TOKEN


def test_metrics_require_a_bearer_token(api_client: APIClient) -> None:
    response = api_client.get("/metrics")

    assert response.status_code == 401
    assert response["WWW-Authenticate"] == 'Bearer realm="metrics"'
    assert response.json()["type"] == "urn:sentinel:problem:not-authenticated"


@pytest.mark.parametrize("header", [f"Bearer {TOKEN}x", f"Basic {TOKEN}", TOKEN, "Bearer"])
def test_metrics_reject_wrong_credentials(api_client: APIClient, header: str) -> None:
    assert api_client.get("/metrics", HTTP_AUTHORIZATION=header).status_code == 401


def test_metrics_are_exported_with_the_right_token(api_client: APIClient) -> None:
    api_client.get("/health/live/")

    response = api_client.get("/metrics", HTTP_AUTHORIZATION=f"Bearer {TOKEN}")

    assert response.status_code == 200
    assert response["Content-Type"].startswith("text/plain")
    assert b"django_http_requests_before_middlewares_total" in response.content


def test_metrics_only_allow_get(api_client: APIClient) -> None:
    response = api_client.post("/metrics", HTTP_AUTHORIZATION=f"Bearer {TOKEN}")

    assert response.status_code == 405
    assert response["Allow"] == "GET"


def test_metrics_are_disabled_without_a_configured_token(
    api_client: APIClient, settings: Settings
) -> None:
    settings.METRICS_AUTH_TOKEN = ""

    assert api_client.get("/metrics", HTTP_AUTHORIZATION="Bearer ").status_code == 404


def test_metrics_are_exempt_from_https_redirect(api_client: APIClient, settings: Settings) -> None:
    settings.SECURE_SSL_REDIRECT = True

    response = api_client.get("/metrics", HTTP_AUTHORIZATION=f"Bearer {TOKEN}")

    assert response.status_code == 200
