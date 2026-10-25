from __future__ import annotations

import pytest
from django.db.utils import OperationalError
from pytest_django import Settings
from rest_framework.test import APIClient


def test_liveness_does_not_touch_the_database(api_client: APIClient) -> None:
    # No django_db mark: any database access in the view would fail this test.
    response = api_client.get("/health/live/")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response["X-Request-ID"]


@pytest.mark.django_db
@pytest.mark.integration
def test_readiness_reports_ok_with_real_postgres_and_redis(api_client: APIClient) -> None:
    response = api_client.get("/health/ready/")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    for name in ("database", "redis"):
        assert body["checks"][name]["status"] == "ok"
        assert isinstance(body["checks"][name]["latency_ms"], float)


@pytest.mark.django_db
def test_readiness_returns_503_without_leaking_database_errors(
    api_client: APIClient, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def broken_database() -> None:
        raise OperationalError("connection to 10.20.30.40 failed: password=hunter2")

    monkeypatch.setattr("config.health.check_database", broken_database)

    response = api_client.get("/health/ready/")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "unavailable"
    assert body["checks"]["database"] == {"status": "error", "latency_ms": None}
    assert body["checks"]["redis"]["status"] == "ok"
    raw = response.content.decode()
    assert "10.20.30.40" not in raw
    assert "hunter2" not in raw
    assert any("Readiness check failed: database" in r.getMessage() for r in caplog.records)


@pytest.mark.django_db
@pytest.mark.integration
def test_readiness_returns_503_when_redis_is_unreachable(
    api_client: APIClient, settings: Settings
) -> None:
    # Port 9 (discard) is closed: the real Redis check fails fast with connection refused.
    settings.CELERY_BROKER_URL = "redis://127.0.0.1:9/0"

    response = api_client.get("/health/ready/")

    assert response.status_code == 503
    assert response.json()["checks"]["redis"] == {"status": "error", "latency_ms": None}
    assert response.json()["checks"]["database"]["status"] == "ok"


def test_probes_are_exempt_from_https_redirect(api_client: APIClient, settings: Settings) -> None:
    settings.SECURE_SSL_REDIRECT = True

    assert api_client.get("/health/live/").status_code == 200
    redirected = api_client.get("/api/schema/")
    assert redirected.status_code == 301
    assert redirected["Location"].startswith("https://")


def test_probes_ignore_invalid_credentials(api_client: APIClient) -> None:
    api_client.credentials(HTTP_AUTHORIZATION="Bearer not-a-real-token")

    assert api_client.get("/health/live/").status_code == 200
