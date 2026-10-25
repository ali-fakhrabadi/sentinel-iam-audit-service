"""Shared pytest fixtures.

Tests run against the real PostgreSQL and Redis configured through the environment
(docker compose dev profile locally, service containers in CI).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from pytest_django import Settings
from rest_framework.test import APIClient

from config.logging import request_id_var


@pytest.fixture(autouse=True)
def _isolated_settings(settings: Settings) -> None:
    """Give every test its own cache and a static storage that needs no collectstatic.

    A per-test in-memory cache keeps DRF throttle counters from leaking between tests.
    """
    settings.CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": f"tests-{uuid.uuid4().hex}",
        }
    }
    settings.STORAGES = {
        **settings.STORAGES,
        "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    }


@pytest.fixture(autouse=True)
def _clean_request_context() -> Iterator[None]:
    token = request_id_var.set(None)
    yield
    request_id_var.reset(token)


@pytest.fixture
def api_client() -> APIClient:
    return APIClient()
