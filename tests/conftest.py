"""Shared pytest fixtures.

Tests run against the real PostgreSQL and Redis configured through the environment
(docker compose dev profile locally, service containers in CI).
"""

from __future__ import annotations

import socket
import uuid
from collections.abc import Callable, Iterator, Sequence
from typing import Any

import pytest
from pytest_django import Settings
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts import services
from apps.accounts.models import Permission, Role, ServiceAccount, User
from config.celery import app as celery_app
from config.logging import request_id_var
from tests.factories import create_service_account, create_user


@pytest.fixture(autouse=True)
def _isolated_settings(settings: Settings) -> None:
    """Per-test cache, static storage without collectstatic, and a fast password hasher.

    A per-test in-memory cache keeps DRF throttle counters from leaking between tests.
    Argon2 is the production hasher (see test_settings); MD5 only keeps tests fast.
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
    settings.PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]


@pytest.fixture(autouse=True, scope="session")
def _in_memory_celery_broker() -> Iterator[None]:
    """Tasks enqueued by tests must never reach a real Redis shared with a running stack."""
    previous = celery_app.conf.broker_url
    celery_app.conf.update(broker_url="memory://")
    yield
    celery_app.conf.update(broker_url=previous)


@pytest.fixture
def sent_tasks(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Names of Celery tasks sent through ``send_task`` during the test."""
    names: list[str] = []
    monkeypatch.setattr(celery_app, "send_task", lambda name, *args, **kwargs: names.append(name))
    return names


@pytest.fixture
def dns(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[str]]:
    """Fake resolver for webhook destinations; unknown names do not resolve."""
    table: dict[str, list[str]] = {"hooks.example.com": ["93.184.216.34"]}

    def resolve(host: str, port: int) -> list[str]:
        if host not in table:
            raise socket.gaierror(f"{host} does not resolve")
        return table[host]

    monkeypatch.setattr("apps.webhooks.ssrf.resolve_host", resolve)
    return table


@pytest.fixture(autouse=True)
def _clean_request_context() -> Iterator[None]:
    token = request_id_var.set(None)
    yield
    request_id_var.reset(token)


@pytest.fixture
def api_client() -> APIClient:
    return APIClient()


MakeUser = Callable[..., User]


@pytest.fixture
def make_user(db: None) -> MakeUser:
    def _make(*, roles: Sequence[str] = (), **fields: Any) -> User:
        return create_user(roles=roles, **fields)

    return _make


@pytest.fixture
def admin_user(make_user: MakeUser) -> User:
    return make_user(roles=["admin"], email="admin@example.test")


@pytest.fixture
def superuser(db: None) -> User:
    return User.objects.create_superuser("root@example.test", "Root-Password-12345")


@pytest.fixture
def client_for() -> Callable[[User], APIClient]:
    """An APIClient authenticated with a fresh JWT access token for ``user``."""

    def _client(user: User) -> APIClient:
        client = APIClient()
        token = RefreshToken.for_user(user)
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")
        return client

    return _client


@pytest.fixture
def make_role(db: None) -> Callable[..., Role]:
    def _make(name: str, permissions: Sequence[str]) -> Role:
        role = Role.objects.create(name=name, description="test role")
        role.permissions.set(Permission.objects.filter(code__in=permissions))
        return role

    return _make


@pytest.fixture
def issue_key(superuser: User) -> Callable[..., tuple[ServiceAccount, services.IssuedAPIKey]]:
    """Create a service account and an API key for it; returns both."""

    def _issue(
        scopes: Sequence[str] = ("audit:write",),
        service_account: ServiceAccount | None = None,
        **kwargs: Any,
    ) -> tuple[ServiceAccount, services.IssuedAPIKey]:
        account = service_account or create_service_account()
        issued = services.api_key_issue(
            actor=superuser, service_account=account, name="test key", scopes=scopes, **kwargs
        )
        return account, issued

    return _issue
