"""factory_boy factories for test data, plus typed helpers for use in tests."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any, cast

import factory
from django.utils import timezone

from apps.accounts.models import Role, ServiceAccount, User, UserRole
from apps.audit_logs.models import AuditEvent
from apps.webhooks.crypto import encrypt_secret, generate_signing_secret
from apps.webhooks.models import WebhookEndpoint

DEFAULT_PASSWORD = "Correct-Horse-Battery-Staple-9"


class UserFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = User
        skip_postgeneration_save = True

    email = factory.Sequence(lambda n: f"user{n}@example.test")
    full_name = factory.Faker("name")
    password = factory.django.Password(DEFAULT_PASSWORD)

    @factory.post_generation
    def roles(self, create: bool, extracted: Sequence[str] | None, **kwargs: Any) -> None:
        # factory_boy passes the created User as ``self`` here.
        if create and extracted:
            user = cast(User, self)
            for name in extracted:
                UserRole.objects.create(user=user, role=Role.objects.get(name=name))


class ServiceAccountFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = ServiceAccount

    name = factory.Sequence(lambda n: f"svc-{n}")
    description = "Test service account"


def create_user(*, roles: Sequence[str] = (), **fields: Any) -> User:
    return cast(User, UserFactory(roles=list(roles), **fields))


def create_service_account(**fields: Any) -> ServiceAccount:
    return cast(ServiceAccount, ServiceAccountFactory(**fields))


def create_event(*, producer: ServiceAccount | User, **fields: Any) -> AuditEvent:
    """Insert an audit event directly (no outbox), e.g. with a chosen created_at."""
    now = timezone.now()
    values: dict[str, Any] = {
        "action": "auth.login.failed",
        "resource_type": "iam.user",
        "severity": "INFO",
        "received_at": now,
        "created_at": now,
        "metadata": {},
    }
    values.update(fields)
    if isinstance(producer, ServiceAccount):
        values["producer_service_account"] = producer
    else:
        values["producer_user"] = producer
    return AuditEvent.objects.create(**values)


def create_endpoint(**fields: Any) -> tuple[WebhookEndpoint, str]:
    """Insert a webhook endpoint directly (no audit event); returns it with its secret."""
    secret = generate_signing_secret()
    values: dict[str, Any] = {
        "name": f"endpoint-{uuid.uuid4().hex[:8]}",
        "url": "https://hooks.example.com/sentinel",
        "min_severity": "WARN",
        "secret_ciphertext": encrypt_secret(secret),
    }
    values.update(fields)
    return WebhookEndpoint.objects.create(**values), secret
