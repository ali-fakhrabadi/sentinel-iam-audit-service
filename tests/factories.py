"""factory_boy factories for test data, plus typed helpers for use in tests."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, cast

import factory

from apps.accounts.models import Role, ServiceAccount, User, UserRole

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
