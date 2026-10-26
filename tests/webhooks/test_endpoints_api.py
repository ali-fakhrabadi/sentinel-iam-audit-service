from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Any

import pytest
from django.utils import timezone
from rest_framework.test import APIClient

from apps.accounts.models import User
from apps.webhooks import crypto, services
from apps.webhooks.models import WebhookDelivery, WebhookEndpoint
from tests.factories import create_event, create_service_account

pytestmark = pytest.mark.django_db
URL = "/api/v1/webhooks/endpoints/"
ClientFor = Callable[[User], APIClient]
MakeUser = Callable[..., User]


def _create(client: APIClient, **overrides: object) -> Any:
    payload: dict[str, object] = {
        "name": "soc-pager",
        "url": "https://hooks.example.com/sentinel",
        "min_severity": "WARN",
        "action_prefixes": ["IAM", "auth.login"],
    }
    payload.update(overrides)
    return client.post(URL, payload, format="json")


def test_creation_returns_the_secret_once_and_stores_it_encrypted(
    admin_user: User, client_for: ClientFor, dns: dict[str, list[str]]
) -> None:
    client = client_for(admin_user)

    response = _create(client)

    assert response.status_code == 201
    assert response["Cache-Control"] == "no-store"
    body = response.json()
    assert body["secret"].startswith("whsec_")
    assert body["action_prefixes"] == ["auth.login", "iam"]
    endpoint = WebhookEndpoint.objects.get(pk=body["id"])
    assert body["secret"] not in endpoint.secret_ciphertext
    assert crypto.decrypt_secret(endpoint.secret_ciphertext) == body["secret"]
    listing = client.get(URL).json()
    detail = client.get(f"{URL}{endpoint.pk}/").json()
    assert "secret" not in listing[0]
    assert "secret" not in detail
    assert body["secret"] not in str(listing) + str(detail)


def test_ssrf_destinations_are_rejected_at_creation(
    admin_user: User, client_for: ClientFor, dns: dict[str, list[str]]
) -> None:
    dns["hooks.example.com"] = ["10.0.0.7"]

    response = _create(client_for(admin_user))

    assert response.status_code == 400
    assert response.json()["errors"][0]["field"] == "url"
    assert not WebhookEndpoint.objects.exists()


@pytest.mark.parametrize("prefixes", [["Not Valid"], [".iam"], ["iam..user"]])
def test_invalid_action_prefixes_are_rejected(
    admin_user: User, client_for: ClientFor, dns: dict[str, list[str]], prefixes: list[str]
) -> None:
    response = _create(client_for(admin_user), action_prefixes=prefixes)

    assert response.status_code == 400
    assert response.json()["errors"][0]["field"] == "action_prefixes"


def test_duplicate_names_conflict(
    admin_user: User, client_for: ClientFor, dns: dict[str, list[str]]
) -> None:
    client = client_for(admin_user)
    _create(client)

    assert _create(client).status_code == 409


def test_webhook_permissions(
    make_user: MakeUser, client_for: ClientFor, dns: dict[str, list[str]]
) -> None:
    analyst = client_for(make_user(roles=["security_analyst"]))
    auditor = client_for(make_user(roles=["auditor"]))

    assert analyst.get(URL).status_code == 200
    assert _create(analyst).status_code == 403
    assert auditor.get(URL).status_code == 403


def test_updates_revalidate_the_url(
    admin_user: User, client_for: ClientFor, dns: dict[str, list[str]]
) -> None:
    client = client_for(admin_user)
    endpoint_id = _create(client).json()["id"]
    dns["internal.example.com"] = ["192.168.0.10"]

    rejected = client.patch(
        f"{URL}{endpoint_id}/", {"url": "https://internal.example.com/x"}, format="json"
    )
    disabled = client.patch(f"{URL}{endpoint_id}/", {"is_active": False}, format="json")

    assert rejected.status_code == 400
    assert disabled.status_code == 200
    assert disabled.json()["is_active"] is False
    assert disabled.json()["url"] == "https://hooks.example.com/sentinel"


def test_rotation_issues_a_new_secret_and_keeps_the_old_one_briefly(
    admin_user: User, client_for: ClientFor, dns: dict[str, list[str]]
) -> None:
    client = client_for(admin_user)
    created = _create(client).json()

    rotated = client.post(f"{URL}{created['id']}/rotate-secret/")

    assert rotated.status_code == 200
    new_secret = rotated.json()["secret"]
    assert new_secret != created["secret"]
    endpoint = WebhookEndpoint.objects.get(pk=created["id"])
    now = timezone.now()
    assert services.signing_secrets(endpoint, now=now) == [new_secret, created["secret"]]
    assert services.signing_secrets(endpoint, now=now + timedelta(hours=25)) == [new_secret]


def test_delivery_history_is_listed_and_filterable(
    admin_user: User, client_for: ClientFor, dns: dict[str, list[str]]
) -> None:
    client = client_for(admin_user)
    endpoint = WebhookEndpoint.objects.get(pk=_create(client).json()["id"])
    producer = create_service_account()
    WebhookDelivery.objects.create(
        endpoint=endpoint, event=create_event(producer=producer, severity="WARN")
    )
    WebhookDelivery.objects.create(
        endpoint=endpoint,
        event=create_event(producer=producer, severity="CRITICAL"),
        status="succeeded",
    )

    everything = client.get(f"{URL}{endpoint.pk}/deliveries/").json()
    succeeded = client.get(f"{URL}{endpoint.pk}/deliveries/", {"status": "succeeded"}).json()

    assert len(everything["results"]) == 2
    assert [d["event_severity"] for d in succeeded["results"]] == ["CRITICAL"]
    assert client.get(f"{URL}{endpoint.pk}/deliveries/", {"status": "bogus"}).status_code == 400
