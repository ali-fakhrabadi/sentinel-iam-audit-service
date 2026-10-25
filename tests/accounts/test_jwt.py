from __future__ import annotations

import base64
import json
from collections.abc import Callable
from datetime import timedelta

import pytest
import time_machine
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework.throttling import ScopedRateThrottle

from apps.accounts.models import User
from tests.factories import DEFAULT_PASSWORD

pytestmark = pytest.mark.django_db

TOKEN_URL = "/api/v1/auth/token/"
REFRESH_URL = "/api/v1/auth/token/refresh/"
LOGOUT_URL = "/api/v1/auth/logout/"
ME_URL = "/api/v1/accounts/me/"


def _login(client: APIClient, email: str, password: str = DEFAULT_PASSWORD) -> dict[str, str]:
    response = client.post(TOKEN_URL, {"email": email, "password": password}, format="json")
    assert response.status_code == 200, response.content
    tokens: dict[str, str] = response.json()
    return tokens


def _me(access: str) -> int:
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
    return client.get(ME_URL).status_code


def test_login_returns_a_working_token_pair(
    api_client: APIClient, make_user: Callable[..., User]
) -> None:
    user = make_user(email="carol@example.test")

    tokens = _login(api_client, "carol@example.test")

    assert set(tokens) == {"access", "refresh"}
    assert _me(tokens["access"]) == 200
    user.refresh_from_db()
    assert user.last_login is not None


def test_login_is_case_insensitive_on_email(
    api_client: APIClient, make_user: Callable[..., User]
) -> None:
    make_user(email="dave@example.test")

    assert _login(api_client, "DAVE@Example.TEST")["access"]


@pytest.mark.parametrize(
    ("email", "password"),
    [("erin@example.test", "wrong-password"), ("nobody@example.test", DEFAULT_PASSWORD)],
)
def test_bad_credentials_are_rejected_uniformly(
    api_client: APIClient, make_user: Callable[..., User], email: str, password: str
) -> None:
    make_user(email="erin@example.test")

    response = api_client.post(TOKEN_URL, {"email": email, "password": password}, format="json")

    assert response.status_code == 401
    assert response["Content-Type"].startswith("application/problem+json")
    assert response.json()["detail"] == "No active account found with the given credentials"


def test_inactive_users_cannot_log_in(
    api_client: APIClient, make_user: Callable[..., User]
) -> None:
    make_user(email="frank@example.test", is_active=False)

    response = api_client.post(
        TOKEN_URL, {"email": "frank@example.test", "password": DEFAULT_PASSWORD}, format="json"
    )

    assert response.status_code == 401


def test_refresh_rotates_and_old_refresh_tokens_are_single_use(
    api_client: APIClient, make_user: Callable[..., User]
) -> None:
    make_user(email="gina@example.test")
    first = _login(api_client, "gina@example.test")

    rotated = api_client.post(REFRESH_URL, {"refresh": first["refresh"]}, format="json")
    assert rotated.status_code == 200
    assert rotated.json()["refresh"] != first["refresh"]

    replay = api_client.post(REFRESH_URL, {"refresh": first["refresh"]}, format="json")
    assert replay.status_code == 401
    assert replay.json()["type"] == "urn:sentinel:problem:invalid-token"


def test_logout_revokes_the_refresh_token(
    api_client: APIClient, make_user: Callable[..., User]
) -> None:
    make_user(email="hank@example.test")
    tokens = _login(api_client, "hank@example.test")

    assert (
        api_client.post(LOGOUT_URL, {"refresh": tokens["refresh"]}, format="json").status_code
        == 204
    )
    assert (
        api_client.post(REFRESH_URL, {"refresh": tokens["refresh"]}, format="json").status_code
        == 401
    )


def test_expired_access_tokens_are_rejected(
    api_client: APIClient, make_user: Callable[..., User]
) -> None:
    make_user(email="ivy@example.test")
    tokens = _login(api_client, "ivy@example.test")

    with time_machine.travel(timezone.now() + timedelta(minutes=16), tick=False):
        assert _me(tokens["access"]) == 401


def _forge(
    token: str, *, header: dict[str, str] | None = None, claims: dict[str, object] | None = None
) -> str:
    head, payload, signature = token.split(".")

    def encode(data: dict[str, object]) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    def decode(segment: str) -> dict[str, object]:
        decoded: dict[str, object] = json.loads(
            base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        )
        return decoded

    new_head = encode({**decode(head), **(header or {})})
    new_payload = encode({**decode(payload), **(claims or {})})
    return f"{new_head}.{new_payload}.{signature}"


def test_tampered_and_unsigned_tokens_are_rejected(
    api_client: APIClient, make_user: Callable[..., User], admin_user: User
) -> None:
    make_user(email="jill@example.test")
    access = _login(api_client, "jill@example.test")["access"]

    # Changing the subject to another user breaks the signature.
    assert _me(_forge(access, claims={"sub": str(admin_user.pk)})) == 401
    # "alg": "none" must never be accepted.
    unsigned = _forge(access, header={"alg": "none"}).rsplit(".", 1)[0] + "."
    assert _me(unsigned) == 401


def test_password_change_revokes_existing_tokens(
    api_client: APIClient, make_user: Callable[..., User]
) -> None:
    make_user(email="kate@example.test")
    tokens = _login(api_client, "kate@example.test")
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")

    response = client.post(
        "/api/v1/accounts/me/password/",
        {"current_password": DEFAULT_PASSWORD, "new_password": "A-brand-new-passphrase-77"},
        format="json",
    )

    assert response.status_code == 204
    assert _me(tokens["access"]) == 401
    assert (
        api_client.post(REFRESH_URL, {"refresh": tokens["refresh"]}, format="json").status_code
        == 401
    )
    assert _login(api_client, "kate@example.test", "A-brand-new-passphrase-77")["access"]


def test_password_change_validates_input(
    client_for: Callable[[User], APIClient], make_user: Callable[..., User]
) -> None:
    client = client_for(make_user())

    wrong = client.post(
        "/api/v1/accounts/me/password/",
        {"current_password": "nope", "new_password": "A-brand-new-passphrase-77"},
        format="json",
    )
    weak = client.post(
        "/api/v1/accounts/me/password/",
        {"current_password": DEFAULT_PASSWORD, "new_password": "123"},
        format="json",
    )

    assert wrong.status_code == 400
    assert {e["field"] for e in wrong.json()["errors"]} == {"current_password"}
    assert weak.status_code == 400
    assert {e["field"] for e in weak.json()["errors"]} == {"new_password"}


def test_deactivation_revokes_access_and_refresh_tokens(
    api_client: APIClient,
    make_user: Callable[..., User],
    admin_user: User,
    client_for: Callable[[User], APIClient],
) -> None:
    target = make_user(email="liam@example.test")
    tokens = _login(api_client, "liam@example.test")

    response = client_for(admin_user).patch(
        f"/api/v1/accounts/users/{target.pk}/", {"is_active": False}, format="json"
    )

    assert response.status_code == 200
    assert _me(tokens["access"]) == 401
    assert (
        api_client.post(REFRESH_URL, {"refresh": tokens["refresh"]}, format="json").status_code
        == 401
    )


def test_login_is_rate_limited(
    api_client: APIClient, make_user: Callable[..., User], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(ScopedRateThrottle.THROTTLE_RATES, "auth", "3/minute")
    make_user(email="mia@example.test")
    attempt = {"email": "mia@example.test", "password": "wrong-password"}

    statuses = [api_client.post(TOKEN_URL, attempt, format="json").status_code for _ in range(4)]

    assert statuses == [401, 401, 401, 429]
