from __future__ import annotations

import pytest
from django.test import Client

from apps.accounts.models import User

pytestmark = pytest.mark.django_db


@pytest.fixture
def admin_client_logged_in(superuser: User) -> Client:
    client = Client()
    client.force_login(superuser)
    return client


@pytest.mark.parametrize(
    "path",
    [
        "/admin/accounts/user/",
        "/admin/accounts/user/add/",
        "/admin/accounts/role/",
        "/admin/accounts/permission/",
        "/admin/accounts/serviceaccount/",
        "/admin/accounts/apikey/",
    ],
)
def test_admin_pages_render(admin_client_logged_in: Client, path: str) -> None:
    assert admin_client_logged_in.get(path).status_code == 200


def test_user_change_page_renders(admin_client_logged_in: Client, superuser: User) -> None:
    response = admin_client_logged_in.get(f"/admin/accounts/user/{superuser.pk}/change/")
    assert response.status_code == 200


@pytest.mark.parametrize("path", ["/admin/accounts/apikey/add/", "/admin/accounts/permission/add/"])
def test_keys_and_catalog_cannot_be_created_in_admin(
    admin_client_logged_in: Client, path: str
) -> None:
    assert admin_client_logged_in.get(path).status_code == 403
