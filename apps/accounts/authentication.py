"""API key authentication for machine-to-machine clients.

Human-facing endpoints use JWT (the DRF default). Machine endpoints opt in to
``APIKeyAuthentication`` explicitly, so the two credential types never unlock each
other's endpoints.
"""

from __future__ import annotations

from rest_framework.authentication import BaseAuthentication
from rest_framework.request import Request

from apps.accounts import services
from apps.accounts.models import APIKey, ServiceAccount

API_KEY_HEADER = "X-API-Key"


class APIKeyAuthentication(BaseAuthentication):
    """Authenticate ``X-API-Key: sntl_<prefix>_<secret>``.

    On success ``request.user`` is the key's ``ServiceAccount`` and ``request.auth``
    is the ``APIKey`` (whose scopes drive authorization).
    """

    def authenticate(self, request: Request) -> tuple[ServiceAccount, APIKey] | None:
        raw_key = request.headers.get(API_KEY_HEADER)
        if raw_key is None:
            return None
        api_key = services.api_key_authenticate(raw_key.strip())
        return api_key.service_account, api_key

    def authenticate_header(self, request: Request) -> str:
        # A challenge keeps DRF from downgrading 401 responses to 403.
        return f'ApiKey header="{API_KEY_HEADER}"'
