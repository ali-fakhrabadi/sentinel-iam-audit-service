"""OpenAPI security scheme for API key authentication (loaded in AccountsConfig.ready)."""

from __future__ import annotations

from typing import Any

from drf_spectacular.extensions import OpenApiAuthenticationExtension

from apps.accounts.authentication import API_KEY_HEADER


class APIKeyAuthenticationScheme(OpenApiAuthenticationExtension):
    target_class = "apps.accounts.authentication.APIKeyAuthentication"
    name = "apiKeyAuth"

    def get_security_definition(self, auto_schema: Any) -> dict[str, str]:
        return {
            "type": "apiKey",
            "in": "header",
            "name": API_KEY_HEADER,
            "description": "Service account API key: `sntl_<prefix>_<secret>`. "
            "Shown once at creation; scopes limit what it can do.",
        }
