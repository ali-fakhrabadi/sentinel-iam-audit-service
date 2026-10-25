from __future__ import annotations

from pathlib import Path

import yaml
from django.conf import settings
from django.core.management import call_command
from rest_framework.test import APIClient


def test_schema_passes_validation_without_warnings(tmp_path: Path) -> None:
    output = tmp_path / "openapi.yaml"

    call_command("spectacular", "--validate", "--fail-on-warn", "--file", str(output))

    schema = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert schema["openapi"].startswith("3.")
    operation_ids = {
        operation["operationId"]
        for path_item in schema["paths"].values()
        for operation in path_item.values()
    }
    assert {"health_live", "health_ready"} <= operation_ids


def test_typescript_friendly_settings() -> None:
    assert settings.SPECTACULAR_SETTINGS["COMPONENT_SPLIT_REQUEST"] is True


def test_schema_endpoint_serves_json(api_client: APIClient) -> None:
    response = api_client.get("/api/schema/", {"format": "json"})

    assert response.status_code == 200
    assert response.json()["info"]["title"] == "Sentinel IAM & Audit Service API"


def test_swagger_ui_and_redoc_use_self_hosted_assets(api_client: APIClient) -> None:
    for path in ("/api/docs/", "/api/redoc/"):
        response = api_client.get(path)
        html = response.content.decode()
        assert response.status_code == 200
        assert "drf_spectacular_sidecar" in html
        assert "cdn.jsdelivr.net" not in html
