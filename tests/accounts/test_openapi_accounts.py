from __future__ import annotations

from collections import Counter
from typing import Any

import pytest
from drf_spectacular.generators import SchemaGenerator


@pytest.fixture(scope="module")
def schema() -> dict[str, Any]:
    generated: dict[str, Any] = SchemaGenerator().get_schema(request=None, public=True)
    return generated


def _operations(schema: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        operation["operationId"]: operation
        for path_item in schema["paths"].values()
        for operation in path_item.values()
        if isinstance(operation, dict) and "operationId" in operation
    }


EXPECTED_OPERATIONS = {
    "auth_token_obtain",
    "auth_token_refresh",
    "auth_logout",
    "auth_api_key_introspect",
    "me_retrieve",
    "me_update",
    "me_password_change",
    "users_list",
    "users_create",
    "users_retrieve",
    "users_update",
    "users_roles_assign",
    "users_roles_revoke",
    "roles_list",
    "roles_create",
    "roles_retrieve",
    "roles_update",
    "roles_delete",
    "permissions_list",
    "service_accounts_list",
    "service_accounts_create",
    "service_accounts_retrieve",
    "service_accounts_update",
    "api_keys_list",
    "api_keys_create",
    "api_keys_revoke",
}


def test_operation_ids_are_explicit_and_unique(schema: dict[str, Any]) -> None:
    ids = [
        operation["operationId"]
        for path_item in schema["paths"].values()
        for operation in path_item.values()
        if isinstance(operation, dict)
    ]
    assert set(ids) >= EXPECTED_OPERATIONS
    assert [name for name, count in Counter(ids).items() if count > 1] == []


def test_security_schemes_document_both_credential_types(schema: dict[str, Any]) -> None:
    schemes = schema["components"]["securitySchemes"]

    assert schemes["jwtAuth"]["scheme"] == "bearer"
    assert schemes["apiKeyAuth"] == {
        "type": "apiKey",
        "in": "header",
        "name": "X-API-Key",
        "description": schemes["apiKeyAuth"]["description"],
    }


def test_each_endpoint_declares_the_right_credential(schema: dict[str, Any]) -> None:
    operations = _operations(schema)

    assert operations["auth_api_key_introspect"]["security"] == [{"apiKeyAuth": []}]
    assert operations["me_retrieve"]["security"] == [{"jwtAuth": []}]
    assert operations["users_list"]["security"] == [{"jwtAuth": []}]
    assert "security" not in operations["auth_token_obtain"] or operations["auth_token_obtain"][
        "security"
    ] in ([], [{}])


def test_problem_responses_are_documented(schema: dict[str, Any]) -> None:
    operations = _operations(schema)

    def problem_codes(operation_id: str) -> set[str]:
        responses = operations[operation_id]["responses"]
        return {
            code
            for code, response in responses.items()
            if "application/problem+json" in response.get("content", {})
        }

    assert {"401", "403", "429"} <= problem_codes("users_list")
    assert {"400", "401", "403", "409"} <= problem_codes("users_create")
    assert {"401", "403", "404"} <= problem_codes("users_retrieve")
    assert "401" in problem_codes("auth_token_obtain")
    assert "404" not in problem_codes("users_list")


def test_lists_are_cursor_paginated_in_the_schema(schema: dict[str, Any]) -> None:
    response = _operations(schema)["users_list"]["responses"]["200"]
    ref = response["content"]["application/json"]["schema"]["$ref"].rsplit("/", 1)[-1]
    paginated = schema["components"]["schemas"][ref]

    assert {"next", "previous", "results"} <= set(paginated["properties"])
    parameters = {p["name"] for p in _operations(schema)["users_list"]["parameters"]}
    assert {"cursor", "page_size", "email", "is_active", "role"} <= parameters


def test_request_and_response_components_are_split(schema: dict[str, Any]) -> None:
    components = schema["components"]["schemas"]

    assert "UserCreateRequest" in components
    assert "User" in components
    assert "password" not in components["User"]["properties"]
    assert "key" not in components["APIKey"]["properties"]
    assert "key" in components["APIKeyIssued"]["properties"]
