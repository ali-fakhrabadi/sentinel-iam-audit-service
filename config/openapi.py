"""OpenAPI generation tweaks shared by every endpoint.

``ProblemAutoSchema`` documents the RFC 7807 error responses each operation can
actually return, so generated TypeScript clients get typed error bodies without
every view repeating the same ``@extend_schema`` boilerplate:

* 400 for operations with a request body
* 401 and 403 for operations that require credentials
* 404 for operations addressing a resource by path parameter
* 429 for rate-limited operations
"""

from __future__ import annotations

from typing import Any

from drf_spectacular.openapi import AutoSchema
from drf_spectacular.utils import OpenApiResponse

from config.exceptions import PROBLEM_CONTENT_TYPE
from config.schemas import ProblemDetailSerializer

_BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})


def problem_response(description: str) -> OpenApiResponse:
    """An explicit problem-details response for ``@extend_schema(responses=...)``."""
    return OpenApiResponse(response=ProblemDetailSerializer, description=description)


def _is_problem(serializer: Any) -> bool:
    target = serializer.response if isinstance(serializer, OpenApiResponse) else serializer
    return target is ProblemDetailSerializer or isinstance(target, ProblemDetailSerializer)


class ProblemAutoSchema(AutoSchema):
    def _get_response_for_code(
        self,
        serializer: Any,
        status_code: Any,
        media_types: Any = None,
        direction: Any = "response",
    ) -> Any:
        # Problem documents are served as application/problem+json, including the
        # ones views declare explicitly in @extend_schema.
        if _is_problem(serializer):
            media_types = [PROBLEM_CONTENT_TYPE]
        return super()._get_response_for_code(serializer, status_code, media_types, direction)

    def _get_response_bodies(self, direction: Any = "response") -> dict[str, Any]:
        responses: dict[str, Any] = super()._get_response_bodies(direction)
        if direction != "response":
            return responses
        for code, description in self._implicit_error_responses():
            if code not in responses:
                responses[code] = self._get_response_for_code(
                    problem_response(description),
                    code,
                    media_types=[PROBLEM_CONTENT_TYPE],
                    direction=direction,
                )
        return responses

    def _implicit_error_responses(self) -> list[tuple[str, str]]:
        errors: list[tuple[str, str]] = []
        if self.method in _BODY_METHODS:
            errors.append(("400", "Validation failed or the body is malformed"))
        # An empty requirement ({}) marks anonymous access as allowed.
        if any(requirement for requirement in self.get_auth()):
            errors.append(("401", "Missing, invalid or expired credentials"))
            errors.append(("403", "Authenticated, but not allowed to perform this action"))
        if "{" in self.path:
            errors.append(("404", "Resource not found"))
        if getattr(self.view, "throttle_classes", ()):
            errors.append(("429", "Rate limit exceeded; see retry_after"))
        return errors
