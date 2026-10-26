"""RFC 7807 (``application/problem+json``) error responses for the whole API.

Every error, whether raised by DRF, by Django before DRF runs, or by an unexpected
bug, is rendered with the same shape::

    {
      "type": "urn:sentinel:problem:validation-error",
      "title": "Request validation failed",
      "status": 400,
      "detail": "One or more fields are invalid.",
      "instance": "/api/v1/audit/events/bulk/",
      "request_id": "3f1c...",
      "errors": [{"field": "events.0.severity", "message": "...", "code": "invalid_choice"}]
    }

Unexpected exceptions are logged with their stack trace; the client only receives
a generic message and the request ID to quote to support.
"""

from __future__ import annotations

import logging
from typing import Any

from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from django.core.exceptions import RequestDataTooBig, SuspiciousOperation
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import OperationalError
from django.http import Http404, HttpRequest, JsonResponse
from rest_framework import exceptions, status
from rest_framework.response import Response
from rest_framework.serializers import as_serializer_error
from rest_framework.views import exception_handler as drf_exception_handler

from config.logging import get_request_id

logger = logging.getLogger("sentinel.errors")

PROBLEM_CONTENT_TYPE = "application/problem+json"
PROBLEM_TYPE_PREFIX = "urn:sentinel:problem:"

# DRF error code -> (problem type slug, human-readable title)
_PROBLEM_TYPES: dict[str, tuple[str, str]] = {
    "invalid": ("validation-error", "Request validation failed"),
    "parse_error": ("malformed-request", "Malformed request body"),
    "not_authenticated": ("not-authenticated", "Authentication required"),
    "authentication_failed": ("authentication-failed", "Authentication failed"),
    "token_not_valid": ("invalid-token", "Invalid or expired token"),
    "permission_denied": ("permission-denied", "Permission denied"),
    "not_found": ("not-found", "Resource not found"),
    "method_not_allowed": ("method-not-allowed", "Method not allowed"),
    "not_acceptable": ("not-acceptable", "Not acceptable"),
    "unsupported_media_type": ("unsupported-media-type", "Unsupported media type"),
    "throttled": ("rate-limited", "Too many requests"),
    "payload_too_large": ("payload-too-large", "Request body too large"),
    "conflict": ("conflict", "Conflict with the current state of the resource"),
    "service_unavailable": ("service-unavailable", "Service temporarily unavailable"),
    "bad_request": ("bad-request", "Bad request"),
    "server_error": ("internal-error", "Internal server error"),
}


class PayloadTooLarge(exceptions.APIException):
    status_code = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
    default_detail = "The request body exceeds the maximum allowed size."
    default_code = "payload_too_large"


class BadRequest(exceptions.APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "The request could not be processed."
    default_code = "bad_request"


class ServiceUnavailable(exceptions.APIException):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = "The service is temporarily unavailable; retry later."
    default_code = "service_unavailable"


class Conflict(exceptions.APIException):
    """The request is valid but clashes with existing state (duplicates, in-use objects)."""

    status_code = status.HTTP_409_CONFLICT
    default_detail = "The request conflicts with the current state of the resource."
    default_code = "conflict"


def build_problem(
    *,
    status_code: int,
    code: str,
    detail: str,
    instance: str | None,
    errors: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Assemble a problem document for ``code`` (a DRF-style error code)."""
    slug, title = _PROBLEM_TYPES.get(code, (code.replace("_", "-"), "Request failed"))
    problem: dict[str, Any] = {
        "type": f"{PROBLEM_TYPE_PREFIX}{slug}",
        "title": title,
        "status": status_code,
        "detail": detail,
    }
    if instance:
        problem["instance"] = instance
    request_id = get_request_id()
    if request_id:
        problem["request_id"] = request_id
    if errors:
        problem["errors"] = errors
    return problem


def flatten_validation_errors(detail: Any, path: str = "") -> list[dict[str, str]]:
    """Turn DRF's nested error structure into a flat list of field errors.

    Nested fields and list positions become dotted paths, e.g. ``events.3.metadata``.
    Errors not tied to a field use the path ``non_field_errors``.
    """
    if isinstance(detail, dict):
        flattened: list[dict[str, str]] = []
        for key, value in detail.items():
            child = str(key) if not path else f"{path}.{key}"
            flattened.extend(flatten_validation_errors(value, child))
        return flattened
    if isinstance(detail, list):
        if all(isinstance(item, exceptions.ErrorDetail) for item in detail):
            return [
                {
                    "field": path or "non_field_errors",
                    "message": str(item),
                    "code": str(item.code),
                }
                for item in detail
            ]
        flattened = []
        for index, item in enumerate(detail):
            if item:  # DRF uses empty dicts for list items without errors
                flattened.extend(
                    flatten_validation_errors(item, f"{path}.{index}" if path else str(index))
                )
        return flattened
    code = getattr(detail, "code", "invalid")
    return [{"field": path or "non_field_errors", "message": str(detail), "code": str(code)}]


def _translate_django_exception(exc: Exception) -> Exception:
    """Map Django exceptions that DRF does not handle onto API exceptions.

    Services raise Django's ValidationError so they stay independent of DRF; it is
    converted here into the same field-level problem response as serializer errors.
    """
    if isinstance(exc, DjangoValidationError):
        return exceptions.ValidationError(detail=as_serializer_error(exc))
    if isinstance(exc, RequestDataTooBig):
        return PayloadTooLarge()
    if isinstance(exc, SuspiciousOperation):
        return BadRequest()
    if isinstance(exc, OperationalError):
        # Lost connection or statement timeout: transient, so the client may retry. The
        # cause is logged here because the 503 response deliberately does not carry it.
        logger.warning("Database operation failed; answering 503", exc_info=exc)
        return ServiceUnavailable()
    return exc


def problem_exception_handler(exc: Exception, context: dict[str, Any]) -> Response:
    """DRF ``EXCEPTION_HANDLER`` producing RFC 7807 responses."""
    exc = _translate_django_exception(exc)
    request = context.get("request")
    instance = request.path if request is not None else None

    response = drf_exception_handler(exc, context)
    if response is None:
        logger.exception("Unhandled exception while processing %s", instance)
        response = Response(
            build_problem(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                code="server_error",
                detail="An unexpected error occurred. Quote the request_id when reporting it.",
                instance=instance,
            ),
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
        response.content_type = PROBLEM_CONTENT_TYPE
        return response

    if isinstance(exc, exceptions.ValidationError):
        problem = build_problem(
            status_code=response.status_code,
            code="invalid",
            detail="One or more fields are invalid.",
            instance=instance,
            errors=flatten_validation_errors(exc.detail),
        )
    else:
        code = _primary_code(exc)
        problem = build_problem(
            status_code=response.status_code,
            code=code,
            detail=_primary_detail(exc),
            instance=instance,
        )
        wait = getattr(exc, "wait", None) if isinstance(exc, exceptions.Throttled) else None
        if wait is not None:
            problem["retry_after"] = int(wait)

    response.data = problem
    response.content_type = PROBLEM_CONTENT_TYPE
    return response


def _primary_code(exc: Exception) -> str:
    if isinstance(exc, Http404):
        return "not_found"
    if isinstance(exc, DjangoPermissionDenied):
        return "permission_denied"
    if isinstance(exc, exceptions.APIException):
        codes = exc.get_codes()
        if isinstance(codes, str):
            return codes
        # Some libraries (e.g. SimpleJWT's InvalidToken) raise a dict detail with a "code".
        if isinstance(codes, dict) and isinstance(codes.get("code"), str):
            return str(codes["code"])
        return str(exc.default_code)
    return "server_error"


def _primary_detail(exc: Exception) -> str:
    if isinstance(exc, exceptions.APIException):
        if isinstance(exc.detail, str):
            return str(exc.detail)
        # Dict details may carry token internals in extra keys; only "detail" is exposed.
        if isinstance(exc.detail, dict) and isinstance(exc.detail.get("detail"), str):
            return str(exc.detail["detail"])
        return str(exc.default_detail)
    if isinstance(exc, Http404):
        return "The requested resource was not found."
    if isinstance(exc, DjangoPermissionDenied):
        # Services raise PermissionDenied with deliberate, user-facing explanations.
        message = str(exc)
        return message or "You do not have permission to perform this action."
    return "The request could not be processed."


def problem_response(
    request: HttpRequest, *, status_code: int, code: str, detail: str
) -> JsonResponse:
    """Problem response for plain Django views and Django's error handlers."""
    return JsonResponse(
        build_problem(status_code=status_code, code=code, detail=detail, instance=request.path),
        status=status_code,
        content_type=PROBLEM_CONTENT_TYPE,
    )
