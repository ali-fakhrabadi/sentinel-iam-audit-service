"""Django-level error handlers (URLs that never reach a DRF view).

They keep 400/403/404/500 responses in the same RFC 7807 JSON format as the API,
instead of Django's default HTML pages.
"""

from __future__ import annotations

from django.http import HttpRequest, JsonResponse

from config.exceptions import problem_response


def bad_request(request: HttpRequest, exception: Exception) -> JsonResponse:
    return problem_response(
        request, status_code=400, code="bad_request", detail="The request could not be processed."
    )


def permission_denied(request: HttpRequest, exception: Exception) -> JsonResponse:
    return problem_response(
        request,
        status_code=403,
        code="permission_denied",
        detail="You do not have permission to perform this action.",
    )


def page_not_found(request: HttpRequest, exception: Exception) -> JsonResponse:
    return problem_response(
        request, status_code=404, code="not_found", detail="The requested resource was not found."
    )


def server_error(request: HttpRequest) -> JsonResponse:
    return problem_response(
        request,
        status_code=500,
        code="server_error",
        detail="An unexpected error occurred. Quote the request_id when reporting it.",
    )
