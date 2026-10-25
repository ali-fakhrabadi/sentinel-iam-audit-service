"""Bearer-token protected Prometheus endpoint.

Metrics reveal traffic patterns and internal names, so ``/metrics`` requires
``Authorization: Bearer <METRICS_AUTH_TOKEN>``. Prometheus supports this natively
(``authorization.credentials`` in the scrape config). With no token configured the
endpoint is disabled and returns 404.
"""

from __future__ import annotations

import hmac

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django_prometheus.exports import ExportToDjangoView

from config.exceptions import problem_response


def metrics_view(request: HttpRequest) -> HttpResponse:
    expected: str = settings.METRICS_AUTH_TOKEN
    if not expected:
        return problem_response(
            request,
            status_code=404,
            code="not_found",
            detail="The requested resource was not found.",
        )
    if request.method != "GET":
        response = problem_response(
            request,
            status_code=405,
            code="method_not_allowed",
            detail=f'Method "{request.method}" not allowed.',
        )
        response["Allow"] = "GET"
        return response

    scheme, _, credentials = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(
        credentials.strip().encode(), expected.encode()
    ):
        response = problem_response(
            request,
            status_code=401,
            code="not_authenticated",
            detail="A valid bearer token is required to read metrics.",
        )
        response["WWW-Authenticate"] = 'Bearer realm="metrics"'
        return response

    exported: HttpResponse = ExportToDjangoView(request)
    return exported
