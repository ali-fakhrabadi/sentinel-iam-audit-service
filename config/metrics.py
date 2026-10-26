"""Bearer-token protected Prometheus endpoint.

Metrics reveal traffic patterns and internal names, so ``/metrics`` requires
``Authorization: Bearer <METRICS_AUTH_TOKEN>``. Prometheus supports this natively
(``authorization.credentials`` in the scrape config). With no token configured the
endpoint is disabled and returns 404.

The response combines:
* process metrics (django-prometheus, application counters), aggregated across
  Gunicorn workers in multiprocess mode;
* gauges computed from PostgreSQL at scrape time (``METRICS_DB_COLLECTORS``), which
  describe work done by Celery workers that Prometheus does not scrape directly.
"""

from __future__ import annotations

import hmac
import logging
import os
from functools import lru_cache

import prometheus_client
from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.utils.module_loading import import_string
from prometheus_client import CollectorRegistry, multiprocess
from prometheus_client.registry import Collector

from config.exceptions import problem_response

logger = logging.getLogger("sentinel.metrics")


@lru_cache(maxsize=1)
def _database_registry() -> CollectorRegistry:
    registry = CollectorRegistry(auto_describe=False)
    for path in settings.METRICS_DB_COLLECTORS:
        collector: Collector = import_string(path)()
        registry.register(collector)
    return registry


def _process_registry() -> CollectorRegistry:
    if "PROMETHEUS_MULTIPROC_DIR" in os.environ:
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
        return registry
    return prometheus_client.REGISTRY


def render_metrics() -> bytes:
    output = prometheus_client.generate_latest(_process_registry())
    try:
        output += prometheus_client.generate_latest(_database_registry())
    except Exception:
        # Database gauges are best effort: process metrics must still be served.
        logger.warning("Database metrics collection failed", exc_info=True)
    return output


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

    return HttpResponse(render_metrics(), content_type=prometheus_client.CONTENT_TYPE_LATEST)
