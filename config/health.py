"""Liveness and readiness probes.

* ``/health/live/``  answers as long as the process can serve requests. It never
  touches PostgreSQL or Redis, so a database outage does not make an orchestrator
  restart healthy application containers.
* ``/health/ready/`` checks PostgreSQL and Redis with short timeouts and returns
  503 while either is unavailable, so load balancers stop routing traffic.

Responses never include error messages, hostnames or connection strings; failures
are logged server-side with the request ID instead.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any

import redis
from django.conf import settings
from django.db import connections
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from config.schemas import LivenessSerializer, ReadinessSerializer

logger = logging.getLogger("sentinel.health")


def _timed(check: Callable[[], None], name: str) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        check()
    except Exception:
        logger.warning("Readiness check failed: %s", name, exc_info=True)
        return {"status": "error", "latency_ms": None}
    return {"status": "ok", "latency_ms": round((time.perf_counter() - started) * 1000, 2)}


def check_database() -> None:
    with connections["default"].cursor() as cursor:
        cursor.execute("SELECT 1")
        cursor.fetchone()


def check_redis() -> None:
    timeout = settings.HEALTH_CHECK_TIMEOUT_SECONDS
    client = redis.Redis.from_url(
        settings.CELERY_BROKER_URL,
        socket_connect_timeout=timeout,
        socket_timeout=timeout,
    )
    try:
        client.ping()
    finally:
        client.close()


class _ProbeView(APIView):
    """Probes are public, unauthenticated and never rate limited."""

    authentication_classes = ()
    permission_classes = (AllowAny,)
    throttle_classes = ()


class LivenessView(_ProbeView):
    @extend_schema(
        operation_id="health_live",
        tags=["Health"],
        summary="Liveness probe",
        description="Returns 200 while the process can serve requests. "
        "Does not check dependencies.",
        responses={200: LivenessSerializer},
        auth=[],
    )
    def get(self, request: Request) -> Response:
        return Response({"status": "ok"})


class ReadinessView(_ProbeView):
    @extend_schema(
        operation_id="health_ready",
        tags=["Health"],
        summary="Readiness probe",
        description="Checks PostgreSQL and Redis with bounded timeouts. Returns 503 while "
        "any dependency is unavailable. Error details are logged, never returned.",
        responses={
            200: ReadinessSerializer,
            503: OpenApiResponse(ReadinessSerializer, description="A dependency is unavailable"),
        },
        auth=[],
    )
    def get(self, request: Request) -> Response:
        checks = {
            "database": _timed(check_database, "database"),
            "redis": _timed(check_redis, "redis"),
        }
        ready = all(result["status"] == "ok" for result in checks.values())
        return Response(
            {"status": "ok" if ready else "unavailable", "checks": checks},
            status=status.HTTP_200_OK if ready else status.HTTP_503_SERVICE_UNAVAILABLE,
        )
