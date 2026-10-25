"""Request correlation and access logging."""

from __future__ import annotations

import logging
import re
import time
import uuid
from collections.abc import Callable

from django.conf import settings
from django.http import HttpRequest, HttpResponse

from config.exceptions import problem_response
from config.logging import request_id_var

REQUEST_ID_HEADER = "X-Request-ID"
# Accept caller-supplied IDs only if they are short and contain no characters that
# could be abused for header or log injection.
_VALID_REQUEST_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")
# Probes and scrapes run every few seconds; log them at DEBUG to keep INFO useful.
_QUIET_PATH_PREFIXES = ("/health/", "/metrics")
_MAX_USER_AGENT_LENGTH = 256

access_logger = logging.getLogger("sentinel.access")


def resolve_request_id(candidate: str | None) -> str:
    """Return the caller's request ID when valid, otherwise a new random one."""
    if candidate and _VALID_REQUEST_ID.fullmatch(candidate):
        return candidate
    return uuid.uuid4().hex


class RequestContextMiddleware:
    """Assign a request ID, echo it in ``X-Request-ID`` and write one access log line.

    The query string is never logged because clients sometimes put credentials in it.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        request_id = resolve_request_id(request.headers.get(REQUEST_ID_HEADER))
        token = request_id_var.set(request_id)
        started = time.perf_counter()
        try:
            response = self.get_response(request)
            response[REQUEST_ID_HEADER] = request_id
            self._log(request, response, (time.perf_counter() - started) * 1000)
            return response
        finally:
            request_id_var.reset(token)

    @staticmethod
    def _log(request: HttpRequest, response: HttpResponse, duration_ms: float) -> None:
        level = logging.DEBUG if request.path.startswith(_QUIET_PATH_PREFIXES) else logging.INFO
        if not access_logger.isEnabledFor(level):
            return
        user = getattr(request, "user", None)
        user_id = str(user.pk) if user is not None and user.is_authenticated else None
        access_logger.log(
            level,
            "%s %s %s",
            request.method,
            request.path,
            response.status_code,
            extra={
                "http_method": request.method,
                "path": request.path,
                "status_code": response.status_code,
                "duration_ms": round(duration_ms, 2),
                "client_ip": request.META.get("REMOTE_ADDR"),
                "user_agent": request.headers.get("User-Agent", "")[:_MAX_USER_AGENT_LENGTH],
                "user_id": user_id,
            },
        )


class RequestSizeLimitMiddleware:
    """Reject bodies larger than ``API_MAX_REQUEST_BYTES`` before anything reads them.

    DRF parsers read the WSGI stream directly, so Django's
    ``DATA_UPLOAD_MAX_MEMORY_SIZE`` check does not protect JSON endpoints. The
    declared Content-Length is checked instead; under WSGI a request without it is
    read as an empty body.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response
        self.max_bytes: int = settings.API_MAX_REQUEST_BYTES

    def __call__(self, request: HttpRequest) -> HttpResponse:
        raw_length = request.META.get("CONTENT_LENGTH") or "0"
        try:
            content_length = int(raw_length)
        except ValueError:
            return problem_response(
                request,
                status_code=400,
                code="bad_request",
                detail="The Content-Length header is invalid.",
            )
        if content_length > self.max_bytes:
            return problem_response(
                request,
                status_code=413,
                code="payload_too_large",
                detail=f"The request body exceeds the maximum of {self.max_bytes} bytes.",
            )
        return self.get_response(request)
