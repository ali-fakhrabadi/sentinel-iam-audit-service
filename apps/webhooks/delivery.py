"""The HTTP side of one webhook attempt and the classification of its result."""

from __future__ import annotations

import time
from dataclasses import dataclass
from http import HTTPStatus
from typing import Literal

import httpx
from django.conf import settings

from apps.webhooks.ssrf import Destination

Outcome = Literal["succeeded", "retryable", "permanent"]
USER_AGENT = "Sentinel-Webhooks/1.0"
# Request timeout (408), throttling (429) and server errors are worth retrying.
_RETRYABLE_STATUS = frozenset(
    {HTTPStatus.REQUEST_TIMEOUT, HTTPStatus.TOO_EARLY, HTTPStatus.TOO_MANY_REQUESTS}
)


@dataclass(frozen=True, slots=True)
class AttemptResult:
    outcome: Outcome
    status_code: int | None
    error: str
    duration_seconds: float


def classify_status(status_code: int) -> tuple[Outcome, str]:
    if HTTPStatus.OK <= status_code < HTTPStatus.MULTIPLE_CHOICES:
        return "succeeded", ""
    if status_code in _RETRYABLE_STATUS or status_code >= HTTPStatus.INTERNAL_SERVER_ERROR:
        return "retryable", f"http_{status_code}"
    if status_code < HTTPStatus.BAD_REQUEST:
        return "permanent", "redirect_not_followed"
    return "permanent", f"http_{status_code}"


def send(destination: Destination, *, body: bytes, headers: dict[str, str]) -> AttemptResult:
    """POST ``body`` to the pinned address of ``destination``.

    The response body is never read beyond the status line: receivers' error pages
    must not end up in Sentinel's database or logs.
    """
    timeout = httpx.Timeout(
        connect=settings.WEBHOOK_CONNECT_TIMEOUT_SECONDS,
        read=settings.WEBHOOK_READ_TIMEOUT_SECONDS,
        write=settings.WEBHOOK_READ_TIMEOUT_SECONDS,
        pool=settings.WEBHOOK_CONNECT_TIMEOUT_SECONDS,
    )
    request_headers = {
        **headers,
        "Host": destination.host_header,
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    }
    extensions = {"sni_hostname": destination.host} if destination.scheme == "https" else {}
    started = time.perf_counter()
    # trust_env=False: proxy variables would bypass the pinned, validated address.
    with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False) as client:
        request = client.build_request(
            "POST",
            destination.pinned_url(),
            content=body,
            headers=request_headers,
            extensions=extensions,
        )
        try:
            response = client.send(request, stream=True)
            response.close()
        except httpx.TimeoutException:
            return AttemptResult("retryable", None, "timeout", time.perf_counter() - started)
        except httpx.TransportError:
            return AttemptResult(
                "retryable", None, "connection_error", time.perf_counter() - started
            )
    outcome, error = classify_status(response.status_code)
    return AttemptResult(outcome, response.status_code, error, time.perf_counter() - started)
