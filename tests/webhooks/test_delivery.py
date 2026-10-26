"""Outbox dispatch and delivery attempts, against a mocked HTTP receiver (respx)."""

from __future__ import annotations

import json
import logging
from datetime import timedelta
from typing import Any

import httpx
import pytest
import respx
from django.utils import timezone
from pytest_django import DjangoCaptureOnCommitCallbacks, Settings

from apps.accounts.models import ServiceAccount, User
from apps.audit_logs import services as audit_services
from apps.audit_logs.models import AuditEvent, OutboxMessage, OutboxStatus
from apps.audit_logs.services import EventInput
from apps.webhooks import services, tasks
from apps.webhooks.models import DeliveryStatus, WebhookDelivery, WebhookEndpoint
from apps.webhooks.signing import verify_signature
from tests.factories import create_endpoint, create_event, create_service_account

pytestmark = pytest.mark.django_db
RECEIVER = "https://93.184.216.34/sentinel"


@pytest.fixture
def enqueued(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, float]]:
    calls: list[tuple[str, float]] = []

    def apply_async(args: list[str], countdown: float = 0, **kwargs: Any) -> None:
        calls.append((args[0], countdown))

    monkeypatch.setattr(tasks.deliver_security_webhook_task, "apply_async", apply_async)
    return calls


@pytest.fixture
def producer() -> ServiceAccount:
    return create_service_account(name="edr-connector")


@pytest.fixture
def endpoint(dns: dict[str, list[str]]) -> tuple[WebhookEndpoint, str]:
    return create_endpoint(name="pager", min_severity="WARN")


@pytest.fixture
def delivery(endpoint: tuple[WebhookEndpoint, str], producer: ServiceAccount) -> WebhookDelivery:
    event = create_event(producer=producer, severity="CRITICAL", action="edr.malware.detected")
    return WebhookDelivery.objects.create(
        endpoint=endpoint[0], event=event, next_attempt_at=timezone.now()
    )


def _ingest(producer: ServiceAccount, *events: tuple[str, str]) -> list[AuditEvent]:
    items = [
        (index, EventInput(action=action, resource_type="host", severity=severity))
        for index, (action, severity) in enumerate(events)
    ]
    results = audit_services.ingest_events(
        producer=producer, items=items, received_at=timezone.now()
    )
    stored: list[AuditEvent] = []
    for result in results:
        assert result.event_id is not None
        stored.append(AuditEvent.objects.get(pk=result.event_id))
    return stored


# --------------------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------------------
def test_dispatch_routes_events_to_matching_endpoints_only(
    producer: ServiceAccount,
    enqueued: list[tuple[str, float]],
    django_capture_on_commit_callbacks: DjangoCaptureOnCommitCallbacks,
    sent_tasks: list[str],
) -> None:
    create_endpoint(name="all-warnings", min_severity="WARN")
    create_endpoint(name="critical-only", min_severity="CRITICAL")
    create_endpoint(name="iam-only", min_severity="WARN", action_prefixes=["iam"])
    create_endpoint(name="disabled", min_severity="WARN", is_active=False)
    _ingest(
        producer,
        ("auth.login.failed", "WARN"),
        ("storage.bucket.deleted", "CRITICAL"),
        ("iam.role.assigned", "WARN"),
        ("auth.login.succeeded", "INFO"),
    )

    with django_capture_on_commit_callbacks(execute=True):
        processed = services.dispatch_outbox()

    assert processed == 3  # INFO never entered the outbox
    counts = {
        endpoint.name: WebhookDelivery.objects.filter(endpoint=endpoint).count()
        for endpoint in WebhookEndpoint.objects.all()
    }
    assert counts == {"all-warnings": 3, "critical-only": 1, "iam-only": 1, "disabled": 0}
    assert len(enqueued) == 5
    assert not OutboxMessage.objects.filter(status=OutboxStatus.PENDING).exists()


def test_dispatch_is_idempotent(
    producer: ServiceAccount, enqueued: list[tuple[str, float]]
) -> None:
    create_endpoint(name="receiver", min_severity="WARN")
    _ingest(producer, ("auth.login.failed", "WARN"))

    services.dispatch_outbox()
    assert services.dispatch_outbox() == 0
    # Even if a message were processed again, the (endpoint, event) constraint holds.
    OutboxMessage.objects.update(status=OutboxStatus.PENDING)
    services.dispatch_outbox()

    assert WebhookDelivery.objects.count() == 1


@pytest.mark.parametrize(
    ("action", "matches"),
    [
        ("auth.login", True),
        ("auth.login.failed", True),
        ("auth.logins.failed", False),
        ("auth.log", False),
        ("storage.bucket.deleted", False),
    ],
)
def test_prefixes_match_whole_segments(action: str, matches: bool) -> None:
    endpoint = WebhookEndpoint(min_severity="WARN", action_prefixes=["auth.login"])
    event = AuditEvent(action=action, severity="CRITICAL")

    assert endpoint.matches(event) is matches


# --------------------------------------------------------------------------------------
# Successful delivery
# --------------------------------------------------------------------------------------
def test_successful_delivery_is_signed_pinned_and_recorded(
    delivery: WebhookDelivery, endpoint: tuple[WebhookEndpoint, str], respx_mock: respx.MockRouter
) -> None:
    _, secret = endpoint
    route = respx_mock.post(RECEIVER).mock(return_value=httpx.Response(204))

    outcome = services.attempt_delivery(delivery.id)

    assert outcome == "succeeded"
    delivery.refresh_from_db()
    assert (delivery.status, delivery.attempt_count, delivery.last_status_code) == (
        DeliveryStatus.SUCCEEDED,
        1,
        204,
    )
    assert delivery.completed_at is not None
    request = route.calls.last.request
    assert request.headers["Host"] == "hooks.example.com"
    assert request.extensions["sni_hostname"] == "hooks.example.com"
    assert request.headers["Content-Type"] == "application/json"
    event_id = str(delivery.event_id)
    assert request.headers["X-Sentinel-Event-Id"] == event_id
    assert request.headers["X-Sentinel-Delivery-Id"] == str(delivery.id)
    payload = json.loads(request.content)
    assert payload["type"] == "audit_event.created"
    assert payload["event"]["id"] == event_id
    assert payload["event"]["action"] == "edr.malware.detected"
    assert verify_signature(
        secret, request.headers["X-Sentinel-Signature"], event_id, request.content
    )


def test_rotated_secrets_sign_with_both_keys_during_the_grace_period(
    delivery: WebhookDelivery,
    endpoint: tuple[WebhookEndpoint, str],
    respx_mock: respx.MockRouter,
    superuser: User,
) -> None:
    hook, old_secret = endpoint
    new_secret = services.endpoint_rotate_secret(actor=superuser, endpoint=hook).secret
    route = respx_mock.post(RECEIVER).mock(return_value=httpx.Response(200))

    services.attempt_delivery(delivery.id)

    request = route.calls.last.request
    header = request.headers["X-Sentinel-Signature"]
    assert header.count("v1=") == 2
    for secret in (new_secret, old_secret):
        assert verify_signature(secret, header, str(delivery.event_id), request.content)


# --------------------------------------------------------------------------------------
# Failures and retries
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("side_effect", "error"),
    [
        (httpx.ConnectTimeout("timed out"), "timeout"),
        (httpx.ReadTimeout("timed out"), "timeout"),
        (httpx.ConnectError("refused"), "connection_error"),
        (httpx.Response(500), "http_500"),
        (httpx.Response(503), "http_503"),
        (httpx.Response(429), "http_429"),
        (httpx.Response(408), "http_408"),
    ],
)
def test_transient_failures_are_retried_with_backoff(
    delivery: WebhookDelivery,
    respx_mock: respx.MockRouter,
    enqueued: list[tuple[str, float]],
    django_capture_on_commit_callbacks: DjangoCaptureOnCommitCallbacks,
    side_effect: Any,
    error: str,
) -> None:
    respx_mock.post(RECEIVER).mock(side_effect=[side_effect])
    started = timezone.now()

    with django_capture_on_commit_callbacks(execute=True):
        outcome = services.attempt_delivery(delivery.id, now=started)

    assert outcome == "retrying"
    delivery.refresh_from_db()
    assert delivery.status == DeliveryStatus.RETRYING
    assert delivery.last_error == error
    assert delivery.next_attempt_at is not None
    delay = (delivery.next_attempt_at - started).total_seconds()
    assert 15 <= delay <= 30  # base 30 s, jitter 0.5-1.0 on the first retry
    [(enqueued_id, countdown)] = enqueued
    assert enqueued_id == str(delivery.id)
    assert abs(countdown - delay) < 1e-6


@pytest.mark.parametrize(
    ("response", "error"),
    [
        (httpx.Response(404), "http_404"),
        (httpx.Response(401), "http_401"),
        (
            httpx.Response(301, headers={"Location": "http://169.254.169.254/"}),
            "redirect_not_followed",
        ),
    ],
)
def test_permanent_failures_stop_immediately(
    delivery: WebhookDelivery, respx_mock: respx.MockRouter, response: httpx.Response, error: str
) -> None:
    route = respx_mock.post(RECEIVER).mock(return_value=response)

    outcome = services.attempt_delivery(delivery.id)

    assert outcome == "failed"
    delivery.refresh_from_db()
    assert (delivery.status, delivery.last_error) == (DeliveryStatus.FAILED, error)
    assert route.call_count == 1  # redirects are never followed


def test_retries_are_bounded(
    delivery: WebhookDelivery,
    respx_mock: respx.MockRouter,
    settings: Settings,
    enqueued: list[tuple[str, float]],
) -> None:
    settings.WEBHOOK_MAX_RETRIES = 2
    route = respx_mock.post(RECEIVER).mock(return_value=httpx.Response(503))
    moment = timezone.now()

    outcomes = []
    for _ in range(3):
        outcomes.append(services.attempt_delivery(delivery.id, now=moment))
        delivery.refresh_from_db()
        moment = (delivery.next_attempt_at or moment) + timedelta(seconds=1)

    assert outcomes == ["retrying", "retrying", "exhausted"]
    assert (delivery.status, delivery.attempt_count) == (DeliveryStatus.EXHAUSTED, 3)
    assert route.call_count == 3


def test_dns_rebinding_is_caught_at_delivery_time(
    delivery: WebhookDelivery, dns: dict[str, list[str]], respx_mock: respx.MockRouter
) -> None:
    dns["hooks.example.com"] = ["127.0.0.1"]  # changed after the endpoint was validated

    outcome = services.attempt_delivery(delivery.id)

    assert outcome == "failed"
    delivery.refresh_from_db()
    assert delivery.last_error == "private_address"
    assert len(respx_mock.calls) == 0


def test_disabled_endpoints_fail_their_pending_deliveries(
    delivery: WebhookDelivery, endpoint: tuple[WebhookEndpoint, str], respx_mock: respx.MockRouter
) -> None:
    hook, _ = endpoint
    hook.is_active = False
    hook.save()

    assert services.attempt_delivery(delivery.id) == "skipped"
    delivery.refresh_from_db()
    assert (delivery.status, delivery.last_error) == (DeliveryStatus.FAILED, "endpoint_disabled")
    assert len(respx_mock.calls) == 0


# --------------------------------------------------------------------------------------
# Idempotency under duplicate or early execution
# --------------------------------------------------------------------------------------
def _set(delivery: WebhookDelivery, **fields: Any) -> None:
    WebhookDelivery.objects.filter(pk=delivery.pk).update(**fields)


@pytest.mark.parametrize("case", ["succeeded", "exhausted", "retry_not_due", "live_lease"])
def test_duplicate_or_early_executions_do_nothing(
    delivery: WebhookDelivery, respx_mock: respx.MockRouter, case: str
) -> None:
    now = timezone.now()
    cases: dict[str, dict[str, Any]] = {
        "succeeded": {"status": DeliveryStatus.SUCCEEDED},
        "exhausted": {"status": DeliveryStatus.EXHAUSTED},
        "retry_not_due": {
            "status": DeliveryStatus.RETRYING,
            "next_attempt_at": now + timedelta(minutes=5),
        },
        "live_lease": {"status": DeliveryStatus.IN_PROGRESS, "last_attempt_at": now},
    }
    _set(delivery, **cases[case])

    assert services.attempt_delivery(delivery.id) == "skipped"
    assert len(respx_mock.calls) == 0


def test_abandoned_attempts_are_resumed_after_the_lease(
    delivery: WebhookDelivery, respx_mock: respx.MockRouter
) -> None:
    _set(
        delivery,
        status=DeliveryStatus.IN_PROGRESS,
        last_attempt_at=timezone.now() - timedelta(minutes=5),
    )
    respx_mock.post(RECEIVER).mock(return_value=httpx.Response(200))

    assert services.attempt_delivery(delivery.id) == "succeeded"


def test_reconciliation_requeues_due_and_abandoned_deliveries(
    endpoint: tuple[WebhookEndpoint, str],
    producer: ServiceAccount,
    enqueued: list[tuple[str, float]],
) -> None:
    hook, _ = endpoint
    now = timezone.now()

    def make(**fields: Any) -> WebhookDelivery:
        return WebhookDelivery.objects.create(
            endpoint=hook, event=create_event(producer=producer), **fields
        )

    due = make(status=DeliveryStatus.RETRYING, next_attempt_at=now - timedelta(seconds=5))
    abandoned = make(status=DeliveryStatus.IN_PROGRESS, last_attempt_at=now - timedelta(minutes=10))
    make(status=DeliveryStatus.RETRYING, next_attempt_at=now + timedelta(minutes=5))
    make(status=DeliveryStatus.IN_PROGRESS, last_attempt_at=now)
    make(status=DeliveryStatus.SUCCEEDED)

    assert services.requeue_due_deliveries(now=now) == 2
    assert {delivery_id for delivery_id, _ in enqueued} == {str(due.id), str(abandoned.id)}


# --------------------------------------------------------------------------------------
# Helpers, tasks and logging
# --------------------------------------------------------------------------------------
def test_backoff_grows_exponentially_with_jitter_and_a_cap(settings: Settings) -> None:
    settings.WEBHOOK_BACKOFF_BASE_SECONDS = 30
    settings.WEBHOOK_BACKOFF_MAX_SECONDS = 600

    for attempt in range(1, 12):
        ceiling = min(600, 30 * 2 ** (attempt - 1))
        assert ceiling * 0.5 <= services.backoff_seconds(attempt) <= ceiling


def test_task_wrappers_delegate_to_services(
    delivery: WebhookDelivery, respx_mock: respx.MockRouter, producer: ServiceAccount
) -> None:
    respx_mock.post(RECEIVER).mock(return_value=httpx.Response(200))
    _ingest(producer, ("auth.login.failed", "CRITICAL"))

    assert tasks.deliver_security_webhook_task.run(str(delivery.id)) == "succeeded"
    assert tasks.dispatch_outbox_task.run() == 1


def test_secrets_and_signatures_never_reach_the_logs(
    delivery: WebhookDelivery,
    endpoint: tuple[WebhookEndpoint, str],
    respx_mock: respx.MockRouter,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _, secret = endpoint
    route = respx_mock.post(RECEIVER).mock(return_value=httpx.Response(500))

    with caplog.at_level(logging.DEBUG):
        services.attempt_delivery(delivery.id)

    signature = route.calls.last.request.headers["X-Sentinel-Signature"]
    for record in caplog.records:
        rendered = record.getMessage() + str(record.__dict__)
        assert secret not in rendered
        assert signature not in rendered
