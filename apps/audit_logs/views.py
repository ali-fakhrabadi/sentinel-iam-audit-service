"""HTTP layer for the audit log.

Authentication policy:
* ingestion (POST) accepts only service-account API keys with ``audit:write``;
* querying (GET) accepts users with ``audit:read`` (see everything) and API keys
  with ``audit:read`` (see only the events they produced).
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, ClassVar

from django.conf import settings
from django.db import DatabaseError
from django.utils import timezone
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import exceptions, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import BaseThrottle, ScopedRateThrottle
from rest_framework.utils.urls import replace_query_param
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from apps.accounts.authentication import APIKeyAuthentication
from apps.accounts.catalog import PermissionCode
from apps.accounts.models import APIKey, ServiceAccount
from apps.accounts.permissions import (
    AllowedPrincipalTypes,
    HasRequiredPermissions,
    IsServicePrincipal,
)
from apps.audit_logs import metrics, selectors, services
from apps.audit_logs.pagination import Cursor
from apps.audit_logs.selectors import EventQuery
from apps.audit_logs.serializers import (
    AuditEventInputSerializer,
    AuditEventPageSerializer,
    AuditEventQuerySerializer,
    AuditEventSerializer,
    BulkIngestRequestSerializer,
    BulkIngestResponseSerializer,
    SingleIngestResponseSerializer,
)
from apps.audit_logs.services import EventInput, ItemResult
from config.exceptions import ServiceUnavailable, flatten_validation_errors
from config.openapi import problem_response

logger = logging.getLogger("sentinel.audit")
TAG = "Audit events"
_NOTHING_STORED = (
    "No events were stored. Retry the whole request; idempotency keys make retries safe."
)


def _service_scope(request: Request) -> ServiceAccount | None:
    """API keys only see their own events; users with audit:read see all."""
    if isinstance(request.auth, APIKey):
        return request.auth.service_account
    return None


def _producer(request: Request) -> ServiceAccount:
    if not isinstance(request.auth, APIKey):  # enforced by permission classes
        raise exceptions.PermissionDenied("Ingestion requires an API key.")
    return request.auth.service_account


def _ingest(request: Request, items: list[tuple[int, EventInput]]) -> list[ItemResult]:
    try:
        return services.ingest_events(
            producer=_producer(request), items=items, received_at=timezone.now()
        )
    except DatabaseError as exc:
        logger.exception("Audit ingestion failed; the transaction was rolled back")
        raise ServiceUnavailable(_NOTHING_STORED) from exc


class AuditEventCollectionView(APIView):
    authentication_classes = (JWTAuthentication, APIKeyAuthentication)
    permission_classes = (IsAuthenticated, AllowedPrincipalTypes, HasRequiredPermissions)
    allowed_principals: ClassVar[dict[str, set[str]]] = {
        "GET": {"user", "service"},
        "POST": {"service"},
    }
    required_permissions: ClassVar[dict[str, tuple[str, ...]]] = {
        "GET": (PermissionCode.AUDIT_READ,),
        "POST": (PermissionCode.AUDIT_WRITE,),
    }

    def get_throttles(self) -> list[BaseThrottle]:
        if self.request.method == "POST":
            throttle = ScopedRateThrottle()
            self.throttle_scope = "ingest"
            return [throttle]
        return super().get_throttles()

    @extend_schema(
        operation_id="audit_events_list",
        tags=[TAG],
        summary="Search audit events (newest first, cursor paginated)",
        description="Filters combine with AND. The time window defaults to the last 30 days "
        "and is limited to 90. Pagination is keyset-based on (created_at, id), so pages stay "
        "stable while new events arrive. API keys only see events they produced.",
        parameters=[AuditEventQuerySerializer],
        responses=AuditEventPageSerializer,
    )
    def get(self, request: Request) -> Response:
        params = AuditEventQuerySerializer(data=request.query_params)
        params.is_valid(raise_exception=True)
        data = params.validated_data
        cursor = Cursor.decode(data["cursor"]) if data.get("cursor") else None
        query = EventQuery(
            created_after=data["created_after"],
            created_before=data["created_before"],
            actor_id=data.get("actor_id"),
            action=data.get("action"),
            action_prefix=data.get("action_prefix"),
            resource_type=data.get("resource_type"),
            resource_id=data.get("resource_id"),
            severities=tuple(sorted(data.get("severity") or ())),
            ip_address=data.get("ip_address"),
            metadata_contains=data.get("metadata_contains") or {},
        )
        events, next_cursor = selectors.search_events(
            query,
            scope=_service_scope(request),
            cursor=cursor,
            page_size=data.get("page_size") or settings.AUDIT_QUERY_DEFAULT_PAGE_SIZE,
        )
        token = next_cursor.encode() if next_cursor else None
        return Response(
            {
                "results": AuditEventSerializer(events, many=True).data,
                "next_cursor": token,
                "next": replace_query_param(request.build_absolute_uri(), "cursor", token)
                if token
                else None,
            }
        )

    @extend_schema(
        operation_id="audit_events_create",
        tags=[TAG],
        summary="Ingest one audit event (API key with audit:write)",
        request=AuditEventInputSerializer,
        responses={
            201: SingleIngestResponseSerializer,
            200: OpenApiResponse(SingleIngestResponseSerializer, description="Duplicate key"),
            503: problem_response("Nothing was stored; retry"),
        },
    )
    def post(self, request: Request) -> Response:
        serializer = AuditEventInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        [result] = _ingest(request, [(0, serializer.to_event_input())])
        return Response(
            {"id": result.event_id, "status": result.status},
            status=status.HTTP_201_CREATED if result.status == "accepted" else status.HTTP_200_OK,
        )


class AuditEventBulkView(APIView):
    authentication_classes = (APIKeyAuthentication,)
    permission_classes = (IsServicePrincipal, HasRequiredPermissions)
    required_permissions: ClassVar[dict[str, tuple[str, ...]]] = {
        "POST": (PermissionCode.AUDIT_WRITE,)
    }
    throttle_classes = (ScopedRateThrottle,)
    throttle_scope = "ingest"

    @extend_schema(
        operation_id="audit_events_bulk_create",
        tags=[TAG],
        summary="Ingest up to 500 audit events with per-item results",
        description="Each item is validated independently. Valid items are stored in a single "
        "transaction (all of them or none); invalid ones are reported as `rejected` with field "
        "errors. A 503 means nothing was stored. Items with an `idempotency_key` already used "
        "by this service account are reported as `duplicate` with the original event ID.",
        request=BulkIngestRequestSerializer,
        responses={
            200: BulkIngestResponseSerializer,
            503: problem_response("Nothing was stored; retry the whole batch"),
        },
    )
    def post(self, request: Request) -> Response:
        raw_events = self._envelope(request.data)
        rejected: dict[int, list[dict[str, str]]] = {}
        valid: list[tuple[int, EventInput]] = []
        for index, raw in enumerate(raw_events):
            serializer = AuditEventInputSerializer(data=raw)
            if serializer.is_valid():
                valid.append((index, serializer.to_event_input()))
            else:
                rejected[index] = flatten_validation_errors(serializer.errors)

        metrics.record_rejected(len(rejected))
        stored = {result.index: result for result in _ingest(request, valid)} if valid else {}
        results: list[dict[str, Any]] = []
        for index in range(len(raw_events)):
            if index in rejected:
                results.append(
                    {
                        "index": index,
                        "status": "rejected",
                        "event_id": None,
                        "errors": rejected[index],
                    }
                )
            else:
                result = stored[index]
                results.append(
                    {"index": index, "status": result.status, "event_id": result.event_id}
                )
        return Response(
            {
                "accepted": sum(1 for r in results if r["status"] == "accepted"),
                "duplicates": sum(1 for r in results if r["status"] == "duplicate"),
                "rejected": len(rejected),
                "results": results,
            }
        )

    @staticmethod
    def _envelope(data: Any) -> list[Any]:
        if (
            not isinstance(data, dict)
            or set(data) != {"events"}
            or not isinstance(data["events"], list)
        ):
            raise exceptions.ValidationError(
                {"events": ["Send an object with a single 'events' list."]}
            )
        events: list[Any] = data["events"]
        maximum: int = settings.AUDIT_BULK_MAX_EVENTS
        if not events:
            raise exceptions.ValidationError({"events": ["Send at least one event."]})
        if len(events) > maximum:
            raise exceptions.ValidationError(
                {"events": [f"Send at most {maximum} events per request."]}
            )
        return events


class AuditEventDetailView(APIView):
    authentication_classes = (JWTAuthentication, APIKeyAuthentication)
    permission_classes = (IsAuthenticated, AllowedPrincipalTypes, HasRequiredPermissions)
    allowed_principals: ClassVar[dict[str, set[str]]] = {"GET": {"user", "service"}}
    required_permissions: ClassVar[dict[str, tuple[str, ...]]] = {
        "GET": (PermissionCode.AUDIT_READ,)
    }

    @extend_schema(
        operation_id="audit_events_retrieve",
        tags=[TAG],
        summary="Get one audit event",
        responses=AuditEventSerializer,
    )
    def get(self, request: Request, event_id: uuid.UUID) -> Response:
        event = selectors.event_get(event_id, scope=_service_scope(request))
        return Response(AuditEventSerializer(event).data)
