"""HTTP layer for webhook endpoints and delivery history (JWT users only)."""

from __future__ import annotations

import uuid
from typing import Any, ClassVar

from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response

from apps.accounts.catalog import PermissionCode
from apps.accounts.views import HumanAPIView, HumanGenericAPIView, request_actor
from apps.webhooks import selectors, services
from apps.webhooks.models import WebhookDelivery
from apps.webhooks.pagination import DeliveryCursorPagination
from apps.webhooks.serializers import (
    DeliveryQuerySerializer,
    WebhookDeliverySerializer,
    WebhookEndpointCreateSerializer,
    WebhookEndpointSerializer,
    WebhookEndpointUpdateSerializer,
    WebhookEndpointWithSecretSerializer,
)
from config.openapi import problem_response

TAG = "Webhooks"
_Required = dict[str, tuple[str, ...]]


def _with_secret(issued: services.IssuedSecret, *, status_code: int) -> Response:
    payload = {**WebhookEndpointSerializer(issued.endpoint).data, "secret": issued.secret}
    response = Response(payload, status=status_code)
    response["Cache-Control"] = "no-store"
    return response


class WebhookEndpointListCreateView(HumanAPIView):
    required_permissions: ClassVar[_Required] = {
        "GET": (PermissionCode.WEBHOOKS_READ,),
        "POST": (PermissionCode.WEBHOOKS_MANAGE,),
    }

    @extend_schema(
        operation_id="webhook_endpoints_list",
        tags=[TAG],
        summary="List webhook endpoints",
        responses=WebhookEndpointSerializer(many=True),
    )
    def get(self, request: Request) -> Response:
        return Response(WebhookEndpointSerializer(selectors.endpoint_list(), many=True).data)

    @extend_schema(
        operation_id="webhook_endpoints_create",
        tags=[TAG],
        summary="Create a webhook endpoint",
        description="The URL must be https on a public address (SSRF protection). The response "
        "contains the signing secret once.",
        request=WebhookEndpointCreateSerializer,
        responses={
            201: WebhookEndpointWithSecretSerializer,
            409: problem_response("Name already in use"),
        },
    )
    def post(self, request: Request) -> Response:
        serializer = WebhookEndpointCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        issued = services.endpoint_create(actor=request_actor(request), **serializer.validated_data)
        return _with_secret(issued, status_code=status.HTTP_201_CREATED)


class WebhookEndpointDetailView(HumanAPIView):
    required_permissions: ClassVar[_Required] = {
        "GET": (PermissionCode.WEBHOOKS_READ,),
        "PATCH": (PermissionCode.WEBHOOKS_MANAGE,),
    }

    @extend_schema(
        operation_id="webhook_endpoints_retrieve",
        tags=[TAG],
        summary="Get a webhook endpoint",
        responses=WebhookEndpointSerializer,
    )
    def get(self, request: Request, endpoint_id: uuid.UUID) -> Response:
        return Response(WebhookEndpointSerializer(selectors.endpoint_get(endpoint_id)).data)

    @extend_schema(
        operation_id="webhook_endpoints_update",
        tags=[TAG],
        summary="Update or disable a webhook endpoint",
        request=WebhookEndpointUpdateSerializer,
        responses=WebhookEndpointSerializer,
    )
    def patch(self, request: Request, endpoint_id: uuid.UUID) -> Response:
        serializer = WebhookEndpointUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        endpoint = services.endpoint_update(
            actor=request_actor(request),
            endpoint=selectors.endpoint_get(endpoint_id),
            **serializer.validated_data,
        )
        return Response(WebhookEndpointSerializer(endpoint).data)


class WebhookSecretRotateView(HumanAPIView):
    required_permissions: ClassVar[_Required] = {"POST": (PermissionCode.WEBHOOKS_MANAGE,)}

    @extend_schema(
        operation_id="webhook_endpoints_rotate_secret",
        tags=[TAG],
        summary="Rotate the signing secret",
        description="Returns the new secret once. For the grace period (24 h by default) "
        "deliveries carry signatures for both the new and the previous secret.",
        request=None,
        responses=WebhookEndpointWithSecretSerializer,
    )
    def post(self, request: Request, endpoint_id: uuid.UUID) -> Response:
        issued = services.endpoint_rotate_secret(
            actor=request_actor(request), endpoint=selectors.endpoint_get(endpoint_id)
        )
        return _with_secret(issued, status_code=status.HTTP_200_OK)


class WebhookDeliveryListView(HumanGenericAPIView):
    required_permissions: ClassVar[_Required] = {"GET": (PermissionCode.WEBHOOKS_READ,)}
    serializer_class = WebhookDeliverySerializer
    pagination_class = DeliveryCursorPagination

    def get_queryset(self) -> Any:
        if getattr(self, "swagger_fake_view", False):  # OpenAPI generation has no real request
            return WebhookDelivery.objects.none()
        params = DeliveryQuerySerializer(data=self.request.query_params)
        params.is_valid(raise_exception=True)
        endpoint = selectors.endpoint_get(self.kwargs["endpoint_id"])
        return selectors.delivery_list(endpoint, status=params.validated_data.get("status"))

    @extend_schema(
        operation_id="webhook_deliveries_list",
        tags=[TAG],
        summary="Delivery history and status for an endpoint",
        parameters=[DeliveryQuerySerializer],
        responses=WebhookDeliverySerializer(many=True),
    )
    def get(self, request: Request, endpoint_id: uuid.UUID) -> Response:
        page = self.paginate_queryset(self.get_queryset())
        return self.get_paginated_response(WebhookDeliverySerializer(page, many=True).data)
