from __future__ import annotations

from django.urls import path

from apps.webhooks import views

urlpatterns = [
    path(
        "webhooks/endpoints/",
        views.WebhookEndpointListCreateView.as_view(),
        name="webhook-endpoint-list",
    ),
    path(
        "webhooks/endpoints/<uuid:endpoint_id>/",
        views.WebhookEndpointDetailView.as_view(),
        name="webhook-endpoint-detail",
    ),
    path(
        "webhooks/endpoints/<uuid:endpoint_id>/rotate-secret/",
        views.WebhookSecretRotateView.as_view(),
        name="webhook-endpoint-rotate-secret",
    ),
    path(
        "webhooks/endpoints/<uuid:endpoint_id>/deliveries/",
        views.WebhookDeliveryListView.as_view(),
        name="webhook-delivery-list",
    ),
]
