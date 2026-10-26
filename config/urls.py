"""Root URL configuration.

Operational endpoints (``/health/*``, ``/metrics``) live outside ``/api/`` so they
are excluded from CORS and can be routed separately at the edge.
"""

from __future__ import annotations

from django.conf import settings
from django.contrib import admin
from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView

from config.health import LivenessView, ReadinessView
from config.metrics import metrics_view

urlpatterns = [
    path("health/live/", LivenessView.as_view(), name="health-live"),
    path("health/ready/", ReadinessView.as_view(), name="health-ready"),
    path("metrics", metrics_view, name="prometheus-metrics"),
    path("api/schema/", SpectacularAPIView.as_view(), name="openapi-schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="openapi-schema"), name="swagger-ui"),
    path("api/redoc/", SpectacularRedocView.as_view(url_name="openapi-schema"), name="redoc"),
    path("api/v1/", include("apps.accounts.urls")),
    path("api/v1/", include("apps.audit_logs.urls")),
    path("api/v1/", include("apps.webhooks.urls")),
    path(settings.ADMIN_URL, admin.site.urls),
]

handler400 = "config.views.bad_request"
handler403 = "config.views.permission_denied"
handler404 = "config.views.page_not_found"
handler500 = "config.views.server_error"
