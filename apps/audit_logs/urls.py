from __future__ import annotations

from django.urls import path

from apps.audit_logs import views

urlpatterns = [
    path("audit/events/", views.AuditEventCollectionView.as_view(), name="audit-event-list"),
    path("audit/events/bulk/", views.AuditEventBulkView.as_view(), name="audit-event-bulk"),
    path(
        "audit/events/<uuid:event_id>/",
        views.AuditEventDetailView.as_view(),
        name="audit-event-detail",
    ),
]
