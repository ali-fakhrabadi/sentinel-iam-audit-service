from __future__ import annotations

from django.apps import AppConfig


class AuditLogsConfig(AppConfig):
    name = "apps.audit_logs"
    label = "audit_logs"
    verbose_name = "Audit log"
    default_auto_field = "django.db.models.BigAutoField"
