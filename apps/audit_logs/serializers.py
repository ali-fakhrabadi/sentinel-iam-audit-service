"""Request and response shapes for audit ingestion and querying."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from typing import Any

from django.conf import settings
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils import timezone
from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers

from apps.accounts.serializers import StrictInputSerializer
from apps.audit_logs.models import ACTION_PATTERN, RESOURCE_TYPE_PATTERN, AuditEvent, Severity
from apps.audit_logs.services import EventInput
from apps.audit_logs.validators import serialized_size, validate_metadata
from config.schemas import ProblemFieldErrorSerializer

_ACTION_RE = re.compile(ACTION_PATTERN)
_RESOURCE_TYPE_RE = re.compile(RESOURCE_TYPE_PATTERN)
_IDEMPOTENCY_KEY_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_MAX_METADATA_FILTER_BYTES = 512


class _UppercaseChoiceField(serializers.ChoiceField):
    def to_internal_value(self, data: Any) -> Any:
        return super().to_internal_value(data.strip().upper() if isinstance(data, str) else data)


# --------------------------------------------------------------------------------------
# Ingestion
# --------------------------------------------------------------------------------------
class AuditEventInputSerializer(StrictInputSerializer):
    action = serializers.CharField(
        max_length=128, help_text="Lowercase dotted name, e.g. auth.login.failed"
    )
    resource_type = serializers.CharField(max_length=64, help_text="e.g. iam.user, storage.bucket")
    resource_id = serializers.CharField(max_length=255, required=False, allow_null=True)
    actor_id = serializers.CharField(
        max_length=255,
        required=False,
        allow_null=True,
        help_text="Who acted, as known to the producer. Stored as an unverified claim.",
    )
    ip_address = serializers.IPAddressField(required=False, allow_null=True)
    user_agent = serializers.CharField(
        max_length=512, required=False, allow_blank=True, default="", trim_whitespace=False
    )
    severity = _UppercaseChoiceField(choices=Severity.choices)
    metadata = serializers.JSONField(required=False, default=dict)
    occurred_at = serializers.DateTimeField(
        required=False,
        allow_null=True,
        help_text="When it happened at the producer; at most 5 minutes ahead, 30 days old.",
    )
    idempotency_key = serializers.CharField(
        max_length=128,
        required=False,
        allow_null=True,
        help_text="Resubmitting the same key returns the original event (status duplicate).",
    )

    def validate_action(self, value: str) -> str:
        normalized = value.strip().lower()
        if not _ACTION_RE.fullmatch(normalized):
            raise serializers.ValidationError(
                "Use 2-6 dot-separated lowercase segments, e.g. auth.login.failed."
            )
        return normalized

    def validate_resource_type(self, value: str) -> str:
        normalized = value.strip().lower()
        if not _RESOURCE_TYPE_RE.fullmatch(normalized):
            raise serializers.ValidationError("Use lowercase dotted segments, e.g. iam.user.")
        return normalized

    def validate_metadata(self, value: Any) -> dict[str, Any]:
        try:
            return validate_metadata(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages) from exc

    def validate_occurred_at(self, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        now = timezone.now()
        if value > now + timedelta(seconds=settings.AUDIT_OCCURRED_AT_MAX_FUTURE_SKEW_SECONDS):
            raise serializers.ValidationError("occurred_at is too far in the future.")
        if value < now - timedelta(days=settings.AUDIT_OCCURRED_AT_MAX_AGE_DAYS):
            raise serializers.ValidationError(
                f"occurred_at is older than {settings.AUDIT_OCCURRED_AT_MAX_AGE_DAYS} days."
            )
        return value

    def validate_idempotency_key(self, value: str | None) -> str | None:
        if value is not None and not _IDEMPOTENCY_KEY_RE.fullmatch(value):
            raise serializers.ValidationError("Use 1-128 letters, digits, '.', '_', ':' or '-'.")
        return value

    def to_event_input(self) -> EventInput:
        data = self.validated_data
        return EventInput(
            action=data["action"],
            resource_type=data["resource_type"],
            severity=data["severity"],
            resource_id=data.get("resource_id"),
            actor_id=data.get("actor_id"),
            ip_address=data.get("ip_address"),
            user_agent=data.get("user_agent", ""),
            metadata=data.get("metadata") or {},
            occurred_at=data.get("occurred_at"),
            idempotency_key=data.get("idempotency_key"),
        )


class BulkIngestRequestSerializer(serializers.Serializer):
    """Documents the bulk body; items are validated one by one by the view."""

    events = AuditEventInputSerializer(many=True, help_text="Between 1 and 500 events")


class IngestItemResultSerializer(serializers.Serializer):
    index = serializers.IntegerField(help_text="Position of the item in the request")
    status = serializers.ChoiceField(choices=["accepted", "duplicate", "rejected"])
    event_id = serializers.UUIDField(allow_null=True)
    # DRF's metaclass removes declared fields from the class, so this does not shadow
    # Serializer.errors at runtime; the stubs cannot express that.
    errors = ProblemFieldErrorSerializer(many=True, required=False)  # type: ignore[assignment]


class BulkIngestResponseSerializer(serializers.Serializer):
    accepted = serializers.IntegerField()
    duplicates = serializers.IntegerField()
    rejected = serializers.IntegerField()
    results = IngestItemResultSerializer(many=True)


class SingleIngestResponseSerializer(serializers.Serializer):
    id = serializers.UUIDField()
    status = serializers.ChoiceField(choices=["accepted", "duplicate"])


# --------------------------------------------------------------------------------------
# Querying
# --------------------------------------------------------------------------------------
class AuditEventQuerySerializer(serializers.Serializer):
    actor_id = serializers.CharField(max_length=255, required=False)
    action = serializers.CharField(max_length=128, required=False, help_text="Exact action")
    action_prefix = serializers.CharField(
        max_length=128, required=False, help_text="e.g. auth. matches auth.login.failed"
    )
    resource_type = serializers.CharField(max_length=64, required=False)
    resource_id = serializers.CharField(max_length=255, required=False)
    severity = serializers.MultipleChoiceField(
        choices=Severity.choices, required=False, help_text="Repeat to match several"
    )
    ip_address = serializers.IPAddressField(required=False)
    created_after = serializers.DateTimeField(
        required=False, help_text="Inclusive lower bound; defaults to 30 days before created_before"
    )
    created_before = serializers.DateTimeField(
        required=False, help_text="Exclusive upper bound; defaults to now"
    )
    metadata_contains = serializers.CharField(
        max_length=1024,
        required=False,
        help_text='JSON object the metadata must contain, e.g. {"mfa": false}',
    )
    cursor = serializers.CharField(max_length=512, required=False)
    page_size = serializers.IntegerField(required=False, min_value=1)

    def validate_page_size(self, value: int) -> int:
        maximum: int = settings.AUDIT_QUERY_MAX_PAGE_SIZE
        if value > maximum:
            raise serializers.ValidationError(
                f"Ensure this value is less than or equal to {maximum}."
            )
        return value

    def validate_metadata_contains(self, value: str) -> dict[str, Any]:
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise serializers.ValidationError("Must be a JSON object.") from exc
        if not isinstance(parsed, dict) or not parsed:
            raise serializers.ValidationError("Must be a non-empty JSON object.")
        if serialized_size(parsed) > _MAX_METADATA_FILTER_BYTES:
            raise serializers.ValidationError(
                f"Keep the filter under {_MAX_METADATA_FILTER_BYTES} bytes."
            )
        return parsed

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        before = attrs.get("created_before") or timezone.now()
        after = attrs.get("created_after") or before - timedelta(
            days=settings.AUDIT_QUERY_DEFAULT_RANGE_DAYS
        )
        if after >= before:
            raise serializers.ValidationError(
                {"created_after": ["Must be earlier than created_before."]}
            )
        if before - after > timedelta(days=settings.AUDIT_QUERY_MAX_RANGE_DAYS):
            raise serializers.ValidationError(
                {
                    "created_after": [
                        f"Query ranges are limited to {settings.AUDIT_QUERY_MAX_RANGE_DAYS} days."
                    ]
                }
            )
        attrs["created_before"], attrs["created_after"] = before, after
        return attrs


class ProducerSerializer(serializers.Serializer):
    type = serializers.ChoiceField(choices=["service_account", "user"])
    id = serializers.UUIDField()
    name = serializers.CharField(help_text="Service account name or user email")


class AuditEventSerializer(serializers.ModelSerializer):
    producer = serializers.SerializerMethodField()

    class Meta:
        model = AuditEvent
        fields = (
            "id",
            "action",
            "resource_type",
            "resource_id",
            "actor_id",
            "severity",
            "ip_address",
            "user_agent",
            "metadata",
            "occurred_at",
            "received_at",
            "created_at",
            "idempotency_key",
            "producer",
        )
        read_only_fields = fields

    @staticmethod
    def _producer(event: AuditEvent) -> dict[str, Any]:
        if event.producer_service_account is not None:
            account = event.producer_service_account
            return {"type": "service_account", "id": account.id, "name": account.name}
        user = event.producer_user
        if user is None:  # forbidden by the audit_exactly_one_producer constraint
            raise ValueError("Audit event without producer")
        return {"type": "user", "id": user.id, "name": user.email}

    @extend_schema_field(ProducerSerializer)
    def get_producer(self, event: AuditEvent) -> dict[str, Any]:
        return dict(ProducerSerializer(self._producer(event)).data)


class AuditEventPageSerializer(serializers.Serializer):
    results = AuditEventSerializer(many=True)
    next_cursor = serializers.CharField(allow_null=True, help_text="Pass as ?cursor= to continue")
    next = serializers.URLField(
        allow_null=True, help_text="Next page URL, or null on the last page"
    )
