from __future__ import annotations

from rest_framework import serializers

from apps.accounts.serializers import StrictInputSerializer
from apps.audit_logs.models import Severity
from apps.webhooks.models import DeliveryStatus, WebhookDelivery, WebhookEndpoint

_MIN_SEVERITY_CHOICES = [(Severity.WARN, "Warning"), (Severity.CRITICAL, "Critical")]


class WebhookEndpointSerializer(serializers.ModelSerializer):
    """Endpoint configuration. Secrets are never part of this representation."""

    class Meta:
        model = WebhookEndpoint
        fields: tuple[str, ...] = (
            "id",
            "name",
            "description",
            "url",
            "is_active",
            "min_severity",
            "action_prefixes",
            "secret_rotated_at",
            "created_at",
            "updated_at",
        )
        read_only_fields: tuple[str, ...] = fields


class WebhookEndpointWithSecretSerializer(WebhookEndpointSerializer):
    secret = serializers.CharField(
        read_only=True,
        help_text="Signing secret (whsec_...). Returned only now; store it in the receiver.",
    )

    class Meta(WebhookEndpointSerializer.Meta):
        fields = (*WebhookEndpointSerializer.Meta.fields, "secret")
        read_only_fields = fields


class WebhookEndpointCreateSerializer(StrictInputSerializer):
    name = serializers.SlugField(max_length=64)
    url = serializers.URLField(max_length=2048, help_text="https:// URL on a public address")
    description = serializers.CharField(
        max_length=255, allow_blank=True, required=False, default=""
    )
    min_severity = serializers.ChoiceField(choices=_MIN_SEVERITY_CHOICES, default=Severity.CRITICAL)
    action_prefixes = serializers.ListField(
        child=serializers.CharField(max_length=128), required=False, default=list, max_length=20
    )


class WebhookEndpointUpdateSerializer(StrictInputSerializer):
    url = serializers.URLField(max_length=2048, required=False)
    description = serializers.CharField(max_length=255, allow_blank=True, required=False)
    min_severity = serializers.ChoiceField(choices=_MIN_SEVERITY_CHOICES, required=False)
    action_prefixes = serializers.ListField(
        child=serializers.CharField(max_length=128), required=False, max_length=20
    )
    is_active = serializers.BooleanField(required=False)


class WebhookDeliverySerializer(serializers.ModelSerializer):
    event_action = serializers.CharField(source="event.action", read_only=True)
    event_severity = serializers.CharField(source="event.severity", read_only=True)

    class Meta:
        model = WebhookDelivery
        fields = (
            "id",
            "event",
            "event_action",
            "event_severity",
            "status",
            "attempt_count",
            "last_attempt_at",
            "last_status_code",
            "last_error",
            "next_attempt_at",
            "created_at",
            "completed_at",
        )
        read_only_fields = fields


class DeliveryQuerySerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=DeliveryStatus.choices, required=False)
