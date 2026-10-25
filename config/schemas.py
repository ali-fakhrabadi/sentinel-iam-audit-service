"""Serializers that only describe responses in the OpenAPI schema.

They give TypeScript code generators precise types for health responses and for
the RFC 7807 error body shared by every endpoint.
"""

from __future__ import annotations

from rest_framework import serializers


class ProblemFieldErrorSerializer(serializers.Serializer):
    field = serializers.CharField(
        help_text="Dotted path of the invalid field, e.g. events.0.action"
    )
    message = serializers.CharField()
    code = serializers.CharField(help_text="Machine-readable error code, e.g. required")


class ProblemDetailSerializer(serializers.Serializer):
    """RFC 7807 problem details (``application/problem+json``)."""

    type = serializers.CharField(help_text="Problem type URI, e.g. urn:sentinel:problem:not-found")
    title = serializers.CharField()
    status = serializers.IntegerField()
    detail = serializers.CharField()
    instance = serializers.CharField(required=False, help_text="Request path")
    request_id = serializers.CharField(required=False, help_text="Value of X-Request-ID")
    # Declared fields are removed from the class by DRF's metaclass, so this does not
    # shadow Serializer.errors at runtime; the stubs cannot express that.
    errors = ProblemFieldErrorSerializer(many=True, required=False)  # type: ignore[assignment]
    retry_after = serializers.IntegerField(
        required=False, help_text="Seconds to wait before retrying (rate limiting only)"
    )


class LivenessSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=["ok"])


class DependencyCheckSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=["ok", "error"])
    latency_ms = serializers.FloatField(allow_null=True)


class ReadinessChecksSerializer(serializers.Serializer):
    database = DependencyCheckSerializer()
    redis = DependencyCheckSerializer()


class ReadinessSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=["ok", "unavailable"])
    checks = ReadinessChecksSerializer()
