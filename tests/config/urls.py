"""Test-only URLconf exposing views that raise each kind of error.

Used with ``@pytest.mark.urls("tests.config.urls")``; the project routes stay
available so Django's own error handlers are exercised too.
"""

from __future__ import annotations

from typing import Any

from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from django.core.exceptions import RequestDataTooBig, SuspiciousOperation
from django.http import Http404
from django.urls import include, path
from rest_framework import exceptions, serializers
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from config import urls as project_urls


class _EventSerializer(serializers.Serializer):
    severity = serializers.ChoiceField(choices=["INFO", "WARN", "CRITICAL"])


class _PayloadSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=5)
    events = _EventSerializer(many=True)


class _PublicView(APIView):
    authentication_classes = ()
    permission_classes = (AllowAny,)
    throttle_classes = ()


class ValidationView(_PublicView):
    def post(self, request: Request) -> Response:
        serializer = _PayloadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({"accepted": True})


class EchoView(_PublicView):
    def post(self, request: Request) -> Response:
        data: Any = request.data
        return Response({"keys": len(data)})


class AuthRequiredView(APIView):
    """Uses the project defaults: JWT authentication and IsAuthenticated."""

    def get(self, request: Request) -> Response:
        return Response({"ok": True})


class DrfForbiddenView(_PublicView):
    def get(self, request: Request) -> Response:
        raise exceptions.PermissionDenied


class DjangoForbiddenView(_PublicView):
    def get(self, request: Request) -> Response:
        raise DjangoPermissionDenied


class MissingView(_PublicView):
    def get(self, request: Request) -> Response:
        raise Http404


class ThrottledView(_PublicView):
    def get(self, request: Request) -> Response:
        raise exceptions.Throttled(wait=17)


class CrashView(_PublicView):
    def get(self, request: Request) -> Response:
        raise RuntimeError("database password=hunter2 must never reach the client")


class SuspiciousView(_PublicView):
    def get(self, request: Request) -> Response:
        raise SuspiciousOperation("Invalid HTTP_HOST header from internal proxy 10.0.0.7")


class TooBigView(_PublicView):
    def get(self, request: Request) -> Response:
        raise RequestDataTooBig("Request body exceeded settings.DATA_UPLOAD_MAX_MEMORY_SIZE.")


urlpatterns = [
    path("errors/validation/", ValidationView.as_view()),
    path("errors/echo/", EchoView.as_view()),
    path("errors/auth/", AuthRequiredView.as_view()),
    path("errors/drf-forbidden/", DrfForbiddenView.as_view()),
    path("errors/django-forbidden/", DjangoForbiddenView.as_view()),
    path("errors/missing/", MissingView.as_view()),
    path("errors/throttled/", ThrottledView.as_view()),
    path("errors/crash/", CrashView.as_view()),
    path("errors/suspicious/", SuspiciousView.as_view()),
    path("errors/too-big/", TooBigView.as_view()),
    path("", include(project_urls)),
]

handler400 = project_urls.handler400
handler403 = project_urls.handler403
handler404 = project_urls.handler404
handler500 = project_urls.handler500
