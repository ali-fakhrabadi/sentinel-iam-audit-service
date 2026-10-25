"""Guards for security-relevant defaults that are easy to regress unnoticed."""

from __future__ import annotations

from django.conf import settings


def test_api_is_deny_by_default() -> None:
    assert settings.REST_FRAMEWORK["DEFAULT_PERMISSION_CLASSES"] == [
        "rest_framework.permissions.IsAuthenticated"
    ]


def test_client_ip_is_not_taken_from_spoofable_headers_by_default() -> None:
    assert settings.REST_FRAMEWORK["NUM_PROXIES"] == 0


def test_errors_use_the_problem_details_handler() -> None:
    assert (
        settings.REST_FRAMEWORK["EXCEPTION_HANDLER"]
        == "config.exceptions.problem_exception_handler"
    )


def test_request_context_runs_before_security_middleware() -> None:
    middleware = settings.MIDDLEWARE
    assert middleware.index("config.middleware.RequestContextMiddleware") < middleware.index(
        "django.middleware.security.SecurityMiddleware"
    )
    assert middleware.index("config.middleware.RequestSizeLimitMiddleware") < middleware.index(
        "django.middleware.common.CommonMiddleware"
    )


def test_every_sql_statement_is_time_bounded() -> None:
    options = settings.DATABASES["default"]["OPTIONS"]
    assert isinstance(options, dict)
    assert "statement_timeout=" in options["options"]


def test_jwt_signing_key_is_independent_of_secret_key() -> None:
    assert settings.SIMPLE_JWT["SIGNING_KEY"] != settings.SECRET_KEY


def test_probes_and_metrics_are_exempt_from_https_redirect() -> None:
    assert r"^health/" in settings.SECURE_REDIRECT_EXEMPT
    assert r"^metrics$" in settings.SECURE_REDIRECT_EXEMPT
