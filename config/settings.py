"""Django settings for the Sentinel IAM & Audit Service.

All deployment-specific values come from environment variables (see .env.example).
Defaults are safe for production: DEBUG off, HTTPS-only cookies and redirects,
deny-by-default API permissions. Development relaxes them explicitly via .env.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

from corsheaders.defaults import default_headers

from config.env import env_bool, env_int, env_list, env_required, env_str

BASE_DIR = Path(__file__).resolve().parent.parent

# --------------------------------------------------------------------------------------
# Core
# --------------------------------------------------------------------------------------
SECRET_KEY = env_required("DJANGO_SECRET_KEY")
DEBUG = env_bool("DJANGO_DEBUG", default=False)
ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", default=["localhost", "127.0.0.1"])
CSRF_TRUSTED_ORIGINS = env_list("DJANGO_CSRF_TRUSTED_ORIGINS", default=[])

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.postgres",
    "corsheaders",
    "rest_framework",
    "rest_framework_simplejwt.token_blacklist",
    "django_filters",
    "drf_spectacular",
    "drf_spectacular_sidecar",
    "django_prometheus",
    "apps.accounts",
]

AUTH_USER_MODEL = "accounts.User"

MIDDLEWARE = [
    # CORS must run first so preflight and error responses carry CORS headers.
    "corsheaders.middleware.CorsMiddleware",
    "django_prometheus.middleware.PrometheusBeforeMiddleware",
    "config.middleware.RequestContextMiddleware",
    "config.middleware.RequestSizeLimitMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "django_prometheus.middleware.PrometheusAfterMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
ADMIN_URL = env_str("DJANGO_ADMIN_URL", "admin/")

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --------------------------------------------------------------------------------------
# Database (PostgreSQL is the source of truth)
# --------------------------------------------------------------------------------------
DB_STATEMENT_TIMEOUT_MS = env_int("DB_STATEMENT_TIMEOUT_MS", default=5000, minimum=0)

DATABASES: dict[str, dict[str, Any]] = {
    "default": {
        # django-prometheus wraps the PostgreSQL backend to export query metrics.
        "ENGINE": "django_prometheus.db.backends.postgresql",
        "NAME": env_str("DB_NAME", "sentinel"),
        "USER": env_str("DB_USER", "sentinel_app"),
        "PASSWORD": env_str("DB_PASSWORD"),
        "HOST": env_str("DB_HOST", "localhost"),
        "PORT": env_int("DB_PORT", default=5432, minimum=1, maximum=65535),
        "CONN_MAX_AGE": env_int("DB_CONN_MAX_AGE", default=60, minimum=0),
        "CONN_HEALTH_CHECKS": True,
        "OPTIONS": {
            "connect_timeout": env_int("DB_CONNECT_TIMEOUT_SECONDS", default=3, minimum=1),
            "application_name": "sentinel-iam-audit-service",
            # Bounds every statement so one expensive query cannot pin a worker.
            "options": f"-c statement_timeout={DB_STATEMENT_TIMEOUT_MS}",
        },
    }
}

# --------------------------------------------------------------------------------------
# Redis: Celery broker and cache (throttling). Never authoritative.
# --------------------------------------------------------------------------------------
CELERY_BROKER_URL = env_str("CELERY_BROKER_URL", "redis://localhost:6379/0")
REDIS_CACHE_URL = env_str("REDIS_CACHE_URL", "redis://localhost:6379/1")
HEALTH_CHECK_TIMEOUT_SECONDS = env_int("HEALTH_CHECK_TIMEOUT_SECONDS", default=2, minimum=1)

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": REDIS_CACHE_URL,
        "KEY_PREFIX": "sentinel",
        "TIMEOUT": 300,
        "OPTIONS": {"socket_connect_timeout": 2, "socket_timeout": 2},
    }
}

# --------------------------------------------------------------------------------------
# Celery
# --------------------------------------------------------------------------------------
CELERY_TASK_SERIALIZER = "json"
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_RESULT_SERIALIZER = "json"
# Delivery state lives in PostgreSQL (outbox and delivery records), not in a result backend.
CELERY_TASK_IGNORE_RESULT = True
# Acknowledge after completion so a crashed worker's task is redelivered.
CELERY_TASK_ACKS_LATE = True
CELERY_TASK_REJECT_ON_WORKER_LOST = True
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_TASK_SOFT_TIME_LIMIT = 45
CELERY_TASK_TIME_LIMIT = 60
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
# Must exceed the longest retry countdown, otherwise Redis redelivers delayed tasks early.
CELERY_BROKER_TRANSPORT_OPTIONS = {"visibility_timeout": 3600}
CELERY_TIMEZONE = "UTC"
CELERY_WORKER_HIJACK_ROOT_LOGGER = False
CELERY_BEAT_SCHEDULE: dict[str, dict[str, object]] = {}

# --------------------------------------------------------------------------------------
# Authentication & passwords
# --------------------------------------------------------------------------------------
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    # Fallbacks only verify (and transparently upgrade) hashes created elsewhere.
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.ScryptPasswordHasher",
]

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 12},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(
        minutes=env_int("JWT_ACCESS_TOKEN_LIFETIME_MINUTES", default=15, minimum=1, maximum=1440)
    ),
    "REFRESH_TOKEN_LIFETIME": timedelta(
        hours=env_int("JWT_REFRESH_TOKEN_LIFETIME_HOURS", default=24, minimum=1, maximum=720)
    ),
    # Every refresh returns a new refresh token and blacklists the old one, so a
    # stolen refresh token is detected as soon as either party uses it again.
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    # Access tokens embed a hash of the password; changing it revokes them at once.
    "CHECK_REVOKE_TOKEN": True,
    "REVOKE_TOKEN_CLAIM": "hash_password",
    "CHECK_USER_IS_ACTIVE": True,
    "UPDATE_LAST_LOGIN": True,
    "USER_ID_FIELD": "id",
    "ALGORITHM": "HS256",
    # Separate from SECRET_KEY so each can be rotated independently.
    "SIGNING_KEY": env_required("JWT_SIGNING_KEY"),
    "ISSUER": "sentinel-iam-audit-service",
    "LEEWAY": timedelta(seconds=10),
    "AUTH_HEADER_TYPES": ("Bearer",),
    "USER_ID_CLAIM": "sub",
}

# --------------------------------------------------------------------------------------
# Django REST Framework
# --------------------------------------------------------------------------------------
_RENDERERS = ["rest_framework.renderers.JSONRenderer"]
if DEBUG:
    _RENDERERS.append("rest_framework.renderers.BrowsableAPIRenderer")

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ],
    # Deny by default: every endpoint must opt in to anonymous access explicitly.
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_RENDERER_CLASSES": _RENDERERS,
    "DEFAULT_PARSER_CLASSES": ["rest_framework.parsers.JSONParser"],
    "DEFAULT_FILTER_BACKENDS": ["django_filters.rest_framework.DjangoFilterBackend"],
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": env_str("THROTTLE_RATE_ANON", "30/minute"),
        "user": env_str("THROTTLE_RATE_USER", "600/minute"),
        "auth": env_str("THROTTLE_RATE_AUTH", "10/minute"),
        "ingest": env_str("THROTTLE_RATE_INGEST", "1200/minute"),
    },
    # 0 = identify clients by REMOTE_ADDR. Set to the number of trusted proxies in
    # front of the service; leaving it unset would let clients spoof X-Forwarded-For.
    "NUM_PROXIES": env_int("API_TRUSTED_PROXY_COUNT", default=0, minimum=0),
    "DEFAULT_SCHEMA_CLASS": "config.openapi.ProblemAutoSchema",
    "EXCEPTION_HANDLER": "config.exceptions.problem_exception_handler",
    "TEST_REQUEST_DEFAULT_FORMAT": "json",
}

API_KEY_DEFAULT_LIFETIME_DAYS = env_int("API_KEY_DEFAULT_LIFETIME_DAYS", default=90, minimum=1)
API_KEY_MAX_LIFETIME_DAYS = env_int(
    "API_KEY_MAX_LIFETIME_DAYS", default=365, minimum=API_KEY_DEFAULT_LIFETIME_DAYS
)
# last_used_at is written at most this often per key, to avoid a write per request.
API_KEY_LAST_USED_UPDATE_SECONDS = env_int(
    "API_KEY_LAST_USED_UPDATE_SECONDS", default=60, minimum=1
)

API_MAX_REQUEST_BYTES = env_int("API_MAX_REQUEST_BYTES", default=2_621_440, minimum=1024)
DATA_UPLOAD_MAX_MEMORY_SIZE = API_MAX_REQUEST_BYTES
DATA_UPLOAD_MAX_NUMBER_FIELDS = 1000

# --------------------------------------------------------------------------------------
# OpenAPI (drf-spectacular), shaped for TypeScript client generators
# --------------------------------------------------------------------------------------
SPECTACULAR_SETTINGS = {
    "TITLE": "Sentinel IAM & Audit Service API",
    "DESCRIPTION": (
        "Headless IAM, RBAC and append-only security audit logging. "
        "Errors use RFC 7807 problem details (application/problem+json) and every "
        "response carries an X-Request-ID header."
    ),
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "SCHEMA_PATH_PREFIX": r"/api/v[0-9]+",
    # Separate request and response components (e.g. UserRequest vs User) so generated
    # TypeScript types have no read-only/write-only field collisions.
    "COMPONENT_SPLIT_REQUEST": True,
    "SERVE_PERMISSIONS": ["rest_framework.permissions.AllowAny"],
    "SERVE_AUTHENTICATION": [],
    # Self-hosted Swagger UI and ReDoc assets: no third-party CDN at runtime.
    "SWAGGER_UI_DIST": "SIDECAR",
    "SWAGGER_UI_FAVICON_HREF": "SIDECAR",
    "REDOC_DIST": "SIDECAR",
    "SWAGGER_UI_SETTINGS": {
        "deepLinking": True,
        "persistAuthorization": True,
        "displayOperationId": True,
    },
    "ENUM_NAME_OVERRIDES": {
        "LivenessStatusEnum": ["ok"],
        "ReadinessStatusEnum": ["ok", "unavailable"],
        "DependencyStatusEnum": ["ok", "error"],
    },
    "TAGS": [
        {"name": "Auth", "description": "JWT login, rotation and logout; API key introspection"},
        {"name": "Current user", "description": "Profile, roles and permissions of the caller"},
        {"name": "Users", "description": "User administration and role assignment"},
        {"name": "Roles", "description": "RBAC roles and the permission catalog"},
        {"name": "Service accounts", "description": "Machine principals and their API keys"},
        {"name": "Health", "description": "Liveness and readiness probes"},
    ],
}

# --------------------------------------------------------------------------------------
# CORS for decoupled SPAs (React / Next.js / Vite)
# --------------------------------------------------------------------------------------
CORS_ALLOWED_ORIGINS = env_list(
    "CORS_ALLOWED_ORIGINS", default=["http://localhost:3000", "http://localhost:5173"]
)
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_HEADERS = (*default_headers, "x-api-key", "x-request-id")
CORS_EXPOSE_HEADERS = ["X-Request-ID", "X-Sentinel-Signature"]
CORS_PREFLIGHT_MAX_AGE = 3600
# Only API routes are cross-origin; admin, probes and metrics stay same-origin.
CORS_URLS_REGEX = r"^/api/.*$"

# --------------------------------------------------------------------------------------
# Security
# --------------------------------------------------------------------------------------
SECURE_HTTPS = env_bool("DJANGO_SECURE_HTTPS", default=True)
# Gunicorn derives the request scheme from X-Forwarded-Proto only for proxies listed
# in GUNICORN_FORWARDED_ALLOW_IPS, so SECURE_PROXY_SSL_HEADER is intentionally unset.
SECURE_SSL_REDIRECT = SECURE_HTTPS
# Container probes and Prometheus talk plain HTTP inside the private network.
SECURE_REDIRECT_EXEMPT = [r"^health/", r"^metrics$"]
SESSION_COOKIE_SECURE = SECURE_HTTPS
CSRF_COOKIE_SECURE = SECURE_HTTPS
SECURE_HSTS_SECONDS = env_int(
    "DJANGO_SECURE_HSTS_SECONDS", default=31_536_000 if SECURE_HTTPS else 0, minimum=0
)
SECURE_HSTS_INCLUDE_SUBDOMAINS = SECURE_HTTPS
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_HTTPONLY = True
X_FRAME_OPTIONS = "DENY"
# HSTS preload is a per-domain commitment made at the edge, not by this service.
SILENCED_SYSTEM_CHECKS = ["security.W021"]

# --------------------------------------------------------------------------------------
# Static files (admin, Swagger UI, ReDoc) served by WhiteNoise
# --------------------------------------------------------------------------------------
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}

# --------------------------------------------------------------------------------------
# Observability
# --------------------------------------------------------------------------------------
METRICS_AUTH_TOKEN = env_str("METRICS_AUTH_TOKEN")
LOG_LEVEL = env_str("DJANGO_LOG_LEVEL", "INFO").upper()

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"json": {"()": "config.logging.JsonFormatter"}},
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
            "formatter": "json",
        }
    },
    "root": {"handlers": ["console"], "level": LOG_LEVEL},
    "loggers": {
        # SQL logging could expose parameters; keep it off unless debugging locally.
        "django.db.backends": {"level": "WARNING", "propagate": True},
        # Access log lines come from config.middleware.RequestContextMiddleware.
        "django.server": {"level": "WARNING", "propagate": True},
        "celery": {"level": LOG_LEVEL, "propagate": True},
    },
}
