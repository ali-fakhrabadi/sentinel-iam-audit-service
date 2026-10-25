# Sentinel IAM & Audit Service
#
# Stages:
#   base     shared Python runtime settings
#   builder  hash-verified runtime dependencies in a virtualenv (wheels only)
#   dev      builder + test, lint and type-check tooling (make test / CI parity)
#   runtime  minimal non-root image served by Gunicorn (default target)

ARG PYTHON_IMAGE=python:3.12.15-slim-trixie

FROM ${PYTHON_IMAGE} AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_DEFAULT_TIMEOUT=30 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:${PATH}"
WORKDIR /app


FROM base AS builder
# Optional PyPI mirror for networks where pypi.org is slow or unreachable.
# Hash pinning means a mirror cannot substitute different files. Never put
# credentials in this value: build arguments are visible in image history.
ARG PIP_INDEX_URL=""
RUN python -m venv "${VIRTUAL_ENV}"
COPY requirements.txt ./
# --require-hashes rejects any artifact that does not match the lock file.
# --only-binary keeps compilers out of the image and makes builds deterministic.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install ${PIP_INDEX_URL:+--index-url "${PIP_INDEX_URL}"} \
        --require-hashes --no-deps --only-binary=:all: -r requirements.txt \
    && pip check


FROM builder AS dev
ARG PIP_INDEX_URL=""
COPY requirements-dev.txt ./
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install ${PIP_INDEX_URL:+--index-url "${PIP_INDEX_URL}"} \
        --require-hashes --no-deps -r requirements-dev.txt \
    && pip check
ENV DJANGO_SETTINGS_MODULE=config.settings
# The source tree is bind-mounted at /app by the compose "dev" profile.
CMD ["pytest"]


FROM base AS runtime
ARG APP_UID=10001
LABEL org.opencontainers.image.title="sentinel-iam-audit-service" \
      org.opencontainers.image.description="IAM, RBAC and append-only security audit log microservice" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/ali-fakhrabadi/sentinel-iam-audit-service"

RUN groupadd --system --gid "${APP_UID}" sentinel \
    && useradd --system --uid "${APP_UID}" --gid sentinel \
       --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin sentinel

COPY --from=builder /opt/venv /opt/venv
# Application code stays owned by root, so the runtime user cannot modify it.
COPY manage.py gunicorn.conf.py ./
COPY config ./config
COPY apps ./apps

ENV DJANGO_SETTINGS_MODULE=config.settings
# Admin, Swagger UI and ReDoc assets are collected at build time and served by
# WhiteNoise. The placeholder values exist only for this command; real secrets
# are injected at runtime and never stored in the image.
RUN DJANGO_SECRET_KEY=build-time-collectstatic-only \
    JWT_SIGNING_KEY=build-time-collectstatic-only \
    METRICS_AUTH_TOKEN=build-time-collectstatic-only \
    WEBHOOK_SECRET_ENCRYPTION_KEYS=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
    python manage.py collectstatic --noinput

USER ${APP_UID}:${APP_UID}
EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health/live/', timeout=2).status == 200 else 1)"]

CMD ["gunicorn", "--config", "gunicorn.conf.py", "config.wsgi:application"]
