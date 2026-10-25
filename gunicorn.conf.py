"""Gunicorn configuration for the Sentinel API container.

Every value can be tuned through environment variables, so one image serves all
environments. Request logs are produced by the application's request-ID
middleware, so Gunicorn's own access log is disabled to avoid duplicates.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    return int(raw) if raw else default


# Prometheus multiprocess mode: every Gunicorn worker writes its metrics to this
# directory and /metrics aggregates them. It must be set before any worker
# imports prometheus_client, which is why it lives in this file.
PROMETHEUS_MULTIPROC_DIR = Path(
    os.environ.setdefault("PROMETHEUS_MULTIPROC_DIR", "/tmp/prometheus-multiproc")  # noqa: S108
)

bind = f"0.0.0.0:{_int_env('GUNICORN_PORT', 8000)}"
worker_class = "gthread"
workers = _int_env("GUNICORN_WORKERS", 3)
threads = _int_env("GUNICORN_THREADS", 4)
timeout = _int_env("GUNICORN_TIMEOUT", 30)
graceful_timeout = _int_env("GUNICORN_GRACEFUL_TIMEOUT", 30)
keepalive = _int_env("GUNICORN_KEEPALIVE", 5)

# Recycle workers periodically to bound the impact of slow memory growth.
max_requests = _int_env("GUNICORN_MAX_REQUESTS", 2000)
max_requests_jitter = _int_env("GUNICORN_MAX_REQUESTS_JITTER", 200)

# Heartbeat files on tmpfs avoid worker stalls on slow or read-only disks.
_SHARED_MEMORY_DIR = Path("/dev/shm")  # noqa: S108 - shared-memory tmpfs, not a temp file path
worker_tmp_dir = str(_SHARED_MEMORY_DIR) if _SHARED_MEMORY_DIR.is_dir() else None

# Reject oversized request lines and headers before they reach Django.
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

forwarded_allow_ips = os.environ.get("GUNICORN_FORWARDED_ALLOW_IPS", "127.0.0.1")

accesslog = None
errorlog = "-"
loglevel = os.environ.get("GUNICORN_LOG_LEVEL", "info")
logconfig_dict: dict[str, Any] = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"json": {"()": "config.logging.JsonFormatter"}},
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json",
            "stream": "ext://sys.stdout",
        }
    },
    "root": {"handlers": ["console"], "level": "WARNING"},
    "loggers": {
        "gunicorn.error": {
            "handlers": ["console"],
            "level": loglevel.upper(),
            "propagate": False,
        },
    },
}


def on_starting(server: Any) -> None:
    """Start every master process with an empty metrics directory."""
    shutil.rmtree(PROMETHEUS_MULTIPROC_DIR, ignore_errors=True)
    PROMETHEUS_MULTIPROC_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)


def child_exit(server: Any, worker: Any) -> None:
    """Drop live-gauge samples of workers that have exited."""
    # Imported lazily so the master process only loads prometheus_client when needed.
    from prometheus_client import multiprocess  # noqa: PLC0415

    multiprocess.mark_process_dead(worker.pid)
