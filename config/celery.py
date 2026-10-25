"""Celery application for background work (webhook delivery, outbox dispatch).

Configuration is read from Django settings prefixed with ``CELERY_``. Workers use
the same JSON logging configuration as the web process.
"""

from __future__ import annotations

import os
from logging.config import dictConfig
from typing import Any

from celery import Celery
from celery.signals import setup_logging

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

app = Celery("sentinel")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()


@setup_logging.connect
def configure_logging(**_kwargs: Any) -> None:
    """Use Django's LOGGING dict instead of Celery's default plain-text handlers."""
    from django.conf import settings  # noqa: PLC0415 - settings load lazily in workers

    dictConfig(settings.LOGGING)
