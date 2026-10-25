from __future__ import annotations

from typing import Any

import pytest
from django.conf import settings

from config import celery_app
from config.celery import configure_logging


def test_celery_reads_reliability_settings_from_django() -> None:
    conf = celery_app.conf

    assert conf.broker_url == settings.CELERY_BROKER_URL
    assert conf.task_acks_late is True
    assert conf.task_reject_on_worker_lost is True
    assert conf.worker_prefetch_multiplier == 1
    assert conf.task_serializer == "json"
    assert conf.accept_content == ["json"]
    assert conf.task_ignore_result is True
    assert conf.worker_hijack_root_logger is False


def test_workers_use_the_django_json_logging_config(monkeypatch: pytest.MonkeyPatch) -> None:
    applied: list[dict[str, Any]] = []
    monkeypatch.setattr("config.celery.dictConfig", applied.append)

    configure_logging()

    assert applied == [settings.LOGGING]
