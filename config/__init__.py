"""Project configuration: settings, URLs, Celery app and cross-cutting middleware."""

from config.celery import app as celery_app

__all__ = ("celery_app",)
