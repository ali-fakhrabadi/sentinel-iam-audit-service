"""ASGI entry point, for deployments behind an ASGI server (e.g. Uvicorn).

The default container runs Gunicorn with the WSGI application; this module keeps
the project deployable on ASGI without code changes.
"""

from __future__ import annotations

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

application = get_asgi_application()
