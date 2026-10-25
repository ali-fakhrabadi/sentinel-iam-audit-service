"""Typed, validated access to environment variables used by the settings module.

Every helper fails fast with ``ImproperlyConfigured`` on malformed values, so a
misconfigured container refuses to start instead of running with surprising
defaults.
"""

from __future__ import annotations

import os

from django.core.exceptions import ImproperlyConfigured

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


def _raw(name: str) -> str | None:
    value = os.environ.get(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def env_str(name: str, default: str = "") -> str:
    """Return the variable as a stripped string, or ``default`` when unset or empty."""
    value = _raw(name)
    return default if value is None else value


def env_required(name: str) -> str:
    """Return a variable that must be set; raise ``ImproperlyConfigured`` otherwise."""
    value = _raw(name)
    if value is None:
        raise ImproperlyConfigured(f"Environment variable {name} is required.")
    return value


def env_bool(name: str, *, default: bool) -> bool:
    """Parse true/false style values (1/0, true/false, yes/no, on/off)."""
    value = _raw(name)
    if value is None:
        return default
    normalized = value.lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ImproperlyConfigured(f"Environment variable {name} must be a boolean, got {value!r}.")


def env_int(
    name: str,
    *,
    default: int,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    """Parse an integer and enforce optional inclusive bounds."""
    value = _raw(name)
    if value is None:
        result = default
    else:
        try:
            result = int(value)
        except ValueError as exc:
            raise ImproperlyConfigured(
                f"Environment variable {name} must be an integer, got {value!r}."
            ) from exc
    if minimum is not None and result < minimum:
        raise ImproperlyConfigured(f"Environment variable {name} must be >= {minimum}.")
    if maximum is not None and result > maximum:
        raise ImproperlyConfigured(f"Environment variable {name} must be <= {maximum}.")
    return result


def env_list(name: str, *, default: list[str]) -> list[str]:
    """Parse a comma-separated list, ignoring blank items."""
    value = _raw(name)
    if value is None:
        return list(default)
    return [item.strip() for item in value.split(",") if item.strip()]
