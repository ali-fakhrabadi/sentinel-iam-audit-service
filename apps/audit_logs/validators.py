"""Validation of producer-supplied metadata.

Limits (all configurable): serialized size, nesting depth, number of keys and list
items, key format and string length. Credentials are rejected outright, by key name
(``password``, ``token``, ``api_key`` ...) and by value shape (JWTs, API keys, bearer
tokens), because an audit log must never become a credential store.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any

from django.conf import settings
from django.core.exceptions import ValidationError

from config.logging import SENSITIVE_KEY_PATTERN, redact_text

MAX_KEYS = 100
MAX_LIST_ITEMS = 50
MAX_STRING_LENGTH = 1024
MAX_SAFE_INTEGER = 2**53 - 1  # largest integer JavaScript clients can represent exactly
_KEY_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,64}")


def serialized_size(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def validate_metadata(metadata: Any) -> dict[str, Any]:
    """Return the metadata if valid; raise ``ValidationError`` with a precise reason."""
    if not isinstance(metadata, dict):
        raise ValidationError("Metadata must be a JSON object.")
    max_bytes: int = settings.AUDIT_METADATA_MAX_BYTES
    size = serialized_size(metadata)
    if size > max_bytes:
        raise ValidationError(f"Metadata is {size} bytes; the maximum is {max_bytes}.")
    _Walker(max_depth=settings.AUDIT_METADATA_MAX_DEPTH).visit(metadata, "metadata", depth=1)
    return metadata


@dataclass
class _Walker:
    max_depth: int
    keys_seen: int = 0

    def visit(self, value: Any, path: str, *, depth: int) -> None:
        if isinstance(value, dict | list) and depth > self.max_depth:
            raise ValidationError(f"{path}: nesting deeper than {self.max_depth} levels.")
        if isinstance(value, dict):
            self._mapping(value, path, depth=depth)
        elif isinstance(value, list):
            self._sequence(value, path, depth=depth)
        else:
            _check_scalar(value, path)

    def _mapping(self, value: dict[Any, Any], path: str, *, depth: int) -> None:
        for key, item in value.items():
            self.keys_seen += 1
            if self.keys_seen > MAX_KEYS:
                raise ValidationError(f"Metadata has more than {MAX_KEYS} keys.")
            if not isinstance(key, str) or not _KEY_PATTERN.fullmatch(key):
                raise ValidationError(
                    f"{path}: key {key!r} must be 1-64 letters, digits, '_', '.' or '-'."
                )
            if SENSITIVE_KEY_PATTERN.search(key):
                raise ValidationError(f"{path}.{key}: credentials must not be stored in metadata.")
            self.visit(item, f"{path}.{key}", depth=depth + 1)

    def _sequence(self, value: list[Any], path: str, *, depth: int) -> None:
        if len(value) > MAX_LIST_ITEMS:
            raise ValidationError(f"{path}: lists are limited to {MAX_LIST_ITEMS} items.")
        for index, item in enumerate(value):
            self.visit(item, f"{path}.{index}", depth=depth + 1)


def _check_scalar(value: Any, path: str) -> None:
    if isinstance(value, str):
        if len(value) > MAX_STRING_LENGTH:
            raise ValidationError(f"{path}: strings are limited to {MAX_STRING_LENGTH} characters.")
        if redact_text(value) != value:
            raise ValidationError(f"{path}: value looks like a credential and was rejected.")
    elif isinstance(value, bool) or value is None:
        return
    elif isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ValidationError(f"{path}: integers must be within +/-(2^53 - 1).")
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise ValidationError(f"{path}: NaN and infinite numbers are not allowed.")
    else:
        raise ValidationError(f"{path}: unsupported value type {type(value).__name__}.")
