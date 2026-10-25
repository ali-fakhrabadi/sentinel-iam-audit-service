"""Generation, parsing and verification of API key material (no database access).

* 256 bits of entropy from ``secrets`` make brute force infeasible, which is why a
  fast hash (SHA-256) is acceptable here. Human passwords use Argon2 instead.
* The prefix is a lookup identifier, never a secret: logs and the API may show it.
* Digests are compared with ``hmac.compare_digest`` to avoid timing side channels.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import string
from dataclasses import dataclass

API_KEY_SCHEME = "sntl"
PREFIX_LENGTH = 8
_SECRET_BYTES = 32  # 256 bits -> 43 URL-safe characters
_PREFIX_ALPHABET = string.ascii_letters + string.digits
_API_KEY_PATTERN = re.compile(
    rf"{API_KEY_SCHEME}_([A-Za-z0-9]{{{PREFIX_LENGTH}}})_[A-Za-z0-9_-]{{43}}"
)


@dataclass(frozen=True, slots=True)
class GeneratedKey:
    raw: str
    prefix: str
    key_hash: str

    def __repr__(self) -> str:
        # Keep the raw key out of tracebacks, debuggers and accidental log calls.
        return f"GeneratedKey(prefix={self.prefix!r}, raw=<redacted>)"


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def generate_api_key() -> GeneratedKey:
    prefix = "".join(secrets.choice(_PREFIX_ALPHABET) for _ in range(PREFIX_LENGTH))
    raw = f"{API_KEY_SCHEME}_{prefix}_{secrets.token_urlsafe(_SECRET_BYTES)}"
    return GeneratedKey(raw=raw, prefix=prefix, key_hash=hash_api_key(raw))


def parse_prefix(raw_key: str) -> str | None:
    """Return the lookup prefix of a well-formed key, or ``None`` for anything else."""
    match = _API_KEY_PATTERN.fullmatch(raw_key)
    return match.group(1) if match else None


def verify_api_key(raw_key: str, expected_hash: str) -> bool:
    return hmac.compare_digest(hash_api_key(raw_key), expected_hash)
