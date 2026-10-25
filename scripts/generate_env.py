#!/usr/bin/env python3
"""Create a .env file from .env.example with freshly generated secrets.

Placeholders recognised in the template:

    __GENERATE_SECRET__      64-character URL-safe random string (signing keys, tokens)
    __GENERATE_PASSWORD__    32-character URL-safe random string (safe inside URLs)
    __GENERATE_FERNET_KEY__  Fernet key: 32 random bytes, URL-safe base64

Only the standard library is used, so this runs before any dependency is installed.

Examples:
    python3 scripts/generate_env.py
    python3 scripts/generate_env.py --set SENTINEL_BIND_ADDRESS=0.0.0.0 \\
        --set SENTINEL_HTTP_PORT=8010
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import secrets
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

GENERATORS: dict[str, Callable[[], str]] = {
    "__GENERATE_SECRET__": lambda: secrets.token_urlsafe(48),
    "__GENERATE_PASSWORD__": lambda: secrets.token_urlsafe(24),
    "__GENERATE_FERNET_KEY__": lambda: base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(
        "ascii"
    ),
}

_KEY_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")


def render(template: str) -> str:
    """Replace every placeholder occurrence with an independently generated value."""
    rendered_lines: list[str] = []
    for line in template.splitlines():
        rendered = line
        for placeholder, generate in GENERATORS.items():
            while placeholder in rendered:
                rendered = rendered.replace(placeholder, generate(), 1)
        rendered_lines.append(rendered)
    return "\n".join(rendered_lines) + "\n"


def apply_overrides(content: str, overrides: Sequence[str]) -> str:
    """Set KEY=VALUE pairs on existing variables. Unknown keys are rejected."""
    lines = content.splitlines()
    for override in overrides:
        key, separator, value = override.partition("=")
        if not separator or not _KEY_PATTERN.match(key):
            raise ValueError(f"invalid override {override!r}; expected KEY=VALUE")
        prefix = f"{key}="
        matches = [index for index, line in enumerate(lines) if line.startswith(prefix)]
        if not matches:
            raise ValueError(f"{key} is not defined in the template")
        for index in matches:
            lines[index] = f"{prefix}{value}"
    return "\n".join(lines) + "\n"


def write_private(path: Path, content: str) -> None:
    """Write the file readable by the owner only (mode 0600 on POSIX systems)."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create .env from .env.example with generated secrets."
    )
    parser.add_argument("--template", type=Path, default=Path(".env.example"))
    parser.add_argument("--output", type=Path, default=Path(".env"))
    parser.add_argument(
        "--force", action="store_true", help="overwrite the output file if it exists"
    )
    parser.add_argument(
        "--set",
        dest="overrides",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="override a variable from the template (repeatable)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.template.is_file():
        print(f"error: template {args.template} not found", file=sys.stderr)
        return 1
    if args.output.exists() and not args.force:
        print(
            f"error: {args.output} already exists; use --force to replace it "
            "(this rotates every generated secret)",
            file=sys.stderr,
        )
        return 1

    try:
        content = apply_overrides(render(args.template.read_text(encoding="utf-8")), args.overrides)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    write_private(args.output, content)
    print(f"Wrote {args.output} with newly generated secrets.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
