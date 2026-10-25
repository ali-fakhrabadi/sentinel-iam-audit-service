from __future__ import annotations

import pytest
from django.core.exceptions import ImproperlyConfigured

from config.env import env_bool, env_int, env_list, env_required, env_str

VAR = "SENTINEL_TEST_VARIABLE"


@pytest.fixture(autouse=True)
def _unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(VAR, raising=False)


def test_env_str_uses_default_when_missing_or_blank(monkeypatch: pytest.MonkeyPatch) -> None:
    assert env_str(VAR, "fallback") == "fallback"
    monkeypatch.setenv(VAR, "   ")
    assert env_str(VAR, "fallback") == "fallback"
    monkeypatch.setenv(VAR, "  value  ")
    assert env_str(VAR, "fallback") == "value"


def test_env_required_rejects_missing_and_blank(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ImproperlyConfigured, match=VAR):
        env_required(VAR)
    monkeypatch.setenv(VAR, " ")
    with pytest.raises(ImproperlyConfigured, match=VAR):
        env_required(VAR)
    monkeypatch.setenv(VAR, "secret")
    assert env_required(VAR) == "secret"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1", True),
        ("TRUE", True),
        ("yes", True),
        ("On", True),
        ("0", False),
        ("false", False),
        ("NO", False),
        ("off", False),
    ],
)
def test_env_bool_parses_common_spellings(
    monkeypatch: pytest.MonkeyPatch, raw: str, expected: bool
) -> None:
    monkeypatch.setenv(VAR, raw)
    assert env_bool(VAR, default=not expected) is expected


def test_env_bool_default_and_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    assert env_bool(VAR, default=True) is True
    monkeypatch.setenv(VAR, "maybe")
    with pytest.raises(ImproperlyConfigured, match="boolean"):
        env_bool(VAR, default=False)


def test_env_int_parses_and_enforces_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    assert env_int(VAR, default=7) == 7
    monkeypatch.setenv(VAR, "42")
    assert env_int(VAR, default=7, minimum=1, maximum=100) == 42
    with pytest.raises(ImproperlyConfigured, match=">= 50"):
        env_int(VAR, default=7, minimum=50)
    with pytest.raises(ImproperlyConfigured, match="<= 10"):
        env_int(VAR, default=7, maximum=10)
    monkeypatch.setenv(VAR, "forty-two")
    with pytest.raises(ImproperlyConfigured, match="integer"):
        env_int(VAR, default=7)


def test_env_int_validates_default_against_bounds() -> None:
    with pytest.raises(ImproperlyConfigured):
        env_int(VAR, default=0, minimum=1)


def test_env_list_splits_strips_and_drops_blanks(monkeypatch: pytest.MonkeyPatch) -> None:
    assert env_list(VAR, default=["a"]) == ["a"]
    monkeypatch.setenv(VAR, " http://a.test , ,http://b.test,")
    assert env_list(VAR, default=[]) == ["http://a.test", "http://b.test"]


def test_env_list_default_is_copied() -> None:
    default = ["x"]
    result = env_list(VAR, default=default)
    result.append("y")
    assert default == ["x"]
