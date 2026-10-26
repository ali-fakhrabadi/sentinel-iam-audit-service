from __future__ import annotations

import pytest

import config.settings as project_settings
from apps.webhooks.ssrf import UnsafeDestinationError, check_destination, is_public_address


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("http://hooks.example.com/in", "scheme_not_allowed"),
        ("ftp://hooks.example.com/in", "scheme_not_allowed"),
        ("https://user:pass@hooks.example.com/in", "credentials_in_url"),
        ("https:///no-host", "invalid_url"),
        ("https://hooks.example.com:99999/in", "invalid_url"),
        ("https://localhost/in", "private_address"),
        ("https://api.localhost/in", "private_address"),
        ("https://127.0.0.1/in", "private_address"),
        ("https://[::1]/in", "private_address"),
        ("https://10.1.2.3/in", "private_address"),
        ("https://172.16.5.4/in", "private_address"),
        ("https://192.168.1.10/in", "private_address"),
        ("https://100.64.0.1/in", "private_address"),
        ("https://169.254.169.254/latest/meta-data/", "private_address"),
        ("https://0.0.0.0/in", "private_address"),
        ("https://224.0.0.1/in", "private_address"),
        ("https://[::ffff:127.0.0.1]/in", "private_address"),
        ("https://[fd00::1]/in", "private_address"),
        ("https://[fe80::1]/in", "private_address"),
        ("https://does-not-exist.example/in", "unresolvable"),
    ],
)
def test_unsafe_destinations_are_rejected(dns: dict[str, list[str]], url: str, code: str) -> None:
    with pytest.raises(UnsafeDestinationError) as excinfo:
        check_destination(url)

    assert excinfo.value.code == code


@pytest.mark.parametrize(
    "addresses",
    [
        ["10.0.0.5"],
        ["169.254.169.254"],  # a public name pointing at the cloud metadata service
        ["93.184.216.34", "127.0.0.1"],  # one bad record poisons the whole answer
    ],
)
def test_names_resolving_to_internal_addresses_are_rejected(
    dns: dict[str, list[str]], addresses: list[str]
) -> None:
    dns["hooks.attacker.test"] = addresses

    with pytest.raises(UnsafeDestinationError) as excinfo:
        check_destination("https://hooks.attacker.test/in")

    assert excinfo.value.code == "private_address"


def test_public_destinations_are_pinned_to_the_validated_address(dns: dict[str, list[str]]) -> None:
    destination = check_destination("https://Hooks.Example.com:8443/in?team=soc")

    assert destination.addresses == ("93.184.216.34",)
    assert destination.pinned_url() == "https://93.184.216.34:8443/in?team=soc"
    assert destination.host_header == "hooks.example.com:8443"


def test_default_ports_are_omitted(dns: dict[str, list[str]]) -> None:
    destination = check_destination("https://hooks.example.com/in")

    assert destination.pinned_url() == "https://93.184.216.34/in"
    assert destination.host_header == "hooks.example.com"


def test_public_ipv6_literals_are_allowed() -> None:
    destination = check_destination("https://[2606:4700:4700::1111]/in")

    assert destination.pinned_url() == "https://[2606:4700:4700::1111]/in"


def test_insecure_mode_allows_plain_http_to_local_receivers() -> None:
    destination = check_destination("http://127.0.0.1:9000/hook", allow_insecure=True)

    assert destination.pinned_url() == "http://127.0.0.1:9000/hook"


def test_insecure_mode_is_off_outside_debug() -> None:
    assert project_settings.DEBUG is False
    assert project_settings.WEBHOOK_ALLOW_INSECURE_DESTINATIONS is False


@pytest.mark.parametrize(
    ("address", "public"),
    [("93.184.216.34", True), ("8.8.8.8", True), ("192.0.2.1", False), ("::ffff:10.0.0.1", False)],
)
def test_address_classification(address: str, public: bool) -> None:
    assert is_public_address(address) is public
