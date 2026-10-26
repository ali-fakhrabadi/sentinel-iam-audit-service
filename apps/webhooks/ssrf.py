"""Server-Side Request Forgery (SSRF) protection for webhook destinations.

Webhook URLs are attacker-controlled input. Before every delivery:

1. the URL must be ``https`` (``http`` only in DEBUG with the explicit override),
   without embedded credentials, and must name a host;
2. the host is resolved, and **every** resolved address must be a public unicast
   address: loopback, private (RFC 1918), CGNAT, link-local (including the cloud
   metadata address 169.254.169.254), multicast, reserved and unspecified ranges are
   rejected, as are IPv4-mapped IPv6 forms of them;
3. the HTTP client connects to the exact address that was validated (TLS still
   verifies the hostname through SNI), so a DNS answer that changes between check
   and connect (DNS rebinding) cannot redirect the request;
4. redirects are never followed.

Limitation: this is application-level protection. Production deployments should
also restrict egress at the network layer (firewall or egress proxy allow-list).
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit

_DEFAULT_PORTS = {"https": 443, "http": 80}
_BLOCKED_HOSTNAMES = frozenset(
    {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}
)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class UnsafeDestinationError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class Destination:
    scheme: str
    host: str
    port: int
    path: str
    addresses: tuple[str, ...]

    @property
    def host_header(self) -> str:
        default = _DEFAULT_PORTS[self.scheme]
        host = f"[{self.host}]" if ":" in self.host else self.host
        return host if self.port == default else f"{host}:{self.port}"

    def pinned_url(self) -> str:
        """The URL with the validated IP address in place of the hostname."""
        address = self.addresses[0]
        host = f"[{address}]" if ":" in address else address
        port = "" if self.port == _DEFAULT_PORTS[self.scheme] else f":{self.port}"
        return f"{self.scheme}://{host}{port}{self.path}"


def is_public_address(address: str) -> bool:
    ip: IPAddress = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast and not ip.is_reserved and not ip.is_unspecified


def resolve_host(host: str, port: int) -> list[str]:
    """All addresses the resolver returns for ``host`` (patched in tests)."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


def _split(url: str, *, allow_insecure: bool) -> tuple[SplitResult, str, int]:
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise UnsafeDestinationError("invalid_url", "The URL is not valid.") from exc
    allowed_schemes = {"https", "http"} if allow_insecure else {"https"}
    if parts.scheme not in allowed_schemes:
        raise UnsafeDestinationError(
            "scheme_not_allowed", "Only https:// destinations are allowed."
        )
    if parts.username is not None or parts.password is not None:
        raise UnsafeDestinationError("credentials_in_url", "URLs must not contain credentials.")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise UnsafeDestinationError("invalid_url", "The URL must include a host.")
    return parts, host, port or _DEFAULT_PORTS[parts.scheme]


def check_destination(url: str, *, allow_insecure: bool = False) -> Destination:
    """Validate ``url`` and resolve it to addresses that are safe to connect to."""
    parts, host, port = _split(url, allow_insecure=allow_insecure)
    if not allow_insecure and (host in _BLOCKED_HOSTNAMES or host.endswith(".localhost")):
        raise UnsafeDestinationError("private_address", "Loopback destinations are not allowed.")

    try:
        literal: IPAddress | None = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        addresses = [str(literal)]
    else:
        try:
            addresses = resolve_host(host, port)
        except (socket.gaierror, UnicodeError) as exc:
            raise UnsafeDestinationError("unresolvable", "The host name does not resolve.") from exc
    if not addresses:
        raise UnsafeDestinationError("unresolvable", "The host name does not resolve.")
    if not allow_insecure and not all(is_public_address(address) for address in addresses):
        # Reject the whole host if any record is internal: an attacker controls which
        # record a client would pick.
        raise UnsafeDestinationError(
            "private_address", "The destination resolves to a private or reserved address."
        )

    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return Destination(
        scheme=parts.scheme, host=host, port=port, path=path, addresses=tuple(addresses)
    )
