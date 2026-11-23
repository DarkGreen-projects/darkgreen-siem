"""Validate outbound URLs to reduce SSRF risk (notify, LLM, etc.)."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from .config import get_settings

_BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata",
    }
)


class UnsafeUrlError(ValueError):
    """Raised when a URL is not allowed for server-side egress."""


def _host_allowlist() -> set[str]:
    raw = (getattr(get_settings(), "egress_host_allowlist", "") or "").strip()
    if not raw:
        return set()
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _resolve_blocked(hostname: str) -> bool:
    host = hostname.strip().lower().rstrip(".")
    if not host:
        return True
    if host in _BLOCKED_HOSTNAMES or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return _is_blocked_ip(ip)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        # Unresolvable: fail closed for egress
        return True
    for info in infos:
        addr = info[4][0]
        try:
            if _is_blocked_ip(ipaddress.ip_address(addr)):
                return True
        except ValueError:
            continue
    return False


def validate_egress_url(url: str, *, purpose: str = "egress") -> str:
    """
    Return stripped URL if safe, else raise UnsafeUrlError.
    Requires https unless ALLOW_INSECURE_WEBHOOKS=true (http allowed then).
    Optional EGRESS_HOST_ALLOWLIST: if set, host must be listed AND not private.
    """
    text = (url or "").strip()
    if not text:
        raise UnsafeUrlError(f"{purpose} URL is empty")
    parsed = urlparse(text)
    scheme = (parsed.scheme or "").lower()
    settings = get_settings()
    allow_http = bool(getattr(settings, "allow_insecure_webhooks", False))
    if scheme == "https":
        pass
    elif scheme == "http" and allow_http:
        pass
    else:
        raise UnsafeUrlError(f"{purpose} URL must use https")
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise UnsafeUrlError(f"{purpose} URL missing host")
    if parsed.username or parsed.password:
        raise UnsafeUrlError(f"{purpose} URL must not embed credentials")
    allowlist = _host_allowlist()
    if allowlist and host not in allowlist:
        raise UnsafeUrlError(f"{purpose} host not in EGRESS_HOST_ALLOWLIST")
    if _resolve_blocked(host):
        raise UnsafeUrlError(f"{purpose} URL targets a blocked/private host")
    return text
