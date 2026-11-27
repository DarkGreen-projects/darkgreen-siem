"""Validate outbound URLs to reduce SSRF risk (notify, LLM, etc.)."""

from __future__ import annotations

import ipaddress
import socket
from contextlib import contextmanager
from typing import Any, Iterator
from urllib.parse import urlparse

import httpx

from .config import get_settings

_BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata",
    }
)

# Extra ranges beyond ipaddress.is_private (CGNAT, cloud metadata aliases).
_EXTRA_BLOCKED_NETWORKS = (
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT / carrier-grade NAT
    ipaddress.ip_network("100.100.100.200/32"),  # Alibaba metadata
)


class UnsafeUrlError(ValueError):
    """Raised when a URL is not allowed for server-side egress."""


def _host_allowlist() -> set[str]:
    raw = (getattr(get_settings(), "egress_host_allowlist", "") or "").strip()
    if not raw:
        return set()
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True
    for net in _EXTRA_BLOCKED_NETWORKS:
        if ip in net:
            return True
    return False


def _resolve_ips(hostname: str) -> list[str]:
    host = hostname.strip().lower().rstrip(".")
    if not host:
        return []
    try:
        ip = ipaddress.ip_address(host)
        return [] if _is_blocked_ip(ip) else [str(ip)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    out: list[str] = []
    for info in infos:
        addr = info[4][0]
        try:
            parsed = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if _is_blocked_ip(parsed):
            return []
        if addr not in out:
            out.append(addr)
    return out


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
    ips = _resolve_ips(host)
    return not ips


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


@contextmanager
def _force_host_resolve(hostname: str, ip: str) -> Iterator[None]:
    """Pin getaddrinfo for hostname to a previously validated public IP."""
    real_gai = socket.getaddrinfo

    def _pinned(
        host: str | bytes | None,
        port: Any,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ):
        h = host.decode() if isinstance(host, (bytes, bytearray)) else (host or "")
        if h.lower().rstrip(".") == hostname.lower().rstrip("."):
            return real_gai(ip, port, family, type, proto, flags)
        return real_gai(host, port, family, type, proto, flags)

    socket.getaddrinfo = _pinned  # type: ignore[assignment]
    try:
        yield
    finally:
        socket.getaddrinfo = real_gai  # type: ignore[assignment]


def egress_request(
    method: str,
    url: str,
    *,
    purpose: str = "egress",
    timeout: float = 8.0,
    headers: dict[str, str] | None = None,
    json: Any = None,
    **kwargs: Any,
) -> httpx.Response:
    """
    HTTP request after egress validation, with DNS pinned to a public IP
    resolved at validation time (mitigates DNS rebinding TOCTOU).
    """
    safe = validate_egress_url(url, purpose=purpose)
    # Fresh resolve immediately before connect.
    safe = validate_egress_url(safe, purpose=purpose)
    host = (urlparse(safe).hostname or "").strip().lower()
    ips = _resolve_ips(host)
    if not ips:
        raise UnsafeUrlError(f"{purpose} host unresolved or blocked at connect time")
    pin_ip = ips[0]
    req_kwargs: dict[str, Any] = {
        "method": method.upper(),
        "url": safe,
        "headers": headers,
        "timeout": timeout,
        "follow_redirects": False,
        **kwargs,
    }
    if json is not None:
        req_kwargs["json"] = json
    with _force_host_resolve(host, pin_ip):
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            return client.request(**req_kwargs)


def egress_post(url: str, **kwargs: Any) -> httpx.Response:
    return egress_request("POST", url, **kwargs)
