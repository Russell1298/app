"""
Network egress guard — SSRF (Server-Side Request Forgery) protection.

Every scanner makes outbound HTTP / TLS / DNS requests to a *user-supplied*
domain. Domain-name validation alone is not enough: an attacker can register
a perfectly valid domain (or abuse a wildcard-DNS service such as nip.io) and
point it at a private, loopback, link-local, or cloud-metadata IP address.
The scanner would then fetch internal resources on the attacker's behalf and
return the response body in the report — classic SSRF leading to full server
or cloud-account compromise (e.g. reading 169.254.169.254 IAM credentials).

This module resolves a hostname and refuses it if *any* resolved address is
not a public, globally-routable unicast IP. Call assert_public_host() (or the
async wrapper) once before scanning a target.

Note on DNS rebinding: a fast-flipping DNS record could pass this pre-flight
check and then resolve to a private IP at request time (TOCTOU). Fully closing
that requires pinning the connection to the validated IP. This guard blocks the
overwhelming majority of SSRF — directly-pointed records, nip.io-style wildcard
services, and metadata endpoints — and is the correct first layer.
"""

import asyncio
import ipaddress
import socket


class UnsafeTargetError(ValueError):
    """Raised when a scan target resolves to a non-public IP address."""


def _is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True only for globally-routable public unicast addresses."""
    # IPv4-mapped / translated IPv6 (e.g. ::ffff:127.0.0.1) can smuggle a
    # private IPv4 — unwrap and re-check the embedded address.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return _is_public_ip(ip.ipv4_mapped)
    return not (
        ip.is_private        # 10/8, 172.16/12, 192.168/16, fc00::/7, fd00::/8 …
        or ip.is_loopback    # 127/8, ::1
        or ip.is_link_local  # 169.254/16 (cloud metadata!), fe80::/10
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified  # 0.0.0.0, ::
    )


def resolve_public_ips(host: str) -> list[str]:
    """
    Resolve *host* to every A/AAAA address and assert each one is public.

    Returns the sorted list of resolved IP strings on success.
    Raises UnsafeTargetError if resolution fails or any address is non-public.
    """
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeTargetError(f"Could not resolve {host}.") from exc

    ips = {info[4][0] for info in infos}
    if not ips:
        raise UnsafeTargetError(f"Could not resolve {host}.")

    for ip_str in ips:
        ip = ipaddress.ip_address(ip_str.split("%")[0])  # strip IPv6 zone id
        if not _is_public_ip(ip):
            raise UnsafeTargetError(
                f"{host} resolves to a non-public address ({ip_str}); "
                "refusing to scan internal infrastructure."
            )
    return sorted(ips)


def assert_public_host(host: str) -> None:
    """Raise UnsafeTargetError unless *host* resolves only to public IPs."""
    resolve_public_ips(host)


async def assert_public_host_async(host: str) -> None:
    """Async wrapper — runs the blocking DNS lookup off the event loop."""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, assert_public_host, host)
