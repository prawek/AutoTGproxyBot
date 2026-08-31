"""Public-target-only networking with DNS validation and address pinning."""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Any

import aiohttp
from aiohttp.abc import AbstractResolver

from app.proxy.identity import normalize_host


class UnsafeTarget(ValueError):
    pass


def validate_public_ip(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise UnsafeTarget("Not an IP address") from exc
    if not ip.is_global or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        raise UnsafeTarget("Only public unicast destinations are allowed")
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        validate_public_ip(str(ip.ipv4_mapped))
    if isinstance(ip, ipaddress.IPv6Address) and (
        ip in ipaddress.ip_network("64:ff9b::/96")
        or ip in ipaddress.ip_network("64:ff9b:1::/48")
        or ip.sixtofour is not None or ip.teredo is not None
    ):
        raise UnsafeTarget("Transition address is not allowed")
    return ip.compressed


async def resolve_public_addresses(host: str, port: int, *, timeout: float = 4.0) -> list[str]:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise UnsafeTarget("Invalid port")
    value = normalize_host(host)
    try:
        ipaddress.ip_address(value)
    except ValueError:
        rows = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(value, port, type=socket.SOCK_STREAM), timeout=timeout
        )
        if not rows or len(rows) > 64:
            raise UnsafeTarget("Invalid DNS answer")
        addresses = list(dict.fromkeys(validate_public_ip(row[4][0]) for row in rows))
        return addresses[:8]
    return [validate_public_ip(value)]


class PublicResolver(AbstractResolver):
    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET) -> list[dict[str, Any]]:
        addresses = await resolve_public_addresses(host, port or 443)
        return [{"hostname": host, "host": address, "port": port,
                 "family": socket.AF_INET6 if ":" in address else socket.AF_INET,
                 "proto": 0, "flags": socket.AI_NUMERICHOST}
                for address in addresses if family in (socket.AF_UNSPEC, 0) or (":" in address) == (family == socket.AF_INET6)]

    async def close(self) -> None:
        pass


class PublicTCPConnector(aiohttp.TCPConnector):
    async def _resolve_host(self, host, port, traces=None):
        # aiohttp skips the resolver for IP literals, so guard that path too.
        rows = await super()._resolve_host(host, port, traces=traces)
        for row in rows:
            validate_public_ip(row["host"])
        return rows


def public_connector(**kwargs) -> aiohttp.TCPConnector:
    return PublicTCPConnector(resolver=PublicResolver(), use_dns_cache=False, **kwargs)


async def open_public_connection(host: str, port: int, *, timeout: float = 3.5):
    addresses = await resolve_public_addresses(host, port, timeout=min(timeout, 4))
    async with asyncio.timeout(timeout):
        last_error = None
        for address in addresses:
            try:
                return await asyncio.open_connection(address, port)
            except OSError as exc:
                last_error = exc
        raise last_error or OSError("No public address available")
