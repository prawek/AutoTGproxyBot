"""Variant identifiers fit Telegram callbacks and distinguish secrets."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re

from app.proxy.decoder import canonical_secret


def normalize_host(host: str) -> str:
    if not isinstance(host, str):
        raise ValueError("Invalid host")
    value = host.strip().strip("[]").rstrip(".").lower()
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        pass
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid host") from exc
    if len(value) > 253 or "." not in value or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in value.split(".")
    ):
        raise ValueError("Invalid host")
    return value


def variant_fingerprint(host: str, port: int, secret: str) -> str:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("Invalid port")
    payload = json.dumps([normalize_host(host), port, canonical_secret(secret)], separators=(",", ":"))
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def make_variant_id(host: str, port: int, secret: str) -> str:
    return variant_fingerprint(host, port, secret)[:32]
