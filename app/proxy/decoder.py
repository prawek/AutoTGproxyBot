"""Strict MTProxy secret decoding; representations canonicalise to wire bytes."""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Literal

SecretGeneration = Literal["plain", "randpad", "faketls", "unknown"]


@dataclass(frozen=True, slots=True)
class DecodedSecret:
    raw: str
    generation: SecretGeneration
    core_bytes: bytes
    sni_domain: str
    is_valid: bool


def secret_bytes(secret: str) -> bytes:
    if not isinstance(secret, str):
        raise ValueError("Secret must be a string")
    value = secret.strip()
    if not 20 <= len(value) <= 1024 or any(ch.isspace() for ch in value):
        raise ValueError("Invalid secret size")
    if len(value) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", value):
        return bytes.fromhex(value)
    if not re.fullmatch(r"[A-Za-z0-9_+/\-]+={0,2}", value):
        raise ValueError("Invalid secret encoding")
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid secret encoding") from exc


def _domain(value: bytes) -> str:
    if value.startswith(b"\x00"):
        value = value[1:]
    if not value or b"\x00" in value:
        raise ValueError("Invalid SNI")
    domain = value.decode("ascii").lower().rstrip(".")
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("Invalid SNI")
    return domain


def decode_secret(secret: str) -> DecodedSecret:
    try:
        raw = secret_bytes(secret)
        canonical = raw.hex()
        if len(raw) == 16:
            return DecodedSecret(canonical, "plain", raw, "", True)
        if len(raw) == 17 and raw[0] == 0xDD:
            return DecodedSecret(canonical, "randpad", raw[1:], "", True)
        if len(raw) > 17 and raw[0] == 0xEE:
            return DecodedSecret(canonical, "faketls", raw[1:17], _domain(raw[17:]), True)
    except (ValueError, UnicodeError):
        pass
    return DecodedSecret(str(secret or "")[:1024], "unknown", b"", "", False)


def canonical_secret(secret: str) -> str:
    decoded = decode_secret(secret)
    if not decoded.is_valid:
        raise ValueError("Invalid MTProxy secret")
    return decoded.raw


def describe_secret(decoded: DecodedSecret) -> str:
    return {"plain": "Plain", "randpad": "RandPad", "faketls": "FakeTLS"}.get(decoded.generation, "Unknown")
