"""Персональное ранжирование прокси по безопасному техническому профилю клиента."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Iterable, Mapping

from app.proxy.catalog import secret_type


_EFFECTIVE_TYPES = {"slow-2g", "2g", "3g", "4g", "unknown"}
_NETWORK_TYPES = {"cellular", "wifi", "ethernet", "unknown"}
_DEVICE_TYPES = {"mobile", "tablet", "desktop", "unknown"}


@dataclass(frozen=True, slots=True)
class ClientProfile:
    """Нечувствительные характеристики соединения без содержимого трафика."""

    device: str = "unknown"
    network: str = "unknown"
    effective_type: str = "unknown"
    rtt_ms: int = 0
    downlink_mbps: float = 0.0
    save_data: bool = False
    platform: str = "unknown"

    @property
    def is_constrained(self) -> bool:
        return (
            self.save_data
            or self.effective_type in {"slow-2g", "2g", "3g"}
            or self.rtt_ms >= 250
            or (0 < self.downlink_mbps < 2.0)
        )

    def as_dict(self) -> dict:
        return {
            "device": self.device,
            "network": self.network,
            "effective_type": self.effective_type,
            "rtt_ms": self.rtt_ms,
            "downlink_mbps": self.downlink_mbps,
            "save_data": self.save_data,
            "platform": self.platform,
        }

    def summary(self) -> str:
        device = {
            "mobile": "телефон",
            "tablet": "планшет",
            "desktop": "компьютер",
        }.get(self.device, "устройство")
        network = {
            "cellular": "мобильная сеть",
            "wifi": "Wi-Fi",
            "ethernet": "кабельная сеть",
        }.get(self.network, "тип сети не определён")
        quality = "экономный профиль" if self.is_constrained else "обычный профиль"
        return f"{device}, {network}, {quality}"


def _bounded_int(value: object, minimum: int, maximum: int) -> int:
    try:
        return max(minimum, min(maximum, int(float(value or 0))))
    except (TypeError, ValueError, OverflowError):
        return 0


def _bounded_float(value: object, minimum: float, maximum: float) -> float:
    try:
        number = float(value or 0)
        return max(minimum, min(maximum, number)) if math.isfinite(number) else 0.0
    except (TypeError, ValueError):
        return 0.0


def normalize_client_profile(raw: Mapping[str, object] | None) -> ClientProfile:
    data = raw if isinstance(raw, Mapping) else {}
    device = str(data.get("device", "unknown")).lower()
    network = str(data.get("network", "unknown")).lower()
    effective_type = str(data.get("effective_type", "unknown")).lower()
    platform = str(data.get("platform", "unknown")).lower()[:32]
    return ClientProfile(
        device=device if device in _DEVICE_TYPES else "unknown",
        network=network if network in _NETWORK_TYPES else "unknown",
        effective_type=effective_type if effective_type in _EFFECTIVE_TYPES else "unknown",
        rtt_ms=_bounded_int(data.get("rtt_ms"), 0, 5000),
        downlink_mbps=_bounded_float(data.get("downlink_mbps"), 0.0, 1000.0),
        save_data=bool(data.get("save_data", False)),
        platform=platform or "unknown",
    )


def _stable_jitter(user_id: int | None, proxy_id: str) -> float:
    """Небольшая стабильная развязка ничьих, персональная для пользователя."""
    seed = f"{user_id or 0}:{proxy_id}".encode("utf-8", errors="ignore")
    return int.from_bytes(hashlib.blake2s(seed, digest_size=2).digest(), "big") / 65535


def personalize_proxies(
    proxies: Iterable[dict],
    profile: ClientProfile,
    *,
    user_id: int | None = None,
) -> list[dict]:
    """Rank by measured evidence; device and bandwidth do not prove circumvention."""
    from app.proxy.selection_service import rank_candidates
    return rank_candidates(proxies, network=profile.network)
