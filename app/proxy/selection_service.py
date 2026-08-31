"""One evidence-based selection policy shared by the site and Telegram bot."""
from __future__ import annotations

import ipaddress
import math
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

from app.proxy.decoder import decode_secret

STRONG_LEVELS = {"auth_key", "auth-key", "authenticated", "full", "session", "sustained"}
NEGATIVE_OUTCOMES = {"connect_timeout", "connection_refused", "reset", "proxy_handshake_failed",
                     "auth_key_failed", "invalid_response", "mtproto_invalid_response", "failed"}


def timestamp(value) -> float:
    try:
        if isinstance(value, datetime):
            return value.replace(tzinfo=value.tzinfo or timezone.utc).timestamp()
        if isinstance(value, (int, float)):
            return float(value) if math.isfinite(value) else 0.0
        if isinstance(value, str):
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).timestamp()
    except (TypeError, ValueError, OverflowError):
        pass
    return 0.0


def _context(obs: dict) -> tuple:
    return tuple(str(obs.get(key) or "") for key in
                 ("agent_id", "network_key", "network_epoch", "resolved_ip", "ip_family", "client_profile_id", "dc_id"))


def _observations(proxy: dict) -> list[dict]:
    observations = proxy.get("observations") or []
    if not isinstance(observations, list):
        observations = []
    result = []
    for value in observations:
        if not isinstance(value, dict):
            continue
        payload = value.get("payload")
        observation = {**value, **payload} if isinstance(payload, dict) else dict(value)
        observation.setdefault("checked_at", observation.get("measured_at"))
        result.append(observation)
    # A checked row can carry the observation until PostgreSQL read-back.
    if isinstance(proxy.get("observation"), dict):
        result.append(dict(proxy["observation"]))
    return result


def _network_tier(obs: dict, network: str) -> int:
    country = str(obs.get("probe_country") or obs.get("country") or "").upper()
    access = str(obs.get("access_type") or "unknown").lower()
    key = str(obs.get("network_key") or "")
    if country == "RU":
        if network not in {"", "unknown", "all", "wifi", "ethernet", "cellular"} and key == network:
            return 6
        if network == "cellular" and access in {"cellular", "mobile"}:
            return 5
        if network in {"wifi", "ethernet"} and access in {"home", "fixed", "residential"}:
            return 5
        if access in {"home", "fixed", "residential", "cellular", "mobile"}:
            return 4
        return 3 if access == "datacenter" else 2
    return 1


def _label(obs: dict) -> str:
    country = str(obs.get("probe_country") or obs.get("country") or "").upper()
    access = str(obs.get("access_type") or "unknown")
    if country == "RU":
        description = {"home": "домашней", "residential": "домашней", "fixed": "домашней",
                       "mobile": "мобильной", "cellular": "мобильной", "datacenter": "датацентровой"}.get(access, "указанной")
        return "MTProto проверен в " + description + " сети РФ"
    if str(obs.get("network_key", "")).startswith("us-oregon"):
        return "MTProto проверен из Орегона; сеть РФ не проверена"
    return "MTProto проверен из " + (country or "указанной сети") + "; сеть пользователя не проверена"


def evidence_for(proxy: dict, *, network: str = "unknown", now: float | None = None,
                 client_profile_id: str | None = None) -> dict:
    current = time.time() if now is None else now
    latest: dict[tuple, dict] = {}
    all_obs = _observations(proxy)
    allowed_ips = proxy.get("resolved_ips")
    for obs in all_obs:
        measured = timestamp(obs.get("checked_at"))
        if not measured or measured > current + 30:
            continue
        if obs.get("agent_healthy") is False or obs.get("control_ok") is False:
            continue
        if client_profile_id and obs.get("client_profile_id") != client_profile_id:
            continue
        # This resolver snapshot belongs to Oregon. Split DNS may legitimately
        # return a different peer to a Russian node; its measurement stays independent.
        local_dns = str(obs.get("network_key", "")).startswith("us-oregon") or obs.get("agent_id") == "oregon"
        if local_dns and isinstance(allowed_ips, list) and allowed_ips and obs.get("resolved_ip") not in allowed_ips:
            continue
        outcome, level = str(obs.get("outcome", "")), str(obs.get("level", ""))
        if outcome != "success" and outcome not in NEGATIVE_OUTCOMES:
            continue
        # TLS-cover failures and successful TCP never supersede an MTProto measurement.
        if level not in STRONG_LEVELS and not (level == "tcp" and outcome in NEGATIVE_OUTCOMES):
            continue
        key = _context(obs)
        if measured >= timestamp(latest.get(key, {}).get("checked_at")):
            latest[key] = obs
    fresh = [obs for obs in latest.values() if obs.get("outcome") == "success"
             and str(obs.get("level")) in STRONG_LEVELS
             and current < timestamp(obs.get("valid_until")) <= timestamp(obs.get("checked_at")) + 3600]
    matching_failure = [obs for obs in latest.values()
                        if obs.get("outcome") in NEGATIVE_OUTCOMES
                        and current - timestamp(obs.get("checked_at")) < 300
                        and (str(obs.get("network_key")) == network if network not in {"unknown", "all", "", "wifi", "ethernet", "cellular"} else False)]
    if matching_failure:
        newest_fail = max(timestamp(obs.get("checked_at")) for obs in matching_failure)
        # A different route/IP may still have independent fresh evidence, but never relabel
        # foreign proof as a success for the user's explicitly failing network.
        fresh = [obs for obs in fresh if _network_tier(obs, network) >= 5
                 and timestamp(obs.get("checked_at")) > newest_fail]
    if fresh:
        best = max(fresh, key=lambda obs: (_network_tier(obs, network), timestamp(obs.get("checked_at"))))
        successes = {(obs.get("network_key"), int(timestamp(obs.get("checked_at")) // 60))
                     for obs in all_obs if obs.get("outcome") == "success"
                     and str(obs.get("level")) in STRONG_LEVELS
                     and current - 3600 < timestamp(obs.get("checked_at")) <= current}
        return {"status": "verified", "level": "auth_key", "tier": _network_tier(best, network),
                "network_key": best.get("network_key", "unknown"),
                "probe_country": best.get("probe_country", best.get("country", "")),
                "access_type": best.get("access_type", "unknown"),
                "client_profile_id": best.get("client_profile_id", "unknown"),
                "engine_version": best.get("engine_version", "unknown"),
                "resolved_ip": best.get("resolved_ip"), "ip_family": best.get("ip_family"),
                "dc_id": best.get("dc_id"), "checked_at": best.get("checked_at"),
                "valid_until": best.get("valid_until"), "duration_ms": best.get("duration_ms"),
                "successful_windows": len(successes), "coverage_label": _label(best),
                "reasons": [_label(best)], "has_conflicts": bool(matching_failure)}
    strong_history = any(str(obs.get("level")) in STRONG_LEVELS and obs.get("outcome") == "success" for obs in all_obs)
    failed = matching_failure or [obs for obs in latest.values() if obs.get("outcome") in NEGATIVE_OUTCOMES
                                 and current - timestamp(obs.get("checked_at")) < 300]
    status = "failed_here" if failed else "stale" if strong_history else "unverified"
    label = {"failed_here": "Последняя протокольная проверка не прошла в проверяемых условиях",
             "stale": "Предыдущее подтверждение устарело; нужна новая проверка",
             "unverified": "Протокольная проверка ещё не подтверждена"}[status]
    return {"status": status, "level": "none", "tier": 0, "network_key": "unknown",
            "probe_country": "", "access_type": "unknown", "client_profile_id": "unknown",
            "checked_at": None, "valid_until": None, "duration_ms": None,
            "coverage_label": label, "reasons": [label], "has_conflicts": bool(failed)}


def _diversity_key(proxy: dict) -> str:
    value = proxy.get("evidence", {}).get("resolved_ip") or proxy.get("host") or proxy.get("server") or ""
    try:
        ip = ipaddress.ip_address(value)
        return str(ipaddress.ip_network(f"{ip}/{24 if ip.version == 4 else 48}", strict=False))
    except ValueError:
        return str(value).lower()


@dataclass(slots=True)
class SelectionResult:
    proxy: dict | None = None
    reserves: list[dict] = field(default_factory=list)
    status: str = "empty"
    reasons: list[str] = field(default_factory=list)
    candidates: list[dict] = field(default_factory=list)

    @property
    def proxies(self) -> list[dict]:
        return ([self.proxy] if self.proxy is not None else []) + self.reserves

    def to_dict(self) -> dict:
        return {"status": self.status, "proxy": self.proxy, "reserves": self.reserves,
                "evidence": self.proxy.get("evidence") if self.proxy else None,
                "reasons": self.reasons}


def select_proxies(proxies: Iterable[dict], *, network: str = "unknown", region: str = "all",
                   proxy_type: str = "all", sort_by: str = "recommended", skip_ids=None,
                   limit: int = 3, allow_unverified: bool = False, now: float | None = None,
                   client_profile_id: str | None = None) -> SelectionResult:
    current = time.time() if now is None else now
    skipped = set(skip_ids or ())
    candidates = []
    for original in proxies:
        if original.get("id") in skipped or original.get("blocked") or original.get("admin_blocked"):
            continue
        decoded = decode_secret(str(original.get("secret", "")))
        if not decoded.is_valid:
            continue
        if proxy_type not in {"", "all"} and proxy_type.lower() != decoded.generation.lower():
            continue
        # Country filters must use actual metadata, never the SNI domain's suffix.
        country = str(original.get("server_country") or "").upper()
        if region == "RU" and country != "RU":
            continue
        if region == "EU" and country not in {"EU", "DE", "NL", "FR", "FI", "SE", "PL", "IT", "ES", "IE", "BE", "AT", "DK", "CZ", "EE", "LV", "LT", "PT", "RO", "BG", "GR", "HU", "SK", "SI", "HR", "CY", "MT", "LU"}:
            continue
        proxy = dict(original)
        proxy["secret"] = decoded.raw
        proxy.setdefault("server", proxy.get("host", ""))
        proxy["type"] = {"faketls": "FakeTLS", "randpad": "RandPad", "plain": "Plain"}[decoded.generation]
        proxy["evidence"] = evidence_for(proxy, network=network, now=current, client_profile_id=client_profile_id)
        proxy["match_reasons"] = proxy["evidence"]["reasons"]
        candidates.append(proxy)
    verified = [p for p in candidates if p["evidence"]["status"] == "verified"]
    pool = verified or ([p for p in candidates if p["evidence"]["status"] != "failed_here"] if allow_unverified else [])
    def order_key(p):
        proof = p["evidence"]
        recent = -timestamp(proof.get("checked_at"))
        windows = -int(proof.get("successful_windows", 0))
        duration = proof.get("duration_ms")
        duration = duration if isinstance(duration, (int, float)) else 999999
        if sort_by == "ping":
            within_tier = (duration, recent, windows)
        elif sort_by == "freshness":
            within_tier = (recent, windows, duration)
        else:
            within_tier = (windows, recent, duration)
        pin = -int(bool(p.get("admin_recommended"))) if proof["status"] == "verified" else 0
        return (-proof["tier"], pin, *within_tier, str(p.get("id", "")))

    pool.sort(key=order_key)
    chosen, endpoints, groups, asns = [], set(), set(), set()
    for proxy in pool:
        endpoint = (proxy.get("host") or proxy.get("server"), proxy.get("port"))
        group, asn = _diversity_key(proxy), proxy.get("asn")
        if endpoint in endpoints or group in groups or asn and asn in asns:
            continue
        chosen.append(proxy)
        endpoints.add(endpoint)
        groups.add(group)
        if asn:
            asns.add(asn)
        if len(chosen) >= max(1, min(int(limit), 300)):
            break
    if chosen:
        status = "verified" if verified else "unverified"
        ordered = pool + [p for p in candidates if p not in pool]
        return SelectionResult(chosen[0], chosen[1:], status, chosen[0]["match_reasons"], ordered)
    return SelectionResult(status="pending" if candidates else "empty",
                           reasons=["Нужна свежая протокольная проверка" if candidates else "Нет вариантов по выбранным фильтрам"],
                           candidates=candidates)


def rank_candidates(proxies: Iterable[dict], **kwargs) -> list[dict]:
    kwargs["allow_unverified"] = True
    kwargs["limit"] = 300
    return select_proxies(proxies, **kwargs).candidates
