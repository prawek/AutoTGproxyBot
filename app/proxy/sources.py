"""Источники прокси и их настройка.

Небольшой проверяемый список лучше сотен вымышленных/дублирующихся каналов.
Дополнительные источники задаются без правки кода через окружение.
"""

from __future__ import annotations

import os
import re
from urllib.parse import urlsplit


DEFAULT_CHANNELS: tuple[str, ...] = (
    "ProxyMTProto",
    "MTProto_Proxy",
    "proxymtproto_ru",
    "VipProxyMTProto",
    "MTProxyList",
    "FreeProxyMTProto",
    "bestmtproxy",
    "ProxyForTelegram",
    "freemtproxy",
    "tgmtproxylist",
    "MTProtoProxies",
    "FastMTProxy",
    "free_mtproto_proxy",
    "TGproxies",
    "proxy4telegram",
)

DEFAULT_SOURCE_URLS: tuple[str, ...] = (
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
    "https://raw.githubusercontent.com/Argh94/Proxy-List/main/MTProto.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
)


def _csv_env(name: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in os.getenv(name, "").split(",") if item.strip())


def get_channels() -> list[str]:
    configured = _csv_env("PROXY_CHANNELS")
    values = configured or DEFAULT_CHANNELS
    return list(dict.fromkeys(value.lstrip("@").strip() for value in values
                             if re.fullmatch(r"@?[A-Za-z0-9_]{1,64}", value.strip())))[:100]


def get_source_urls() -> list[str]:
    configured = _csv_env("PROXY_SOURCE_URLS")
    values = configured or DEFAULT_SOURCE_URLS
    return list(dict.fromkeys(value.strip() for value in values
                             if urlsplit(value).scheme == "https" and urlsplit(value).hostname
                             and not urlsplit(value).username and not urlsplit(value).password))[:100]
