"""Единая типизированная конфигурация приложения из переменных окружения."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from dotenv import load_dotenv

load_dotenv()


def _env_int(name: str, default: int, *, minimum: int = 1, maximum: int = 65535) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} должен быть целым числом") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} должен быть в диапазоне {minimum}..{maximum}")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    bot_token: str
    bot_username: str
    tg_webhook_secret: str
    database_url: str
    secret_key: str
    base_url: str
    admin_password: str
    admin_path: str
    probe_region: str
    port: int
    trusted_proxy_hops: int = 0

    @classmethod
    def from_env(cls) -> "Settings":
        base_url = os.getenv("BASE_URL", os.getenv("RENDER_EXTERNAL_URL", "")).strip().rstrip("/")
        if base_url:
            parsed = urlsplit(base_url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
                raise ValueError("BASE_URL должен быть HTTP(S)-адресом без пути, пароля и параметров")
        admin_path = os.getenv("ADMIN_PATH", "admin").strip().strip("/") or "admin"
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", admin_path):
            raise ValueError("ADMIN_PATH может содержать только латинские буквы, цифры, _ и -")
        bot_username = os.getenv("BOT_USERNAME", "autotgproxysuperbot").strip().lstrip("@")
        if bot_username and not re.fullmatch(r"[A-Za-z0-9_]{5,32}", bot_username):
            raise ValueError("Неверный BOT_USERNAME")
        secret_key = os.getenv("SECRET_KEY", "").strip()
        if base_url.startswith("https://") and len(secret_key) < 32:
            raise ValueError("Для HTTPS-развёртывания SECRET_KEY должен содержать минимум 32 символа")
        return cls(
            bot_token=os.getenv("BOT_TOKEN", "").strip(),
            bot_username=bot_username,
            tg_webhook_secret=os.getenv("TG_WEBHOOK_SECRET", "").strip(),
            database_url=os.getenv("DATABASE_URL", "").strip(),
            secret_key=secret_key,
            base_url=base_url,
            admin_password=os.getenv("ADMIN_PASSWORD", "").strip(),
            admin_path=admin_path,
            probe_region=os.getenv("PROBE_REGION", "us-oregon").strip() or "us-oregon",
            port=_env_int("PORT", 5000),
            trusted_proxy_hops=_env_int("TRUSTED_PROXY_HOPS", 0, minimum=0, maximum=5),
        )

    @property
    def use_webhook(self) -> bool:
        return bool(self.bot_token and self.base_url.startswith("https://"))
