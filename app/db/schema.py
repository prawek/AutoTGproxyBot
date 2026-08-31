"""
db_schema.py — Схема PostgreSQL и слой доступа к данным.

Таблицы:
  proxies              — прокси-серверы (проверенные, с метриками)
  users                — аккаунты (логин + пароль + опциональный telegram_id как PK)
  pending_registrations — временные записи регистрации (пока не привязан TG)
"""

from __future__ import annotations

import hashlib
import asyncio
import json
import re
import logging
import secrets
import string
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from app.core.auth import hash_password, password_needs_rehash, verify_password

logger = logging.getLogger(__name__)


def _contains_pattern(value: str) -> str:
    escaped = value.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


# ──────────────────────────────────────────────────────────────────────────────
# DDL — proxies
# ──────────────────────────────────────────────────────────────────────────────

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS proxies (
    id           TEXT        PRIMARY KEY,
    host         TEXT        NOT NULL,
    port         INTEGER     NOT NULL CHECK (port BETWEEN 1 AND 65535),
    secret       TEXT        NOT NULL DEFAULT '',
    kind         TEXT        NOT NULL DEFAULT 'mtproto'
                             CHECK (kind IN ('mtproto', 'socks5')),
    generation   TEXT        NOT NULL DEFAULT 'unknown'
                             CHECK (generation IN ('plain', 'randpad', 'faketls', 'unknown')),
    sni_domain   TEXT        NOT NULL DEFAULT '',
    category     TEXT        NOT NULL DEFAULT 'EU'
                             CHECK (category IN ('RU', 'EU')),
    ping_ms      INTEGER     NOT NULL DEFAULT 0,
    tspu_score   INTEGER     NOT NULL DEFAULT 0 CHECK (tspu_score BETWEEN 0 AND 100),
    stability    INTEGER     NOT NULL DEFAULT 0 CHECK (stability BETWEEN 0 AND 100),
    rank         INTEGER     NOT NULL DEFAULT 9999,
    is_alive     BOOLEAN     NOT NULL DEFAULT FALSE,
    admin_recommended BOOLEAN NOT NULL DEFAULT FALSE,
    admin_recommended_at TIMESTAMPTZ,
    checked_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_proxies_alive_rank
    ON proxies (is_alive, rank)
    WHERE is_alive = TRUE;

CREATE INDEX IF NOT EXISTS idx_proxies_category
    ON proxies (category, rank)
    WHERE is_alive = TRUE;

CREATE INDEX IF NOT EXISTS idx_proxies_generation
    ON proxies (generation)
    WHERE is_alive = TRUE;

CREATE INDEX IF NOT EXISTS idx_proxies_updated
    ON proxies (updated_at DESC);
"""

CREATE_PROXY_FEEDBACK_SQL = """
CREATE TABLE IF NOT EXISTS proxy_feedback (
    proxy_id      TEXT        NOT NULL,
    telegram_id   BIGINT      NOT NULL,
    works_in_ru   BOOLEAN     NOT NULL,
    network_type  TEXT        NOT NULL DEFAULT 'unknown'
                              CHECK (network_type IN ('unknown', 'mobile', 'home', 'work')),
    operator_name TEXT        NOT NULL DEFAULT '',
    reported_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (proxy_id, telegram_id)
);
CREATE INDEX IF NOT EXISTS idx_proxy_feedback_recent
    ON proxy_feedback (proxy_id, reported_at DESC);
"""

# ──────────────────────────────────────────────────────────────────────────────
# DDL — users (новая схема для чистой установки)
# ──────────────────────────────────────────────────────────────────────────────

CREATE_USERS_SQL = """
CREATE TABLE IF NOT EXISTS users (
    telegram_id   BIGINT      PRIMARY KEY,
    account_login TEXT        NOT NULL DEFAULT '',
    password_hash  TEXT        NOT NULL DEFAULT '',
    username       TEXT        NOT NULL DEFAULT '',
    first_name    TEXT        NOT NULL DEFAULT '',
    last_name     TEXT        NOT NULL DEFAULT '',
    photo_url     TEXT        NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""

CREATE_AUTH_TOKENS_SQL = """
CREATE TABLE IF NOT EXISTS auth_tokens (
    token       TEXT        PRIMARY KEY,
    telegram_id BIGINT      REFERENCES users(telegram_id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_tokens_expires ON auth_tokens(expires_at);
"""

# ──────────────────────────────────────────────────────────────────────────────
# DDL — pending_registrations (временные записи до привязки Telegram)
# ──────────────────────────────────────────────────────────────────────────────

CREATE_PENDING_REG_SQL = """
CREATE TABLE IF NOT EXISTS pending_registrations (
    token         TEXT        PRIMARY KEY,
    account_login TEXT        NOT NULL,
    password_hash TEXT        NOT NULL,
    telegram_id   BIGINT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pending_reg_expires ON pending_registrations(expires_at);
"""


# ──────────────────────────────────────────────────────────────────────────────
# Утилиты
# ──────────────────────────────────────────────────────────────────────────────

def make_proxy_id(host: str, port: int, secret: str) -> str:
    from app.proxy.identity import make_variant_id
    return make_variant_id(host, port, secret)


def utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def _gen_password(length: int = 10) -> str:
    """Генерирует случайный пароль из букв и цифр."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _gen_login(telegram_id: int, username: str = "") -> str:
    """Логин = TG username (без @), если задан; иначе user{id}."""
    return username.lower() if username else f"user{telegram_id}"


# ──────────────────────────────────────────────────────────────────────────────
# ProxyRepository
# ──────────────────────────────────────────────────────────────────────────────

class ProxyRepository:
    def __init__(self, pool: Any) -> None:
        self._pool = pool

    async def migrate(self) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(CREATE_TABLE_SQL)
            await conn.execute(CREATE_PROXY_FEEDBACK_SQL)
            await conn.execute(
                "ALTER TABLE proxies ADD COLUMN IF NOT EXISTS "
                "admin_recommended BOOLEAN NOT NULL DEFAULT FALSE"
            )
            await conn.execute(
                "ALTER TABLE proxies ADD COLUMN IF NOT EXISTS "
                "admin_recommended_at TIMESTAMPTZ"
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_proxies_admin_recommended "
                "ON proxies (admin_recommended DESC, admin_recommended_at DESC) "
                "WHERE admin_recommended = TRUE"
            )
            await conn.execute("ALTER TABLE proxies ADD COLUMN IF NOT EXISTS probe_state TEXT NOT NULL DEFAULT 'unverified'")
            await conn.execute("ALTER TABLE proxies ADD COLUMN IF NOT EXISTS selection_metadata JSONB NOT NULL DEFAULT '{}'")
            await conn.execute("ALTER TABLE proxies ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()")
            await conn.execute("ALTER TABLE proxies ADD COLUMN IF NOT EXISTS blocked BOOLEAN NOT NULL DEFAULT FALSE")
        from app.db.probes import ProbeRepository
        await ProbeRepository(self._pool).migrate()
        logger.info("db: proxy variants and probe evidence migrated")

    async def record_feedback(
        self,
        proxy_id: str,
        telegram_id: int,
        works_in_ru: bool,
        *,
        network_type: str = "unknown",
        operator_name: str = "",
    ) -> None:
        if network_type not in {"unknown", "mobile", "home", "work"}:
            network_type = "unknown"
        operator_name = operator_name.strip()[:64]
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO proxy_feedback
                    (proxy_id, telegram_id, works_in_ru, network_type, operator_name, reported_at)
                VALUES ($1, $2, $3, $4, $5, NOW())
                ON CONFLICT (proxy_id, telegram_id) DO UPDATE SET
                    works_in_ru   = EXCLUDED.works_in_ru,
                    network_type  = EXCLUDED.network_type,
                    operator_name = EXCLUDED.operator_name,
                    reported_at   = NOW()
                """,
                proxy_id, telegram_id, works_in_ru, network_type, operator_name,
            )

    async def get_feedback_summaries(self, proxy_ids: list[str]) -> dict[str, dict[str, int]]:
        if not proxy_ids:
            return {}
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT proxy_id,
                       COUNT(*) FILTER (WHERE works_in_ru)     AS successes,
                       COUNT(*) FILTER (WHERE NOT works_in_ru) AS failures
                FROM proxy_feedback
                WHERE proxy_id = ANY($1::text[])
                  AND reported_at > NOW() - INTERVAL '14 days'
                GROUP BY proxy_id
                """,
                proxy_ids,
            )
        return {
            row["proxy_id"]: {
                "successes": int(row["successes"] or 0),
                "failures": int(row["failures"] or 0),
            }
            for row in rows
        }

    async def purge_old_feedback(self, days: int = 30) -> int:
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM proxy_feedback WHERE reported_at < NOW() - INTERVAL '1 day' * $1",
                days,
            )
        return int(result.split()[-1])

    async def upsert_proxy(self, record: dict[str, Any]) -> None:
        await self.upsert_many([record])

    async def upsert_many(self, records: list[dict[str, Any]]) -> None:
        if not records:
            return
        from app.proxy.identity import canonical_secret
        rows = []
        now = utcnow()
        for record in records:
            secret = canonical_secret(record["secret"])
            variant_id = make_proxy_id(record["host"], record["port"], secret)
            metadata = {k: record[k] for k in ("sources", "source_count", "server_country", "asn") if k in record}
            rows.append((variant_id, str(record["host"]).lower().rstrip("."), int(record["port"]), secret,
                str(record.get("kind", "mtproto")), str(record.get("generation", "unknown")),
                str(record.get("sni_domain", "")), str(record.get("category", "EU")),
                max(0, int(record.get("ping_ms", 0) or 0)), max(0, min(100, int(record.get("tspu_score", 0) or 0))),
                max(0, min(100, int(record.get("stability", 0) or 0))), int(record.get("rank", 9999) or 9999),
                bool(record.get("is_alive", False)), record.get("checked_at"), now, now,
                str(record.get("probe_state", "unverified")), json.dumps(metadata, default=str)))
        async with self._pool.acquire() as conn:
            await conn.executemany("""INSERT INTO proxies
                (id,host,port,secret,kind,generation,sni_domain,category,ping_ms,tspu_score,stability,
                 rank,is_alive,checked_at,created_at,updated_at,probe_state,selection_metadata)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18::jsonb)
                ON CONFLICT(id) DO UPDATE SET updated_at=NOW(),last_seen_at=NOW(),
                    selection_metadata=proxies.selection_metadata || EXCLUDED.selection_metadata""", rows)

    async def record_observation(self, data: dict) -> None:
        from app.db.probes import ProbeRepository
        await ProbeRepository(self._pool).record_local_observation(data)
        # Checking a candidate never renews its discovery age. DNS membership is
        # separate metadata, used to stop reusing proof for an address no longer present.
        metadata = {"resolved_ips": data["resolved_ips"]} if data.get("resolved_ips") else {}
        async with self._pool.acquire() as conn:
            await conn.execute("""UPDATE proxies SET probe_state=$2, checked_at=$3,
                is_alive=$4, ping_ms=COALESCE($5,ping_ms), updated_at=NOW(),
                selection_metadata=selection_metadata || $6::jsonb WHERE id=$1""",
                data["variant_id"], data["outcome"], datetime.fromisoformat(data["checked_at"]),
                data["outcome"] == "success", data.get("duration_ms"), json.dumps(metadata))

    async def get_selection_snapshot(self, limit: int = 300) -> list[dict]:
        from app.db.probes import ProbeRepository
        async with self._pool.acquire() as conn:
            rows = await conn.fetch("""SELECT p.* FROM proxies p WHERE length(id)=32 AND NOT blocked
                AND last_seen_at>NOW()-INTERVAL '1 day'
                ORDER BY admin_recommended DESC,
                    EXISTS(SELECT 1 FROM probe_observations o WHERE o.variant_id=p.id AND o.valid_until>NOW()) DESC,
                    last_seen_at DESC,checked_at ASC NULLS FIRST,id LIMIT $1""", max(1,min(limit,1000)))
        observations = await ProbeRepository(self._pool).latest_observations([row["id"] for row in rows])
        result = []
        for row in rows:
            item = dict(row)
            metadata = item.pop("selection_metadata", {})
            if isinstance(metadata, str):
                metadata = json.loads(metadata)
            item = {**metadata, **item}
            item["server"] = item["host"]
            item["observations"] = observations.get(item["id"], [])
            result.append(item)
        return result

    async def get_best(self, *, category: str | None = None, generation: str | None = None,
                       limit: int = 10) -> list[dict[str, Any]]:
        rows = await self.get_selection_snapshot(limit=max(limit, 300))
        if category:
            rows = [r for r in rows if r.get("category") == category]
        if generation:
            rows = [r for r in rows if r.get("generation") == generation]
        return rows[:max(1,min(limit,1000))]

    async def mark_dead(self, proxy_ids: list[str]) -> None:
        if not proxy_ids:
            return
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE proxies SET is_alive = FALSE, updated_at = NOW() "
                "WHERE id = ANY($1::text[])",
                proxy_ids,
            )

    async def set_admin_recommendation(self, proxy_id: str, recommended: bool) -> dict[str, Any] | None:
        """Pin only freshly authenticated variants; pins never override expiry."""
        if recommended:
            from app.db.probes import ProbeRepository
            from app.proxy.selection_service import select_proxies
            async with self._pool.acquire() as conn:
                candidate = await conn.fetchrow("""SELECT * FROM proxies WHERE id=$1 AND length(id)=32
                    AND NOT blocked AND last_seen_at>NOW()-INTERVAL '1 day'""", proxy_id)
            if not candidate:
                return None
            item = dict(candidate)
            metadata = item.pop("selection_metadata", {})
            if isinstance(metadata, str):
                metadata = json.loads(metadata)
            item = {**metadata, **item}
            item["observations"] = (await ProbeRepository(self._pool).latest_observations([proxy_id])).get(proxy_id, [])
            if select_proxies([item]).proxy is None:
                return None
        async with self._pool.acquire() as conn:
            if recommended:
                row = await conn.fetchrow(
                    """
                    UPDATE proxies
                    SET admin_recommended = TRUE,
                        admin_recommended_at = NOW(),
                        updated_at = NOW()
                    WHERE id = $1 AND NOT blocked AND last_seen_at>NOW()-INTERVAL '1 day'
                    RETURNING id, admin_recommended, admin_recommended_at
                    """,
                    proxy_id,
                )
            else:
                row = await conn.fetchrow(
                    """
                    UPDATE proxies
                    SET admin_recommended = FALSE,
                        admin_recommended_at = NULL,
                        updated_at = NOW()
                    WHERE id = $1
                    RETURNING id, admin_recommended, admin_recommended_at
                    """,
                    proxy_id,
                )
        return dict(row) if row else None

    async def get_admin_recommendations(self, proxy_ids: list[str]) -> dict[str, Any]:
        if not proxy_ids:
            return {}
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id, admin_recommended_at
                FROM proxies
                WHERE id = ANY($1::text[]) AND admin_recommended = TRUE
                """,
                proxy_ids,
            )
        return {row["id"]: row["admin_recommended_at"] for row in rows}

    async def purge_old_dead(self, days: int = 7) -> int:
        async with self._pool.acquire() as conn:
            value = await conn.execute("""DELETE FROM proxies p WHERE NOT p.blocked
                AND NOT p.admin_recommended AND p.last_seen_at < NOW()-INTERVAL '1 day' * $1
                AND NOT EXISTS(SELECT 1 FROM probe_observations o WHERE o.variant_id=p.id
                    AND o.valid_until>NOW())
                AND NOT EXISTS(SELECT 1 FROM probe_jobs j WHERE j.variant_id=p.id AND j.status IN ('queued','leased'))""", days)
        return int(value.split()[-1])

    async def cap_proxies(self, max_rows: int = 3000) -> int:
        async with self._pool.acquire() as conn:
            value = await conn.execute("""DELETE FROM proxies p WHERE NOT p.blocked
                AND NOT p.admin_recommended AND p.id NOT IN (
                    SELECT id FROM proxies WHERE NOT blocked ORDER BY last_seen_at DESC LIMIT $1)
                AND NOT EXISTS(SELECT 1 FROM probe_observations o WHERE o.variant_id=p.id
                    AND o.measured_at>NOW()-INTERVAL '1 day')
                AND NOT EXISTS(SELECT 1 FROM probe_jobs j WHERE j.variant_id=p.id AND j.status IN ('queued','leased'))""", max_rows)
        return int(value.split()[-1])

    async def get_db_size_mb(self) -> float:
        """Возвращает размер текущей БД в МБ."""
        async with self._pool.acquire() as conn:
            size = await conn.fetchval(
                "SELECT pg_database_size(current_database())"
            )
        return round((size or 0) / (1024 * 1024), 1)

    async def stats(self) -> dict[str, Any]:
        """Catalog counts use the same expiring protocol evidence as selection."""
        from app.proxy.selection_service import rank_candidates
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("""SELECT COUNT(*) AS total,
                COUNT(*) FILTER (WHERE blocked) AS blocked,
                COUNT(*) FILTER (WHERE length(id)=32 AND NOT blocked AND last_seen_at>NOW()-INTERVAL '1 day') AS catalog_total,
                COUNT(*) FILTER (WHERE admin_recommended AND NOT blocked) AS admin_recommended,
                COUNT(*) FILTER (WHERE created_at>NOW()-INTERVAL '24 hours') AS added_24h FROM proxies""")
        result = dict(row)
        catalog = await self.get_selection_snapshot(limit=1000)
        candidates = rank_candidates(catalog)
        verified = [p for p in candidates if p['evidence']['status'] == 'verified']
        ru = [p for p in verified if str(p['evidence'].get('probe_country', '')).lower() == 'ru']
        duration = [p['evidence']['duration_ms'] for p in verified if isinstance(p['evidence'].get('duration_ms'), (int, float))]
        result.update(catalog_sampled=len(catalog), alive=len(verified), dead=len(catalog)-len(verified),
            ru=len(ru), foreign=len(verified)-len(ru),
            unverified=sum(p['evidence']['status'] == 'unverified' for p in candidates),
            stale=sum(p['evidence']['status'] == 'stale' for p in candidates),
            failed_here=sum(p['evidence']['status'] == 'failed_here' for p in candidates),
            pinned_verified=sum(bool(p.get('admin_recommended')) for p in verified),
            avg_test_duration_ms=round(sum(duration)/len(duration)) if duration else None,
            faketls=sum(p.get('generation') == 'faketls' for p in verified),
            randpad=sum(p.get('generation') == 'randpad' for p in verified),
            plain=sum(p.get('generation') == 'plain' for p in verified),
            fresh_10m=len(verified))
        # Legacy fields remain for API consumers; no synthetic quality is assigned.
        result.update(eu=0, ru_faketls=sum(p.get('generation') == 'faketls' for p in ru),
                      avg_ping_ru=0, avg_ping_eu=0, avg_tspu=0)
        return result

    async def list_proxies(
        self,
        *,
        page: int = 1,
        limit: int = 50,
        category: str | None = None,
        generation: str | None = None,
        alive_only: bool | None = None,
    ) -> tuple[list[dict], int]:
        """Inspect at most 1000 recent matches; alive means fresh measured eligibility."""
        from app.db.probes import ProbeRepository
        from app.proxy.decoder import decode_secret
        from app.proxy.selection_service import evidence_for
        conditions, params = [], []
        if category:
            params.append(category)
            conditions.append(f"category=${len(params)}")
        if generation:
            params.append(generation)
            conditions.append(f"generation=${len(params)}")
        if alive_only is True:
            conditions.append("length(id)=32 AND NOT blocked AND last_seen_at>NOW()-INTERVAL '1 day'")
        where = ('WHERE ' + ' AND '.join(conditions)) if conditions else ''
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(f"""SELECT *,
                (length(id)=32 AND NOT blocked AND last_seen_at>NOW()-INTERVAL '1 day') AS in_catalog
                FROM proxies {where} ORDER BY last_seen_at DESC,admin_recommended DESC,id LIMIT 1000""", *params)
        observations = await ProbeRepository(self._pool).latest_observations([r['id'] for r in rows])
        inspected = []
        for row in rows:
            item = dict(row)
            metadata = item.pop('selection_metadata', {})
            if isinstance(metadata, str):
                metadata = json.loads(metadata)
            item = {**metadata, **item}
            item['observations'] = observations.get(item['id'], [])
            evidence = evidence_for(item)
            if item.get('blocked'):
                evidence = {**evidence, 'status': 'blocked', 'coverage_label': 'Excluded by administrator'}
            elif not item['in_catalog'] or not decode_secret(item.get('secret', '')).is_valid:
                evidence = {**evidence, 'status': 'archived', 'coverage_label': 'Outside the active catalog'}
            item['evidence'] = evidence
            item['is_alive'] = evidence['status'] == 'verified'
            item.pop('observations', None)
            if alive_only is None or item['is_alive'] == alive_only:
                inspected.append(item)
        limit = max(1, min(int(limit), 200))
        offset = (max(1, int(page))-1)*limit
        return inspected[offset:offset+limit], len(inspected)

    async def delete_by_ids(self, ids: list[str]) -> int:
        """Удаляет прокси по списку ID. Возвращает число удалённых записей."""
        if not ids:
            return 0
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                "UPDATE proxies SET blocked=TRUE,is_alive=FALSE WHERE id = ANY($1::text[]) AND NOT blocked", ids
            )
        return int(result.split()[-1])

    async def delete_by_filter(
        self,
        *,
        sni_contains: str | None = None,
        host_contains: str | None = None,
        category: str | None = None,
        generation: str | None = None,
        alive_only: bool | None = None,
    ) -> int:
        """
        Удаляет прокси по фильтру. Возвращает число удалённых записей.
        Хотя бы один фильтр должен быть задан.
        """
        conditions: list[str] = []
        params: list[Any] = []

        if sni_contains:
            params.append(_contains_pattern(sni_contains))
            conditions.append(f"LOWER(sni_domain) LIKE ${len(params)}")
        if host_contains:
            params.append(_contains_pattern(host_contains))
            conditions.append(f"LOWER(host) LIKE ${len(params)}")
        if category:
            params.append(category)
            conditions.append(f"category = ${len(params)}")
        if generation:
            params.append(generation)
            conditions.append(f"generation = ${len(params)}")
        if alive_only is True:
            conditions.append("is_alive = TRUE")
        elif alive_only is False:
            conditions.append("is_alive = FALSE")

        if not conditions:
            raise ValueError("delete_by_filter: нужен хотя бы один фильтр")

        where = " AND ".join(conditions)
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                f"UPDATE proxies SET blocked=TRUE,is_alive=FALSE WHERE NOT blocked AND {where}", *params
            )
        deleted = int(result.split()[-1])
        logger.info("db: delete_by_filter удалено %d прокси (filter=%r)", deleted, conditions)
        return deleted

    async def count_by_filter(
        self,
        *,
        sni_contains: str | None = None,
        host_contains: str | None = None,
        category: str | None = None,
        generation: str | None = None,
        alive_only: bool | None = None,
    ) -> int:
        """Предварительный подсчёт числа прокси под фильтр (без удаления)."""
        conditions: list[str] = []
        params: list[Any] = []

        if sni_contains:
            params.append(_contains_pattern(sni_contains))
            conditions.append(f"LOWER(sni_domain) LIKE ${len(params)}")
        if host_contains:
            params.append(_contains_pattern(host_contains))
            conditions.append(f"LOWER(host) LIKE ${len(params)}")
        if category:
            params.append(category)
            conditions.append(f"category = ${len(params)}")
        if generation:
            params.append(generation)
            conditions.append(f"generation = ${len(params)}")
        if alive_only is True:
            conditions.append("is_alive = TRUE")
        elif alive_only is False:
            conditions.append("is_alive = FALSE")

        if not conditions:
            return 0

        where = " AND ".join(conditions)
        async with self._pool.acquire() as conn:
            return int(await conn.fetchval(f"SELECT COUNT(*) FROM proxies WHERE NOT blocked AND {where}", *params) or 0)


# ──────────────────────────────────────────────────────────────────────────────
# UserRepository
# ──────────────────────────────────────────────────────────────────────────────

class UserRepository:
    def __init__(self, pool: Any) -> None:
        self._pool = pool

    async def migrate(self) -> None:
        """
        Создаёт/мигрирует все таблицы.
        Безопасно для повторного запуска (IF NOT EXISTS / ADD COLUMN IF NOT EXISTS).
        """
        async with self._pool.acquire() as conn:
            # Базовые таблицы
            await conn.execute(CREATE_USERS_SQL)
            # Платёжная система удалена: стираем оставшиеся служебные таблицы
            # старых развёртываний вместе с хранившейся в них историей.
            await conn.execute("DROP TABLE IF EXISTS da_payments")
            await conn.execute("DROP TABLE IF EXISTS payments")
            await conn.execute("DROP INDEX IF EXISTS idx_users_subscribed")
            await conn.execute("ALTER TABLE users DROP COLUMN IF EXISTS is_subscribed")
            await conn.execute("ALTER TABLE users DROP COLUMN IF EXISTS sub_expires")
            await conn.execute(CREATE_AUTH_TOKENS_SQL)
            await conn.execute(CREATE_PENDING_REG_SQL)

            # ── Миграция существующей таблицы users ──────────────────────────
            # Добавляем новые колонки (для существующих БД)
            await conn.execute(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
                "account_login TEXT NOT NULL DEFAULT ''"
            )
            await conn.execute(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
                "password_hash TEXT NOT NULL DEFAULT ''"
            )
            await conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS session_version INTEGER NOT NULL DEFAULT 0")
            # Заполняем account_login для существующих пользователей без логина
            await conn.execute(
                "UPDATE users SET account_login = 'user' || telegram_id::text "
                "WHERE account_login = '' OR account_login IS NULL"
            )

            # Старые версии сохраняли пароль открытым текстом. Удаляем столбец
            # вместе с накопленными значениями; для входа нужен только хеш.
            await conn.execute(
                "ALTER TABLE users DROP COLUMN IF EXISTS plain_password"
            )
            # Уникальный индекс на account_login (CREATE UNIQUE INDEX IF NOT EXISTS)
            await conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_account_login "
                "ON users(account_login)"
            )

            duplicates = await conn.fetchval("SELECT COUNT(*) FROM (SELECT LOWER(account_login) FROM users GROUP BY LOWER(account_login) HAVING COUNT(*)>1) collisions")
            if not duplicates:
                await conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_account_login_lower ON users(LOWER(account_login))")
            else:
                logger.error("Legacy case-colliding logins detected; ambiguous login is disabled until resolved")
        logger.info("db: миграция users/pending_reg — завершена")

    # ── Пользователи ──────────────────────────────────────────────────────────

    async def register_existing_telegram_user(self, account_login: str, plain_password: str) -> dict:
        raise ValueError("Existing Telegram accounts require confirmation inside Telegram")

    async def create_web_user(self, account_login: str, plain_password: str) -> dict:
        login = account_login.strip().lower()
        if not re.fullmatch(r"[a-z0-9_]{3,32}", login) or not 10 <= len(plain_password) <= 1024:
            raise ValueError("Invalid credentials format")
        phash = await asyncio.to_thread(hash_password, plain_password)
        fake_id = -(secrets.randbelow(8_000_000_000_000_000)+1_000_000_000_000_000)
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", login)
                if await conn.fetchval("SELECT 1 FROM users WHERE LOWER(account_login)=$1", login):
                    raise ValueError("Login is already taken")
                row = await conn.fetchrow("""INSERT INTO users(telegram_id,account_login,password_hash)
                    VALUES($1,$2,$3) RETURNING *""", fake_id, login, phash)
        return dict(row)

    async def ensure_user(self, telegram_id: int, username: str = "") -> None:
        await self.upsert_user(telegram_id, username=username)

    async def upsert_user(self, telegram_id: int, *, username: str = "", first_name: str = "",
                          last_name: str = "", photo_url: str = "") -> None:
        if telegram_id <= 0:
            raise ValueError("A real Telegram identity must be positive")
        preferred = _gen_login(telegram_id, username)
        for attempt in range(3):
            login = preferred if attempt == 0 else f"tg_{telegram_id}_{secrets.token_hex(3)}"
            async with self._pool.acquire() as conn:
                try:
                    await conn.execute("""INSERT INTO users(telegram_id,account_login,username,first_name,last_name,photo_url)
                        VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(telegram_id) DO UPDATE SET
                        username=EXCLUDED.username,first_name=EXCLUDED.first_name,last_name=EXCLUDED.last_name,
                        photo_url=EXCLUDED.photo_url,updated_at=NOW()""",
                        telegram_id, login, username[:64], first_name[:128], last_name[:128], photo_url[:2048])
                    return
                except Exception as exc:
                    if getattr(exc, "sqlstate", "") != "23505":
                        raise
        raise ValueError("Could not allocate an account login")

    async def get_user(self, telegram_id: int) -> Optional[dict[str, Any]]:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM users WHERE telegram_id = $1", telegram_id
            )
        return dict(row) if row else None

    async def get_user_by_login(self, account_login: str) -> Optional[dict[str, Any]]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM users WHERE LOWER(account_login)=LOWER($1) LIMIT 2", account_login)
        # Legacy case-colliding accounts must not resolve to an arbitrary identity.
        return dict(rows[0]) if len(rows) == 1 else None

    async def login_user(
        self, account_login: str, plain_password: str
    ) -> Optional[dict[str, Any]]:
        """
        Проверяет логин + пароль.
        Возвращает запись пользователя при успехе, иначе None.
        """
        user = await self.get_user_by_login(account_login)
        if not user:
            return None
        if not user.get("password_hash"):
            return None
        if not await asyncio.to_thread(verify_password, plain_password, user["password_hash"]):
            return None
        if password_needs_rehash(user["password_hash"]):
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "UPDATE users SET password_hash=$2, updated_at=NOW() WHERE telegram_id=$1 AND password_hash=$3",
                    user["telegram_id"], await asyncio.to_thread(hash_password, plain_password), user["password_hash"],
                )
        return user

    async def set_credentials(
        self, telegram_id: int, account_login: str, plain_password: str
    ) -> None:
        """Устанавливает / обновляет логин и пароль пользователя."""
        phash = await asyncio.to_thread(hash_password, plain_password)
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE users
                SET account_login  = $2,
                    password_hash  = $3,
                    session_version = session_version + 1,
                    updated_at     = NOW()
                WHERE telegram_id = $1
                """,
                telegram_id, account_login, phash,
            )

    async def ensure_credentials(self, telegram_id: int) -> tuple[str, str]:
        """
        Гарантирует, что у пользователя есть пароль.
        Если нет — генерирует автоматически.
        Возвращает (account_login, plain_password).
        Если пароль уже был установлен — возвращает (account_login, "") чтобы не пересылать его.
        """
        user = await self.get_user(telegram_id)
        if not user:
            await self.ensure_user(telegram_id)
            user = await self.get_user(telegram_id)

        if user and user.get("password_hash"):
            return user["account_login"], ""

        # Генерируем пароль, логин берём уже установленный (username или user{id})
        login    = user["account_login"] if user else _gen_login(telegram_id)
        password = _gen_password(20)
        phash = await asyncio.to_thread(hash_password, password)
        async with self._pool.acquire() as conn:
            changed = await conn.fetchrow("""UPDATE users SET password_hash=$2,
                session_version=session_version+1,updated_at=NOW()
                WHERE telegram_id=$1 AND password_hash='' RETURNING account_login""", telegram_id, phash)
        if changed:
            return changed["account_login"], password
        # Another /start or a password reset won the race; never overwrite it.
        current = await self.get_user(telegram_id)
        return (current["account_login"] if current else login), ""

    async def link_tg_to_existing(self, telegram_id: int, account_login: str, plain_password: str,
                                  username: str = "", first_name: str = "", last_name: str = "") -> bool:
        if telegram_id <= 0:
            return False
        web_user = await self.login_user(account_login, plain_password)
        if not web_user:
            return False
        old_id = int(web_user["telegram_id"])
        if old_id == telegram_id:
            return True
        if old_id >= 0:
            return False  # An existing Telegram identity can never be transferred.
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                rows = await conn.fetch("SELECT * FROM users WHERE telegram_id=ANY($1::bigint[]) ORDER BY telegram_id FOR UPDATE", [old_id,telegram_id])
                locked = {row["telegram_id"]: row for row in rows}
                old, target = locked.get(old_id), locked.get(telegram_id)
                if not old or old["password_hash"] != web_user["password_hash"] or target and target["password_hash"]:
                    return False
                if target:
                    await conn.execute("DELETE FROM users WHERE telegram_id=$1", telegram_id)
                await conn.execute("UPDATE users SET account_login=$2 WHERE telegram_id=$1", old_id, "linking_"+secrets.token_hex(16))
                await conn.execute("""INSERT INTO users(telegram_id,account_login,password_hash,username,first_name,last_name,photo_url,created_at,session_version)
                    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)""", telegram_id, old["account_login"],old["password_hash"],
                    username[:64],first_name[:128] or old["first_name"],last_name[:128] or old["last_name"],old["photo_url"],
                    old["created_at"], int(old["session_version"])+1)
                await conn.execute("DELETE FROM auth_tokens WHERE telegram_id=ANY($1::bigint[])", [old_id,telegram_id])
                await conn.execute("DELETE FROM pending_registrations WHERE telegram_id=ANY($1::bigint[])", [old_id,telegram_id])
                await conn.execute("DELETE FROM proxy_feedback WHERE telegram_id=$1 AND proxy_id IN (SELECT proxy_id FROM proxy_feedback WHERE telegram_id=$2)", telegram_id,old_id)
                await conn.execute("UPDATE proxy_feedback SET telegram_id=$1 WHERE telegram_id=$2", telegram_id,old_id)
                await conn.execute("DELETE FROM users WHERE telegram_id=$1", old_id)
        return True

    async def register_web_user(
        self, account_login: str, plain_password: str
    ) -> int:
        """Регистрация через сайт отключена — используйте Telegram-бота."""
        raise NotImplementedError("Регистрация только через Telegram-бота.")

    # ── Pending registrations (веб-регистрация до привязки Telegram) ──────────

    async def create_pending_reg(
        self, account_login: str, plain_password: str, ttl_minutes: int = 15
    ) -> str:
        """
        Создаёт временную запись регистрации.
        Возвращает одноразовый токен.
        """
        token      = secrets.token_urlsafe(24)
        phash      = await asyncio.to_thread(hash_password, plain_password)
        expires_at = utcnow() + timedelta(minutes=ttl_minutes)
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO pending_registrations
                    (token, account_login, password_hash, expires_at)
                VALUES ($1, $2, $3, $4)
                """,
                token, account_login, phash, expires_at,
            )
        return token

    async def get_pending_reg(self, token: str) -> Optional[dict[str, Any]]:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM pending_registrations WHERE token = $1 "
                "AND expires_at > NOW()",
                token,
            )
        return dict(row) if row else None

    async def consume_pending_reg(self, token: str, telegram_id: int, first_name: str = "", last_name: str = ""):
        # Legacy deep links must not replace credentials of an existing identity.
        return None

    async def cleanup_expired(self) -> dict:
        """
        Очистка временных токенов и незавершённых регистраций.
        Возвращает словарь с числом удалённых строк по каждой таблице.
        """
        async with self._pool.acquire() as conn:
            r1 = await conn.execute(
                "DELETE FROM auth_tokens WHERE expires_at < NOW()"
            )
            r2 = await conn.execute(
                "DELETE FROM pending_registrations WHERE expires_at < NOW()"
            )
        counts = {
            "auth_tokens":  int(r1.split()[-1]),
            "pending_regs": int(r2.split()[-1]),
        }
        if any(counts.values()):
            logger.info("db: cleanup_expired: %s", counts)
        return counts

    async def table_sizes(self) -> list[dict[str, Any]]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT
                    relname AS table_name,
                    pg_total_relation_size(relid) AS bytes,
                    pg_size_pretty(pg_total_relation_size(relid)) AS size
                FROM pg_catalog.pg_statio_user_tables
                ORDER BY pg_total_relation_size(relid) DESC
                """
            )
        return [dict(row) for row in rows]

    async def cleanup_pending_regs(self) -> None:
        """Удаляет просроченные pending-записи."""
        async with self._pool.acquire() as conn:
            await conn.execute(
                "DELETE FROM pending_registrations WHERE expires_at < NOW()"
            )

    # ── Auth tokens (legacy, не используются для логина) ──────────────────────

    async def create_auth_token(self, token: str, expires_at: datetime) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO auth_tokens (token, expires_at) VALUES ($1, $2) "
                "ON CONFLICT DO NOTHING",
                token, expires_at,
            )

    async def get_auth_token(self, token: str) -> Optional[dict[str, Any]]:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM auth_tokens WHERE token = $1 AND expires_at > NOW()",
                token,
            )
        return dict(row) if row else None

    async def consume_auth_token(
        self,
        token: str,
        telegram_id: int,
        username: str = "",
        first_name: str = "",
        last_name: str = "",
    ) -> bool:
        row = await self.get_auth_token(token)
        if not row:
            return False
        async with self._pool.acquire() as conn:
            await self.upsert_user(
                telegram_id,
                username=username, first_name=first_name, last_name=last_name,
            )
            await conn.execute(
                "UPDATE auth_tokens SET telegram_id = $2 WHERE token = $1",
                token, telegram_id,
            )
        return True
