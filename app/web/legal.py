"""Public legal documents, rendered without authentication or application JS."""
from __future__ import annotations

from dataclasses import dataclass
import html
import os
from pathlib import Path
import re

from aiohttp import web

PROJECT_DIR = Path(__file__).resolve().parents[2]
LEGAL_VERSION = "2026-11-03"
DOCUMENTS = {
    "privacy": ("Политика обработки персональных данных", "privacy.html"),
    "terms": ("Условия использования", "terms.html"),
    "cookies": ("Cookie и локальное хранилище", "cookies.html"),
    "selection": ("Правила подбора прокси", "recommendations.html"),
}


@dataclass(frozen=True)
class LegalProfile:
    operator_name: str = ""
    postal_address: str = ""
    privacy_email: str = "autotgproxy@gmail.com"
    inn: str = ""
    registration_number: str = ""
    database_country: str = ""
    processors: str = ""
    log_retention: str = ""
    backup_retention: str = ""

    @classmethod
    def from_env(cls):
        names = {
            "operator_name": "LEGAL_OPERATOR_NAME", "postal_address": "LEGAL_POSTAL_ADDRESS",
            "privacy_email": "LEGAL_PRIVACY_EMAIL", "inn": "LEGAL_INN",
            "registration_number": "LEGAL_REGISTRATION_NUMBER", "database_country": "LEGAL_DATABASE_COUNTRY",
            "processors": "LEGAL_PROCESSORS", "log_retention": "LEGAL_LOG_RETENTION",
            "backup_retention": "LEGAL_BACKUP_RETENTION",
        }
        values = {key: os.getenv(env, "").strip() for key, env in names.items()}
        values["privacy_email"] = values["privacy_email"] or cls.privacy_email
        if not re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}", values["privacy_email"]):
            raise ValueError("LEGAL_PRIVACY_EMAIL must be a plain email address")
        if any(len(value) > 4000 for value in values.values()):
            raise ValueError("Legal profile fields must not exceed 4000 characters")
        return cls(**values)

    @property
    def missing_fields(self):
        fields = {"operator_name": "владелец сервиса", "postal_address": "почтовый адрес",
                  "privacy_email": "email для обращений", "database_country": "страна базы аккаунтов",
                  "processors": "лица, которым поручена обработка", "log_retention": "срок хранения журналов",
                  "backup_retention": "срок хранения резервных копий"}
        return [label for field, label in fields.items() if not getattr(self, field)]


def _value(text: str, missing: str = "Не заполнено владельцем сервиса") -> str:
    return html.escape(text or missing, quote=True)


def _operator_block(profile: LegalProfile) -> str:
    rows = [("Владелец сервиса / оператор персональных данных", profile.operator_name),
            ("Почтовый адрес для обращений", profile.postal_address)]
    if profile.inn:
        rows.append(("ИНН", profile.inn))
    if profile.registration_number:
        rows.append(("ОГРН / ОГРНИП", profile.registration_number))
    content = "".join(f"<dt>{label}</dt><dd>{_value(value)}</dd>" for label, value in rows)
    email = _value(profile.privacy_email)
    return f'<dl class="legal-operator">{content}<dt>Обращения по персональным данным</dt><dd><a href="mailto:{email}">{email}</a></dd></dl>'


def _location_block(profile: LegalProfile) -> str:
    return ('<p>Приложение сервиса размещено на Render в Орегоне, США. Запросы к сайту, '
            'включая данные входа и технические сведения о соединении, обрабатываются этим сервером. '
            'Эта схема предусматривает обработку данных за пределами России.</p>'
            '<p>Страна размещения базы аккаунтов: <strong>' + _value(profile.database_country) + '</strong>.</p>'
            '<p>Размещение базы в России само по себе не исключает иностранную обработку: '
            'сервер приложения остаётся в США. Публикация этой политики не заменяет выполнение '
            'требований к локализации и трансграничной передаче.</p>')


def _navigation(current: str = "") -> str:
    return "".join(f'<a href="/legal/{key}"' + (' aria-current="page"' if key == current else '') + f'>{title}</a>'
                   for key, (title, _) in DOCUMENTS.items())


def render_document(key: str, profile: LegalProfile, static_version: str) -> str:
    title, filename = DOCUMENTS[key]
    body = (PROJECT_DIR / "templates/legal" / filename).read_text(encoding="utf-8")
    page = (PROJECT_DIR / "templates/legal_page.html").read_text(encoding="utf-8")
    missing = profile.missing_fields
    notice = ('<aside class="legal-notice" role="note"><strong>Документ подготовлен, сведения требуют заполнения.</strong>'
              '<p>Владелец ещё не указал: ' + html.escape(", ".join(missing)) + '. '
              'До заполнения и проверки фактической обработки данных документ остаётся проектом.</p></aside>') if missing else ""
    values = {
        "__TITLE__": title, "__DOCUMENT_BODY__": body, "__DOCUMENT_NOTICE__": notice,
        "__LEGAL_NAVIGATION__": _navigation(key), "__OPERATOR_BLOCK__": _operator_block(profile),
        "__PRIVACY_EMAIL__": _value(profile.privacy_email), "__DATA_LOCATION_BLOCK__": _location_block(profile),
        "__PROCESSORS__": _value(profile.processors), "__LOG_RETENTION__": _value(profile.log_retention),
        "__BACKUP_RETENTION__": _value(profile.backup_retention),
        "__LEGAL_VERSION__": LEGAL_VERSION, "__STATIC_VER__": html.escape(static_version, quote=True),
    }
    page = page.replace("__DOCUMENT_BODY__", body)
    # One substitution pass: even operator-provided text resembling a template
    # token remains inert and cannot inject another rendered block.
    return re.sub(r"__[A-Z_]+__", lambda match: values.get(match.group(), match.group()), page)


def setup_legal_routes(app: web.Application, *, static_version: str):
    if "legal_profile" not in app:
        app["legal_profile"] = LegalProfile.from_env()

    async def document(request):
        key = request.match_info["document"]
        if key not in DOCUMENTS:
            raise web.HTTPNotFound()
        return web.Response(text=render_document(key, request.app["legal_profile"], static_version),
                            content_type="text/html", headers={"Cache-Control": "no-store"})

    app.router.add_get("/legal/{document}", document)
    app.router.add_get("/legal/{document}/", document)
