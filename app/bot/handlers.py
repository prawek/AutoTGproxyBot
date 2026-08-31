"""Telegram-native Auto Proxy interface. Private chats only; no live network scans in handlers."""
from __future__ import annotations

import html
import logging
import re
import time
from collections import OrderedDict
from datetime import datetime, timezone
from urllib.parse import urlencode, urlsplit

from aiogram import F, Router
from aiogram.exceptions import TelegramBadRequest, TelegramForbiddenError
from aiogram.filters import Command, CommandObject
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, LinkPreviewOptions, Message

from app.proxy import pipeline as worker
from app.proxy.catalog import available_proxies, feedback, secret_type
from app.proxy.selection_service import select_proxies

logger = logging.getLogger(__name__)
router = Router()
router.message.filter(F.chat.type == "private", F.from_user)


async def _own_private_callback(callback: CallbackQuery) -> bool:
    return (
        isinstance(callback.message, Message)
        and callback.message.chat.type == "private"
        and callback.message.chat.id == callback.from_user.id
    )


router.callback_query.filter(_own_private_callback)
_user_repo = None
_proxy_repo = None
_site_url = ""
_STATE_LIMIT = 2000
_STATE_TTL = 3600
_user_state: OrderedDict[int, dict] = OrderedDict()
_action_times: OrderedDict[tuple[int, str], float] = OrderedDict()
_VALID_ID = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_DEFAULT_FILTER = "aar"


def setup_handlers(user_repo, proxy_repo=None, site_url: str = "") -> None:
    global _user_repo, _proxy_repo, _site_url
    _user_repo, _proxy_repo = user_repo, proxy_repo
    parsed = urlsplit(site_url)
    _site_url = site_url.rstrip("/") if parsed.scheme in {"http", "https"} and parsed.netloc and not parsed.username else ""


def _escape(value: object) -> str:
    return html.escape(str(value or ""), quote=True)


def _state(uid: int) -> dict:
    now = time.monotonic()
    for key, value in list(_user_state.items()):
        if value["until"] < now:
            _user_state.pop(key, None)
    if uid not in _user_state:
        while len(_user_state) >= _STATE_LIMIT:
            _user_state.popitem(last=False)
        _user_state[uid] = {"network": "unknown", "skip": set(), "until": now + _STATE_TTL}
    _user_state.move_to_end(uid)
    _user_state[uid]["until"] = now + _STATE_TTL
    return _user_state[uid]


def _allowed(uid: int, action: str, seconds: float) -> bool:
    now = time.monotonic()
    key = (uid, action)
    previous = _action_times.get(key, 0)
    if previous + seconds > now:
        return False
    _action_times[key] = now
    _action_times.move_to_end(key)
    while len(_action_times) > 5000:
        _action_times.popitem(last=False)
    return True


def _site_button(label: str = "Открыть кабинет") -> InlineKeyboardButton | None:
    return InlineKeyboardButton(text=label, url=_site_url + "/connect_proxy") if _site_url else None


def _home_keyboard() -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton(text="↗ Подобрать прокси", callback_data="fb:" + _DEFAULT_FILTER)],
        [InlineKeyboardButton(text="☰ Каталог", callback_data="prx:" + _DEFAULT_FILTER),
         InlineKeyboardButton(text="◎ Выбрать сеть", callback_data="pc:" + _DEFAULT_FILTER)],
    ]
    site = _site_button()
    if site:
        rows.append([site])
    return InlineKeyboardMarkup(inline_keyboard=rows)


async def _answer(message: Message, text: str, *, keyboard=None, credentials=False) -> None:
    await message.answer(text, parse_mode="HTML", reply_markup=keyboard,
                         link_preview_options=LinkPreviewOptions(is_disabled=True), protect_content=credentials)


async def _send_credentials(message: Message, login: str, password: str) -> None:
    await _answer(message,
        "<b>✈ Auto Proxy · доступ к сайту</b>\n\n"
        f"Логин: <code>{_escape(login)}</code>\nПароль: <code>{_escape(password)}</code>\n\n"
        "Сохраните пароль: он показывается один раз. Он нужен только для входа на сайт.",
        keyboard=_home_keyboard(), credentials=True)


async def _ensure_user(message: Message) -> tuple[str, str] | None:
    if _user_repo is None:
        return None
    user = message.from_user
    await _user_repo.upsert_user(user.id, username=user.username or "", first_name=user.first_name or "", last_name=user.last_name or "")
    return await _user_repo.ensure_credentials(user.id)


@router.message(Command("start"))
async def cmd_start(message: Message, command: CommandObject) -> None:
    credentials = await _ensure_user(message)
    if credentials and credentials[1]:
        await _send_credentials(message, *credentials)
        return
    await _answer(message,
        "<b>✈ Auto Proxy</b>\nПрокси для Telegram\n\n"
        "Подберу основной вариант и доступные резервы по свежим измерениям. "
        "Рядом со ссылкой покажу, где и когда проверено соединение.\n\n"
        "Проверка из Орегона не подтверждает доступность в вашей сети. "
        "Российское подтверждение появляется только после измерения в РФ.\n\n"
        "Доступ бесплатный. /account — кабинет и пароль.", keyboard=_home_keyboard())


@router.message(Command("account", "status"))
async def cmd_account(message: Message) -> None:
    if _user_repo is None:
        await _answer(message, "<b>Кабинет временно недоступен</b>\nПопробуйте позже.")
        return
    user = await _user_repo.get_user(message.from_user.id)
    if not user:
        await _answer(message, "Аккаунт пока не создан. Нажмите /start.")
        return
    rows = [[InlineKeyboardButton(text="Сменить пароль сайта", callback_data="reset_pw")]]
    site = _site_button()
    if site:
        rows.insert(0, [site])
    rows.append([InlineKeyboardButton(text="↗ Подобрать прокси", callback_data="fb:" + _DEFAULT_FILTER)])
    await _answer(message,
        "<b>✈ Auto Proxy · кабинет</b>\n\n"
        f"Логин: <code>{_escape(user.get('account_login') or 'не задан')}</code>\n"
        f"Telegram: <code>{_escape('@' + user['username'] if user.get('username') else 'username не указан')}</code>\n"
        "Доступ: бесплатно\n\nПароль хранится в виде хеша. Новый пароль заменит прежний.",
        keyboard=InlineKeyboardMarkup(inline_keyboard=rows))


@router.callback_query(F.data == "reset_pw")
async def cb_reset_password(callback: CallbackQuery) -> None:
    await callback.answer()
    await _answer(callback.message,
        "<b>Сменить пароль сайта?</b>\nПрежний пароль перестанет работать. Новый пароль будет показан только в этом личном диалоге.",
        keyboard=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="Да, сменить пароль", callback_data="reset_pw_confirm")],
            [InlineKeyboardButton(text="Отмена", callback_data="noop")],
        ]))


@router.callback_query(F.data == "reset_pw_confirm")
async def cb_reset_password_confirm(callback: CallbackQuery) -> None:
    uid = callback.from_user.id
    if not _allowed(uid, "reset", 60):
        await callback.answer("Повторная смена доступна через минуту.", show_alert=True)
        return
    if _user_repo is None:
        await callback.answer("Кабинет временно недоступен.", show_alert=True)
        return
    user = await _user_repo.get_user(uid)
    if not user:
        await callback.answer("Сначала создайте аккаунт через /start.", show_alert=True)
        return
    from app.db.schema import _gen_password
    login = user.get("account_login") or f"user{uid}"
    password = _gen_password(20)
    await _user_repo.set_credentials(uid, login, password)
    await callback.answer("Пароль изменён")
    await _send_credentials(callback.message, login, password)


async def _link_account(message: Message, command: CommandObject) -> None:
    args = (command.args or "").strip().split(maxsplit=1)
    if len(args) != 2:
        await _answer(message,
            "<b>Привязка аккаунта сайта</b>\n\nОтправьте в этом личном диалоге команду "
            "<code>/link логин пароль</code>. Сообщение с паролем будет удалено, если Telegram позволит. "
            "Аккаунт Telegram определяется по вашему ID, а не по совпадению username.")
        return
    # Password-bearing commands never stay in a group; router accepts private chats only.
    try:
        await message.delete()
    except (TelegramBadRequest, TelegramForbiddenError):
        pass
    if not _allowed(message.from_user.id, "link", 5):
        await _answer(message, "Подождите несколько секунд перед новой попыткой.")
        return
    if _user_repo is None:
        await _answer(message, "Кабинет временно недоступен. Попробуйте позже.")
        return
    login, password = args
    if len(login) > 32 or len(password.encode("utf-8")) > 1024:
        await _answer(message, "Неверный логин или пароль.")
        return
    user = message.from_user
    ok = await _user_repo.link_tg_to_existing(user.id, login, password,
        username=user.username or "", first_name=user.first_name or "", last_name=user.last_name or "")
    if not ok:
        await _answer(message, "Не удалось привязать аккаунт. Проверьте данные или откройте /account.")
        return
    await _answer(message, "<b>Аккаунт привязан</b>\nЛогин: <code>" + _escape(login) + "</code>", keyboard=_home_keyboard())


@router.message(Command("link"))
async def cmd_link(message: Message, command: CommandObject) -> None:
    await _link_account(message, command)


@router.message(Command("login"))
async def cmd_login(message: Message, command: CommandObject) -> None:
    if command.args:
        await _link_account(message, command)
    else:
        await cmd_account(message)


@router.message(Command("register"))
async def cmd_register(message: Message) -> None:
    result = await _ensure_user(message)
    if result and result[1]:
        await _send_credentials(message, *result)
    elif result:
        await cmd_account(message)
    else:
        await _answer(message, "Кабинет временно недоступен. Подбор прокси доступен через /proxy.")


@router.message(Command("logout"))
async def cmd_logout(message: Message) -> None:
    await _answer(message, "<b>Выход из кабинета</b>\nВ боте доступ определяется вашим Telegram ID. "
                  "Для выхода с сайта используйте кнопку «Выйти» в веб-кабинете.", keyboard=_home_keyboard())


@router.message(Command("subscribe"))
async def cmd_subscribe(message: Message, command: CommandObject) -> None:
    await _answer(message, "<b>Доступ открыт</b>\nПодбор прокси бесплатный. Карта, платёж и подтверждение тарифа не нужны.", keyboard=_home_keyboard())


def _decode_filter(code: str) -> tuple[str, str, str]:
    code = code if isinstance(code, str) and len(code) == 3 else _DEFAULT_FILTER
    return ("all", {"a": "all", "f": "FakeTLS", "d": "RandPad", "p": "Plain"}.get(code[1], "all"),
            {"r": "recommended", "p": "ping", "u": "recommended", "v": "recommended"}.get(code[2], "recommended"))


def _encode_filter(region: str, ptype: str, sort: str) -> str:
    return "a" + {"all": "a", "FakeTLS": "f", "RandPad": "d", "Plain": "p"}.get(ptype, "a") + ("p" if sort == "ping" else "r")


def _selection(uid: int, flt: str, *, manual=False, limit=3):
    region, ptype, sort = _decode_filter(flt)
    candidates = available_proxies(worker.CACHED_BEST_PROXIES, worker.banned_proxies, user_id=uid)
    return select_proxies(candidates, network=_state(uid)["network"], region=region, proxy_type=ptype,
                          sort_by=sort, skip_ids=_state(uid)["skip"], limit=limit, allow_unverified=manual)


def _proxy_url(proxy: dict) -> str:
    host = str(proxy.get("server") or proxy.get("host") or "")
    secret = str(proxy.get("secret") or "")
    try:
        port = int(proxy.get("port", 0))
    except (TypeError, ValueError):
        return ""
    if not host or len(host) > 253 or not 1 <= port <= 65535 or not secret or len(secret) > 1024:
        return ""
    return "tg://proxy?" + urlencode({"server": host, "port": port, "secret": secret})


def _evidence_text(proxy: dict) -> str:
    evidence = proxy.get("evidence") or {}
    status = evidence.get("status", "unverified")
    level = evidence.get("level", "none")
    labels = {"verified": "Протокол подтверждён", "stale": "Подтверждение устарело", "failed_here": "Не прошёл проверку здесь",
              "failed": "Не прошёл проверку", "degraded": "Нестабильный результат", "unverified": "Протокол не подтверждён"}
    label = labels.get(status, "Протокол не подтверждён")
    if status == "verified" and level not in {"auth_key", "auth-key", "authenticated", "full"}:
        label = "Только предварительная проверка"
    coverage = str(evidence.get("coverage_label") or evidence.get("network_key") or "Сеть проверки не указана")[:200]
    checked = evidence.get("checked_at")
    when = ""
    try:
        if isinstance(checked, (float, int)):
            stamp = datetime.fromtimestamp(checked, tz=timezone.utc)
        else:
            stamp = datetime.fromisoformat(str(checked).replace("Z", "+00:00"))
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
        when = " · " + stamp.astimezone(timezone.utc).strftime("%d.%m %H:%M UTC")
    except (ValueError, TypeError, OverflowError, OSError):
        pass
    return _escape(label) + "\n" + _escape(coverage + when)


def _proxy_button_text(proxy: dict) -> str:
    host = str(proxy.get("server") or proxy.get("host") or "адрес")[:55]
    return host + " · " + secret_type(str(proxy.get("secret") or ""))


def _proxy_keyboard(proxy: dict, flt: str, reserves=()) -> InlineKeyboardMarkup:
    pid = str(proxy.get("id") or "")
    rows = []
    url = _proxy_url(proxy)
    if url:
        rows.append([InlineKeyboardButton(text="↗ Подключить в Telegram", url=url)])
    for index, reserve in enumerate(reserves, start=1):
        reserve_url = _proxy_url(reserve)
        if reserve_url:
            rows.append([InlineKeyboardButton(text=f"Резерв {index} · {_proxy_button_text(reserve)}", url=reserve_url)])
    if _VALID_ID.fullmatch(pid):
        rows.extend([
            [InlineKeyboardButton(text="✓ Работает у меня", callback_data=f"ok:{pid}"),
             InlineKeyboardButton(text="Не работает", callback_data=f"rep:{pid}:{flt}")],
            [InlineKeyboardButton(text="↻ Найти другой", callback_data=f"fn:{flt}:{pid}")],
        ])
    rows.append([InlineKeyboardButton(text="◎ Сеть", callback_data=f"pc:{flt}"),
                 InlineKeyboardButton(text="☰ Каталог", callback_data=f"prx:{flt}")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def _format_found_text(found: dict, label="Основной вариант") -> tuple[str, str, str]:
    server = found.get("server") or found.get("host") or ""
    text = ("<b>✈ Auto Proxy · " + _escape(label) + "</b>\n\n"
            + "<code>" + _escape(f"{server}:{found.get('port', '')}") + "</code>\n"
            + _evidence_text(found) + "\n\n"
            + "Откройте ссылку и подтвердите подключение в Telegram. "
              "Если соединения нет, попробуйте резерв или замените вариант.")
    return text, _proxy_url(found), str(found.get("id") or "")


async def _send_selection(message: Message, uid: int, flt: str, *, edit=False) -> None:
    result = _selection(uid, flt)
    if result.proxy:
        proxy = result.proxy
        _state(uid)["skip"].add(proxy["id"])
        text, _, _ = _format_found_text(proxy)
        keyboard = _proxy_keyboard(proxy, flt, result.reserves)
    else:
        worker.request_pipeline_update()
        text = ("<b>✈ Auto Proxy</b>\n\n"
                "Свежих подтверждённых вариантов по выбранным условиям пока нет. "
                "Новые измерения появятся после проверки. В каталоге можно посмотреть ссылки с явно указанным статусом.\n\n"
                "Подтверждение из вашей российской сети не подменяется проверкой из Орегона.")
        keyboard = _home_keyboard()
    if edit:
        try:
            await message.edit_text(text, parse_mode="HTML", reply_markup=keyboard,
                                    link_preview_options=LinkPreviewOptions(is_disabled=True))
        except TelegramBadRequest:
            pass
    else:
        await _answer(message, text, keyboard=keyboard)


def _catalog_keyboard(proxies: list[dict], flt: str) -> InlineKeyboardMarkup:
    _, ptype, sort = _decode_filter(flt)
    rows = []
    for label, kind in (("Все", "all"), ("FakeTLS", "FakeTLS"), ("RandPad", "RandPad"), ("Plain", "Plain")):
        marker = "✓ " if ptype == kind else ""
        rows.append(InlineKeyboardButton(text=marker + label, callback_data="prx:" + _encode_filter("all", kind, sort)))
    keyboard = [rows]
    for proxy in proxies:
        url = _proxy_url(proxy)
        if url:
            keyboard.append([InlineKeyboardButton(text=_proxy_button_text(proxy), url=url)])
    keyboard.append([InlineKeyboardButton(text="↗ Подобрать подтверждённый", callback_data="fb:" + flt)])
    return InlineKeyboardMarkup(inline_keyboard=keyboard)


async def _send_proxy_panel(message: Message, uid: int, flt=_DEFAULT_FILTER, *, edit=False) -> None:
    result = _selection(uid, flt, manual=True, limit=5)
    proxies = result.proxies
    text = "<b>✈ Auto Proxy · каталог</b>\n\n"
    if not proxies:
        text += "По выбранным условиям ссылок пока нет. Фильтры не снимаются автоматически."
    else:
        text += "В каталоге могут быть варианты без подтверждения протокола.\n\n"
        for index, proxy in enumerate(proxies, 1):
            text += f"<b>{index}. {_escape(_proxy_button_text(proxy))}</b>\n{_evidence_text(proxy)}\n\n"
    text += "Нажатие на ссылку откроет предложение подключения в Telegram."
    keyboard = _catalog_keyboard(proxies, flt)
    if edit:
        try:
            await message.edit_text(text, parse_mode="HTML", reply_markup=keyboard)
        except TelegramBadRequest:
            pass
    else:
        await _answer(message, text, keyboard=keyboard)


@router.message(Command("proxy"))
async def cmd_proxy(message: Message) -> None:
    if not _allowed(message.from_user.id, "select", 2):
        return
    _state(message.from_user.id)["skip"].clear()
    await _send_selection(message, message.from_user.id, _DEFAULT_FILTER)


@router.callback_query(F.data == "free_access")
async def cb_free_access(callback: CallbackQuery) -> None:
    await callback.answer("Доступ бесплатный")
    _state(callback.from_user.id)["skip"].clear()
    await _send_selection(callback.message, callback.from_user.id, _DEFAULT_FILTER)


@router.callback_query(F.data.startswith("prx:"))
async def cb_proxy_filter(callback: CallbackQuery) -> None:
    await callback.answer()
    if not _allowed(callback.from_user.id, "catalog", 1):
        return
    flt = _encode_filter(*_decode_filter(callback.data.split(":", 1)[1]))
    _state(callback.from_user.id)["skip"].clear()
    await _send_proxy_panel(callback.message, callback.from_user.id, flt, edit=True)


@router.callback_query(F.data.startswith("fb:"))
async def cb_find_best(callback: CallbackQuery) -> None:
    await callback.answer("Подбираю по актуальным измерениям")
    if not _allowed(callback.from_user.id, "select", 2):
        return
    flt = _encode_filter(*_decode_filter(callback.data.split(":", 1)[1]))
    _state(callback.from_user.id)["skip"].clear()
    await _send_selection(callback.message, callback.from_user.id, flt)


@router.callback_query(F.data.startswith("fn:"))
async def cb_find_next(callback: CallbackQuery) -> None:
    await callback.answer()
    if not _allowed(callback.from_user.id, "select", 2):
        return
    parts = callback.data.split(":")
    flt = _encode_filter(*_decode_filter(parts[1] if len(parts) > 1 else _DEFAULT_FILTER))
    if len(parts) > 2 and _VALID_ID.fullmatch(parts[2]):
        _state(callback.from_user.id)["skip"].add(parts[2])
    await _send_selection(callback.message, callback.from_user.id, flt, edit=True)


def _profile_keyboard(flt: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="Домашний интернет / Wi-Fi", callback_data=f"fp:{flt}:wifi")],
        [InlineKeyboardButton(text="Мобильный интернет", callback_data=f"fp:{flt}:cellular")],
        [InlineKeyboardButton(text="Сеть неизвестна", callback_data=f"fp:{flt}:unknown")],
    ])


@router.callback_query(F.data.startswith("pc:"))
async def cb_change_profile(callback: CallbackQuery) -> None:
    await callback.answer()
    flt = _encode_filter(*_decode_filter(callback.data.split(":", 1)[1]))
    await _answer(callback.message, "<b>Сеть подключения</b>\n\nБот не видит вашего оператора. "
                  "Выбор помогает сопоставить доступные измерения, но сам по себе не подтверждает работу в этой сети.",
                  keyboard=_profile_keyboard(flt))


@router.callback_query(F.data.startswith("fp:"))
async def cb_choose_profile(callback: CallbackQuery) -> None:
    await callback.answer("Сеть сохранена для следующего подбора")
    parts = callback.data.split(":")
    flt = _encode_filter(*_decode_filter(parts[1] if len(parts) > 1 else _DEFAULT_FILTER))
    network = parts[2] if len(parts) > 2 else "unknown"
    _state(callback.from_user.id)["network"] = network if network in {"wifi", "cellular", "unknown"} else "unknown"
    _state(callback.from_user.id)["skip"].clear()
    await _send_selection(callback.message, callback.from_user.id, flt)


async def _save_proxy_feedback(proxy_id: str, user_id: int, works: bool) -> bool:
    if not _VALID_ID.fullmatch(proxy_id) or not any(p.get("id") == proxy_id for p in worker.CACHED_BEST_PROXIES):
        return False
    if works:
        feedback.report_success(proxy_id, user_id)
    else:
        feedback.report_failure(proxy_id, user_id)
    if _proxy_repo is not None:
        try:
            await _proxy_repo.record_feedback(proxy_id, user_id, works)
        except Exception:
            logger.warning("bot feedback persistence unavailable")
    return True


@router.callback_query(F.data.startswith("ok:"))
async def report_working(callback: CallbackQuery) -> None:
    if not _allowed(callback.from_user.id, "feedback", 2):
        await callback.answer("Отметка уже обрабатывается")
        return
    saved = await _save_proxy_feedback(callback.data.split(":", 1)[1], callback.from_user.id, True)
    await callback.answer("Ваша отметка сохранена. Она не заменяет автоматическую проверку." if saved else "Ссылка устарела. Запросите новый подбор.", show_alert=True)


@router.callback_query(F.data.startswith("rep:"))
async def report(callback: CallbackQuery) -> None:
    if not _allowed(callback.from_user.id, "feedback", 2):
        await callback.answer("Отметка уже обрабатывается")
        return
    parts = callback.data.split(":")
    pid = parts[1] if len(parts) > 1 else ""
    flt = _encode_filter(*_decode_filter(parts[2] if len(parts) > 2 else _DEFAULT_FILTER))
    saved = await _save_proxy_feedback(pid, callback.from_user.id, False)
    await callback.answer("Скрыто для вас. Подбираю замену." if saved else "Ссылка устарела. Обновляю подбор.")
    await _send_selection(callback.message, callback.from_user.id, flt, edit=True)


@router.callback_query(F.data == "noop")
async def cb_noop(callback: CallbackQuery) -> None:
    await callback.answer()
