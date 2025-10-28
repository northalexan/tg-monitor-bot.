# main.py
import os
import re
import sqlite3
import asyncio
import logging
from datetime import datetime, timedelta

import requests
from cryptography.fernet import Fernet
from aiohttp import web

from telethon import TelegramClient, events
from telethon.sessions import StringSession
from telethon.errors import (
    SessionPasswordNeededError,
    PhoneNumberInvalidError,
    PhoneCodeInvalidError,
    PhoneCodeExpiredError,
    FloodWaitError,
)

from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
)

# =========================
# ENV
# =========================
API_ID = int(os.environ["API_ID"])
API_HASH = os.environ["API_HASH"]
BOT_TOKEN = os.environ["BOT_TOKEN"]

FERNET_KEY = os.environ.get("FERNET_KEY")
PORT = int(os.environ.get("PORT", "8000"))
DB_PATH = os.environ.get("DB_PATH", "data.db")

if not FERNET_KEY:
    # сгенерим и выведем, чтобы ты добавил в Variables
    FERNET_KEY = Fernet.generate_key().decode()
    print("FERNET_KEY (ДОБАВЬ в Environment):", FERNET_KEY)

fernet = Fernet(FERNET_KEY)

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("tg-monitor-bot")


# =========================
# DB
# =========================
def _conn():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with _conn() as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS users(
                tg_id INTEGER PRIMARY KEY,
                created_at TEXT
            )"""
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS sessions(
                tg_id INTEGER PRIMARY KEY,
                enc_session BLOB NOT NULL,
                phone TEXT,
                keywords TEXT DEFAULT '',
                negative TEXT DEFAULT '',
                only_public INTEGER DEFAULT 0,
                webhook TEXT DEFAULT '',
                created_at TEXT
            )"""
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS pending(
                tg_id INTEGER PRIMARY KEY,
                tmp_enc_session BLOB NOT NULL,
                phone TEXT NOT NULL,
                code_hash TEXT,              -- ВАЖНО: храним phone_code_hash
                sent_at TEXT NOT NULL
            )"""
        )


def now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def enc(b: bytes) -> bytes:
    return fernet.encrypt(b)


def dec(b: bytes) -> bytes:
    return fernet.decrypt(b)


# =========================
# LOGIN FLOW
# =========================
async def start_login(tg_id: int, phone: str) -> str:
    """
    1) создаем временную сессию
    2) шлем код и сохраняем code_hash
    """
    sess = StringSession()
    client = TelegramClient(sess, API_ID, API_HASH)
    await client.connect()
    try:
        sent = await client.send_code_request(phone)  # returns types.auth.SentCode
    except PhoneNumberInvalidError:
        await client.disconnect()
        return "Телефон некорректен. Формат: /phone +79991234567"

    tmp = sess.save()
    with _conn() as c:
        c.execute(
            "REPLACE INTO pending(tg_id,tmp_enc_session,phone,code_hash,sent_at) VALUES(?,?,?,?,?)",
            (tg_id, enc(tmp.encode()), phone, sent.phone_code_hash, now_iso()),
        )
    await client.disconnect()
    return "Код отправлен. Введи /code 12345 (или /resend для нового кода)."


async def resend_code(tg_id: int) -> str:
    """
    Если запросил новый код — записываем новый phone_code_hash.
    """
    with _conn() as c:
        p = c.execute("SELECT * FROM pending WHERE tg_id=?", (tg_id,)).fetchone()
    if not p:
        return "Нет активной попытки. Напиши /connect"

    tmp = StringSession(dec(p["tmp_enc_session"]).decode())
    client = TelegramClient(tmp, API_ID, API_HASH)
    await client.connect()
    try:
        sent = await client.send_code_request(p["phone"])
    except FloodWaitError as e:
        await client.disconnect()
        return f"Слишком часто. Подожди {e.seconds} сек."
    finally:
        await client.disconnect()

    with _conn() as c:
        c.execute(
            "UPDATE pending SET code_hash=?, sent_at=? WHERE tg_id=?",
            (sent.phone_code_hash, now_iso(), tg_id),
        )
    return "Отправил новый код. Введи /code 12345"


async def confirm_code(tg_id: int, code: str) -> str:
    """
    Подтверждаем вход:
    - берем phone и code_hash из pending
    - sign_in(phone, code, phone_code_hash=...)
    """
    with _conn() as c:
        p = c.execute("SELECT * FROM pending WHERE tg_id=?", (tg_id,)).fetchone()
    if not p:
        return "Нет активной попытки. Напиши /connect"

    if not p["code_hash"]:
        return "Нет сохранённого phone_code_hash. Нажми /resend и потом снова /code."

    tmp = StringSession(dec(p["tmp_enc_session"]).decode())
    client = TelegramClient(tmp, API_ID, API_HASH)
    await client.connect()
    try:
        await client.sign_in(
            phone=p["phone"], code=code.strip(), phone_code_hash=p["code_hash"]
        )
    except SessionPasswordNeededError:
        await client.disconnect()
        return "Включена двухэтапка. Введи /password <пароль 2FA>"
    except PhoneCodeInvalidError:
        await client.disconnect()
        return "Неверный код. Ещё раз /code 12345 или /resend"
    except PhoneCodeExpiredError:
        await client.disconnect()
        return "Код просрочен. Нажми /resend для нового."
    except FloodWaitError as e:
        await client.disconnect()
        return f"Слишком часто. Подожди {e.seconds} сек."

    # успех
    s = client.session.save()
    await client.disconnect()

    with _conn() as c:
        c.execute("DELETE FROM pending WHERE tg_id=?", (tg_id,))
        c.execute(
            """REPLACE INTO sessions(tg_id,enc_session,phone,created_at)
               VALUES(?,?,?,?)""",
            (tg_id, enc(s.encode()), p["phone"], now_iso()),
        )

    # запуск мониторинга для пользователя
    asyncio.create_task(run_monitor_for_user(tg_id))
    return "✅ Подключено! Мониторинг запущен. /status для проверки."


async def confirm_password(tg_id: int, pwd: str) -> str:
    with _conn() as c:
        p = c.execute("SELECT * FROM pending WHERE tg_id=?", (tg_id,)).fetchone()
    if not p:
        return "Нет ожидания пароля. /connect"

    tmp = StringSession(dec(p["tmp_enc_session"]).decode())
    client = TelegramClient(tmp, API_ID, API_HASH)
    await client.connect()
    try:
        await client.sign_in(password=pwd)
    except Exception as e:
        await client.disconnect()
        return f"Пароль не подошёл: {e.__class__.__name__}"

    s = client.session.save()
    await client.disconnect()

    with _conn() as c:
        c.execute("DELETE FROM pending WHERE tg_id=?", (tg_id,))
        c.execute(
            """REPLACE INTO sessions(tg_id,enc_session,phone,created_at)
               VALUES(?,?,?,?)""",
            (tg_id, enc(s.encode()), None, now_iso()),
        )

    asyncio.create_task(run_monitor_for_user(tg_id))
    return "✅ Пароль принят. Мониторинг запущен."


# =========================
# MONITOR
# =========================
async def run_monitor_for_user(tg_id: int):
    with _conn() as c:
        s = c.execute("SELECT * FROM sessions WHERE tg_id=?", (tg_id,)).fetchone()
    if not s:
        return

    sess = StringSession(dec(s["enc_session"]).decode())
    client = TelegramClient(sess, API_ID, API_HASH)
    await client.connect()

    kw = s["keywords"] or ""
    ng = s["negative"] or ""
    only_pub = bool(s["only_public"])
    webhook = (s["webhook"] or "").strip()

    kw_re = re.compile(kw, re.IGNORECASE | re.DOTALL) if kw else None
    ng_re = re.compile(ng, re.IGNORECASE | re.DOTALL) if ng else None

    def fits(text: str) -> bool:
        if not text:
            return False
        if kw_re and not kw_re.search(text):
            return False
        if ng_re and ng_re.search(text):
            return False
        return True

    @client.on(events.NewMessage(incoming=True))
    async def on_msg(event):
        try:
            if only_pub:
                chat = await event.get_chat()
                if not getattr(chat, "username", None):
                    return
            text = event.message.message or ""
            if not fits(text):
                return
            chat = await event.get_chat()
            title = getattr(chat, "title", None) or getattr(chat, "username", None)
            link = (
                f"https://t.me/{chat.username}/{event.message.id}"
                if getattr(chat, "username", None)
                else None
            )
            msg = f"🛰 Совпадение\nЧат: {title}\n{now_iso()}\n{(link or '')}\n—\n{text[:1000]}"
            await client.send_message("me", msg)
            if webhook:
                try:
                    requests.post(
                        webhook,
                        json={"chat": title, "text": text, "link": link},
                        timeout=4,
                    )
                except Exception:
                    pass
        except Exception:
            pass

    await client.run_until_disconnected()


# =========================
# BOT COMMANDS
# =========================
async def cmd_start(u, c: ContextTypes.DEFAULT_TYPE):
    await u.message.reply_text(
        "Привет! /connect чтобы подключить аккаунт. Дальше: /phone +79991234567 → /code 12345 (или /password ...)"
    )


async def cmd_connect(u, c):
    await u.message.reply_text("Введи телефон в формате: /phone +79991234567")


async def cmd_phone(u, c):
    if not c.args:
        return await u.message.reply_text("Формат: /phone +7999...")
    msg = await start_login(u.effective_user.id, c.args[0])
    await u.message.reply_text(msg)


async def cmd_resend(u, c):
    msg = await resend_code(u.effective_user.id)
    await u.message.reply_text(msg)


async def cmd_code(u, c):
    if not c.args:
        return await u.message.reply_text("Формат: /code 12345")
    msg = await confirm_code(u.effective_user.id, c.args[0])
    await u.message.reply_text(msg)


async def cmd_password(u, c):
    if not c.args:
        return await u.message.reply_text("Формат: /password ваш_пароль")
    msg = await confirm_password(u.effective_user.id, " ".join(c.args))
    await u.message.reply_text(msg)


async def cmd_keywords(u, c):
    txt = u.message.text.partition(" ")[2].strip()
    with _conn() as x:
        x.execute(
            "UPDATE sessions SET keywords=? WHERE tg_id=?", (txt, u.effective_user.id)
        )
    await u.message.reply_text("KEYWORDS обновлены.")


async def cmd_negative(u, c):
    txt = u.message.text.partition(" ")[2].strip()
    with _conn() as x:
        x.execute(
            "UPDATE sessions SET negative=? WHERE tg_id=?", (txt, u.effective_user.id)
        )
    await u.message.reply_text("NEGATIVE обновлены.")


async def cmd_status(u, c):
    with _conn() as x:
        s = x.execute(
            "SELECT keywords,negative,only_public FROM sessions WHERE tg_id=?",
            (u.effective_user.id,),
        ).fetchone()
    await u.message.reply_text(str(dict(s)) if s else "Нет активной сессии.")


# =========================
# KEEP-ALIVE (aiohttp)
# =========================
async def _ok(_):
    return web.Response(text="OK")


async def start_keepalive():
    app = web.Application()
    app.router.add_get("/", _ok)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()


# =========================
# ENTRY
# =========================
async def main():
    init_db()
    await start_keepalive()

    application = Application.builder().token(BOT_TOKEN).build()

    application.add_handler(CommandHandler("start", cmd_start))
    application.add_handler(CommandHandler("connect", cmd_connect))
    application.add_handler(CommandHandler("phone", cmd_phone))
    application.add_handler(CommandHandler("resend", cmd_resend))
    application.add_handler(CommandHandler("code", cmd_code))
    application.add_handler(CommandHandler("password", cmd_password))
    application.add_handler(CommandHandler("keywords", cmd_keywords))
    application.add_handler(CommandHandler("negative", cmd_negative))
    application.add_handler(CommandHandler("status", cmd_status))

    # Важно: close_loop=False → не закрываем event loop (иначе Render ругался)
    await application.run_polling(allowed_updates=[], close_loop=False)


if __name__ == "__main__":
    asyncio.run(main())