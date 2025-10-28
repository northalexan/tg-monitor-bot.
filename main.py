import os
import re
import sqlite3
import asyncio
import logging
from datetime import datetime
from telethon.tl import functions

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

from telegram.ext import Application, CommandHandler
from telegram.error import Conflict

# =========================
# ENV
# =========================
API_ID = int(os.environ["API_ID"])
API_HASH = os.environ["API_HASH"]
BOT_TOKEN = os.environ["BOT_TOKEN"]

PORT = int(os.environ.get("PORT", "8000"))
DB_PATH = os.environ.get("DB_PATH", "data.db")

FERNET_KEY = os.environ.get("FERNET_KEY")
if not FERNET_KEY:
    FERNET_KEY = Fernet.generate_key().decode()
    print("FERNET_KEY (добавь в Environment):", FERNET_KEY)

fernet = Fernet(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("tg-monitor")

# Активные Telethon-клиенты (не даём их собирать GC)
ACTIVE_CLIENTS = {}  # tg_id -> TelegramClient


# =========================
# DB
# =========================
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    with db() as c:
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
                code_hash TEXT,
                sent_at TEXT NOT NULL
            )"""
        )
        # миграция: добавим code_hash, если старый столбец отсутствует
        cols = [r["name"] for r in c.execute("PRAGMA table_info(pending)").fetchall()]
        if "code_hash" not in cols:
            c.execute("ALTER TABLE pending ADD COLUMN code_hash TEXT")


def now_iso():
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def enc(b: bytes) -> bytes:
    return fernet.encrypt(b)


def dec(b: bytes) -> bytes:
    return fernet.decrypt(b)


# =========================
# LOGIN FLOW
# =========================
async def start_login(tg_id: int, phone: str) -> str:
    sess = StringSession()
    client = TelegramClient(sess, API_ID, API_HASH)
    await client.connect()
    try:
        sent = await client.send_code_request(phone)  # <- получаем хэш
    except PhoneNumberInvalidError:
        await client.disconnect()
        return "Телефон некорректен. Формат: /phone +79991234567"
    tmp = sess.save()
    with db() as c:
        c.execute("""REPLACE INTO pending(tg_id,tmp_enc_session,phone,sent_at,code_hash)
                     VALUES(?,?,?,?,?)""",
                  (tg_id, enc(tmp.encode()), phone, now_iso(), sent.phone_code_hash))
    await client.disconnect()
    return "Код отправлен. Введите /code 12345 (только цифры)."


async def resend_code(tg_id: int) -> str:
    """Переотправка кода и обновление code_hash в pending."""
    with db() as c:
        p = c.execute("SELECT tmp_enc_session, phone FROM pending WHERE tg_id=?", (tg_id,)).fetchone()
    if not p:
        return "Нет активной попытки. Сначала /connect"

    sess = StringSession(dec(p["tmp_enc_session"]).decode())
    client = TelegramClient(sess, API_ID, API_HASH)
    await client.connect()
    try:
        sent = await client.send_code_request(p["phone"])
    finally:
        await client.disconnect()

    with db() as c:
        c.execute(
            "UPDATE pending SET code_hash=?, sent_at=? WHERE tg_id=?",
            (getattr(sent, "phone_code_hash", None), now_iso(), tg_id),
        )
    return "Отправил новый код. Введите /code 12345 (используй самый последний)."


async def confirm_code(tg_id: int, code: str) -> str:
    with db() as c:
        p = c.execute("SELECT * FROM pending WHERE tg_id=?", (tg_id,)).fetchone()
    if not p:
        return "Нет активной попытки. Набери /connect и укажи телефон."
    tmp = StringSession(dec(p["tmp_enc_session"]).decode())
    client = TelegramClient(tmp, API_ID, API_HASH)
    await client.connect()
    try:
        # передаём И телефон, И код, И phone_code_hash
        await client.sign_in(phone=p["phone"], code=code.strip(), phone_code_hash=p["code_hash"])
    except SessionPasswordNeededError:
        await client.disconnect()
        return "Включена двухэтапка. Введи /password <пароль>."
    except PhoneCodeInvalidError:
        await client.disconnect()
        return "Неверный код. Попробуй ещё раз или /resend чтобы выслать новый."
    except PhoneCodeExpiredError:
        await client.disconnect()
        return "Код просрочен. Набери /resend, вышлю новый."
    except FloodWaitError as e:
        await client.disconnect()
        return f"Слишком часто. Подожди {e.seconds} сек."
    s = client.session.save()
    await client.disconnect()
    with db() as c:
        c.execute("DELETE FROM pending WHERE tg_id=?", (tg_id,))
        c.execute("""REPLACE INTO sessions(tg_id,enc_session,phone,created_at)
                     VALUES(?,?,?,?)""",
                  (tg_id, enc(s.encode()), p["phone"], now_iso()))
    asyncio.create_task(run_monitor_for_user(tg_id))
    return "✅ Подключено! Мониторинг запущен."

async def confirm_password(tg_id: int, pwd: str) -> str:
    """Шаг 2b: если включена 2FA — принимаем пароль и завершаем логин."""
    with db() as c:
        p = c.execute("SELECT * FROM pending WHERE tg_id=?", (tg_id,)).fetchone()
    if not p:
        return "Нет ожидания пароля. Сначала /connect"

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

    with db() as c:
        c.execute("DELETE FROM pending WHERE tg_id=?", (tg_id,))
        c.execute(
            """REPLACE INTO sessions(tg_id, enc_session, phone, created_at)
               VALUES(?, ?, ?, ?)""",
            (tg_id, enc(s.encode()), None, now_iso()),
        )

    asyncio.create_task(run_monitor_for_user(tg_id))
    return "✅ Пароль принят. Мониторинг запущен."


async def resend_code(tg_id: int) -> str:
    with db() as c:
        p = c.execute("SELECT * FROM pending WHERE tg_id=?", (tg_id,)).fetchone()
    if not p:
        return "Нет активной попытки логина. Набери /connect."
    tmp = StringSession(dec(p["tmp_enc_session"]).decode())
    client = TelegramClient(tmp, API_ID, API_HASH)
    await client.connect()
    try:
        # Телеграм может требовать старый хэш для корректного ресенда
        if p["code_hash"]:
            r = await client(functions.auth.ResendCodeRequest(phone_number=p["phone"], phone_code_hash=p["code_hash"]))
            new_hash = r.phone_code_hash
        else:
            sent = await client.send_code_request(p["phone"])
            new_hash = sent.phone_code_hash
    finally:
        await client.disconnect()
    with db() as c:
        c.execute("UPDATE pending SET code_hash=?, sent_at=? WHERE tg_id=?",
                  (new_hash, now_iso(), tg_id))
    return "Отправил новый код. Введи /code 12345."

# =========================
# MONITOR
# =========================
async def run_monitor_for_user(tg_id: int):
    """Старт фонового мониторинга входящих сообщений для пользователя."""
    if tg_id in ACTIVE_CLIENTS:
        return

    with db() as c:
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
        return bool(text and (not kw_re or kw_re.search(text)) and (not ng_re or not ng_re.search(text)))

    @client.on(events.NewMessage(incoming=True))
    async def handler(event):
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
            link = f"https://t.me/{chat.username}/{event.message.id}" if getattr(chat, "username", None) else None

            msg = f"🛰 Совпадение\nЧат: {title}\n{now_iso()}\n{link or ''}\n—\n{text[:1000]}"
            await client.send_message("me", msg)

            if webhook:
                try:
                    requests.post(webhook, json={"chat": title, "text": text, "link": link}, timeout=3)
                except Exception:
                    pass
        except Exception:
            pass

    ACTIVE_CLIENTS[tg_id] = client
    asyncio.create_task(client.run_until_disconnected())
    log.info("Monitor started for user %s", tg_id)


# =========================
# BOT COMMANDS
# =========================
async def cmd_start(update, context):
    await update.message.reply_text(
        "Привет! /connect чтобы подключить аккаунт. Дальше: /phone +79991234567 → /code 12345 (или /password ...)\n"
        "Если код не приходит/просрочен: /resend"
    )


async def cmd_connect(update, context):
    await update.message.reply_text("Введите телефон: /phone +79991234567")


async def cmd_phone(update, context):
    if not context.args:
        return await update.message.reply_text("Формат: /phone +7999...")
    msg = await start_login(update.effective_user.id, context.args[0])
    await update.message.reply_text(msg)


async def cmd_code(update, context):
    if not context.args:
        return await update.message.reply_text("Формат: /code 12345")
    msg = await confirm_code(update.effective_user.id, context.args[0])
    await update.message.reply_text(msg)


async def cmd_password(update, context):
    if not context.args:
        return await update.message.reply_text("Формат: /password ваш_пароль")
    msg = await confirm_password(update.effective_user.id, " ".join(context.args))
    await update.message.reply_text(msg)


async def cmd_resend(update, context):
    msg = await resend_code(update.effective_user.id)
    await update.message.reply_text(msg)


async def cmd_keywords(update, context):
    txt = update.message.text.partition(" ")[2].strip()
    with db() as c:
        c.execute("UPDATE sessions SET keywords=? WHERE tg_id=?", (txt, update.effective_user.id))
    await update.message.reply_text("KEYWORDS обновлены.")


async def cmd_negative(update, context):
    txt = update.message.text.partition(" ")[2].strip()
    with db() as c:
        c.execute("UPDATE sessions SET negative=? WHERE tg_id=?", (txt, update.effective_user.id))
    await update.message.reply_text("NEGATIVE обновлены.")


async def cmd_status(update, context):
    with db() as c:
        s = c.execute(
            "SELECT keywords, negative, only_public FROM sessions WHERE tg_id=?",
            (update.effective_user.id,),
        ).fetchone()
    if s:
        await update.message.reply_text(
            f"keywords={s['keywords']!r}\nnegative={s['negative']!r}\nonly_public={s['only_public']}"
        )
    else:
        await update.message.reply_text("Нет активной сессии. /connect")


# =========================
# KEEP-ALIVE (Render)
# =========================
async def keepalive(_):
    return web.Response(text="OK")


async def start_keepalive():
    app = web.Application()
    app.router.add_get("/", keepalive)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()


# =========================
# ENTRYPOINT (Render-safe)
# =========================
async def main():
    init_db()
    await start_keepalive()

    application = Application.builder().token(BOT_TOKEN).build()
    application.add_handler(CommandHandler("start", cmd_start))
    application.add_handler(CommandHandler("connect", cmd_connect))
    application.add_handler(CommandHandler("phone", cmd_phone))
    application.add_handler(CommandHandler("code", cmd_code))
    application.add_handler(CommandHandler("password", cmd_password))
    application.add_handler(CommandHandler("resend", cmd_resend))
    application.add_handler(CommandHandler("keywords", cmd_keywords))
    application.add_handler(CommandHandler("negative", cmd_negative))
    application.add_handler(CommandHandler("status", cmd_status))

    await application.initialize()
    # Предочистка: убираем вебхук и сбрасываем подвисшие апдейты
    await application.bot.delete_webhook(drop_pending_updates=True)
    await application.start()


    # Защита от параллельного polling (409 Conflict)
    while True:
        try:
            await application.updater.start_polling()
            break
        except Conflict:
            print("Another polling instance detected. Retrying in 5s…")
            await asyncio.sleep(5)

    print("✅ Бот запущен. Ожидаю команды…")
    await asyncio.Future()  # удерживаем процесс


if __name__ == "__main__":
    asyncio.run(main())