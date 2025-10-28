import os, re, sqlite3, asyncio, logging, requests
from datetime import datetime
from typing import Optional
from cryptography.fernet import Fernet
from telethon import TelegramClient, events
from telethon.sessions import StringSession
from telethon.errors import (
    SessionPasswordNeededError, PhoneNumberInvalidError,
    PhoneCodeInvalidError, PhoneCodeExpiredError, FloodWaitError
)
from telegram.ext import Application, CommandHandler, ContextTypes
from aiohttp import web

# ---------- ENV ----------
API_ID = int(os.environ["API_ID"])
API_HASH = os.environ["API_HASH"]
BOT_TOKEN = os.environ["BOT_TOKEN"]
FERNET_KEY = os.environ.get("FERNET_KEY")
PORT = int(os.environ.get("PORT", "8000"))
DB_PATH = os.environ.get("DB_PATH", "data.db")

if not FERNET_KEY:
    from cryptography.fernet import Fernet as FKey
    FERNET_KEY = FKey.generate_key().decode()
    print("FERNET_KEY (СОХРАНИ в Environment):", FERNET_KEY)

fernet = Fernet(FERNET_KEY)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("tg-monitor")

# ---------- DB ----------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    with db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS users(
          tg_id INTEGER PRIMARY KEY, created_at TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS sessions(
          tg_id INTEGER PRIMARY KEY, enc_session BLOB NOT NULL,
          phone TEXT, keywords TEXT DEFAULT '', negative TEXT DEFAULT '',
          only_public INTEGER DEFAULT 0, webhook TEXT DEFAULT '', created_at TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS pending(
          tg_id INTEGER PRIMARY KEY, tmp_enc_session BLOB NOT NULL,
          phone TEXT NOT NULL, sent_at TEXT NOT NULL)""")

def now_iso(): return datetime.utcnow().isoformat(timespec="seconds")+"Z"
def enc(b: bytes) -> bytes: return fernet.encrypt(b)
def dec(b: bytes) -> bytes: return fernet.decrypt(b)

# ---------- LOGIN ----------
async def start_login(tg_id: int, phone: str) -> str:
    sess = StringSession()
    client = TelegramClient(sess, API_ID, API_HASH)
    await client.connect()
    try:
        await client.send_code_request(phone)
    except PhoneNumberInvalidError:
        await client.disconnect()
        return "Телефон некорректен. Формат: /phone +79991234567"
    tmp = sess.save()
    with db() as c:
        c.execute("REPLACE INTO pending(tg_id,tmp_enc_session,phone,sent_at) VALUES(?,?,?,?)",
                  (tg_id, enc(tmp.encode()), phone, now_iso()))
    await client.disconnect()
    return "Код отправлен. Введите /code 12345"

async def confirm_code(tg_id: int, code: str) -> str:
    with db() as c:
        p = c.execute("SELECT * FROM pending WHERE tg_id=?", (tg_id,)).fetchone()
    if not p: return "Нет активной попытки. /connect"
    tmp = StringSession(dec(p["tmp_enc_session"]).decode())
    client = TelegramClient(tmp, API_ID, API_HASH)
    await client.connect()
    try:
        await client.sign_in(phone=p["phone"], code=code.strip())
    except SessionPasswordNeededError:
        await client.disconnect()
        return "Двухэтапка. Введите /password пароль"
    except PhoneCodeInvalidError:
        await client.disconnect()
        return "Неверный код"
    except PhoneCodeExpiredError:
        await client.disconnect()
        return "Код просрочен. /connect"
    except FloodWaitError as e:
        await client.disconnect()
        return f"Слишком часто. Подождите {e.seconds} сек."
    s = client.session.save()
    await client.disconnect()
    with db() as c:
        c.execute("DELETE FROM pending WHERE tg_id=?", (tg_id,))
        c.execute("""REPLACE INTO sessions(tg_id,enc_session,phone,created_at)
                     VALUES(?,?,?,?)""", (tg_id, enc(s.encode()), p["phone"], now_iso()))
    asyncio.create_task(run_monitor_for_user(tg_id))
    return "✅ Подключено! Мониторинг запущен."

async def confirm_password(tg_id: int, pwd: str) -> str:
    with db() as c:
        p = c.execute("SELECT * FROM pending WHERE tg_id=?", (tg_id,)).fetchone()
    if not p: return "Нет ожидания пароля. /connect"
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
        c.execute("""REPLACE INTO sessions(tg_id,enc_session,phone,created_at)
                     VALUES(?,?,?,?)""", (tg_id, enc(s.encode()), None, now_iso()))
    asyncio.create_task(run_monitor_for_user(tg_id))
    return "✅ Пароль принят. Мониторинг запущен."

# ---------- MONITOR ----------
async def run_monitor_for_user(tg_id: int):
    with db() as c:
        s = c.execute("SELECT * FROM sessions WHERE tg_id=?", (tg_id,)).fetchone()
    if not s: return
    sess = StringSession(dec(s["enc_session"]).decode())
    client = TelegramClient(sess, API_ID, API_HASH)
    await client.connect()
    kw = s["keywords"] or ""
    ng = s["negative"] or ""
    only_pub = bool(s["only_public"])
    webhook = (s["webhook"] or "").strip()
    kw_re = re.compile(kw, re.IGNORECASE|re.DOTALL) if kw else None
    ng_re = re.compile(ng, re.IGNORECASE|re.DOTALL) if ng else None
    def fits(t): return t and (not kw_re or kw_re.search(t)) and (not ng_re or not ng_re.search(t))
    @client.on(events.NewMessage(incoming=True))
    async def handler(event):
        try:
            if only_pub:
                chat = await event.get_chat()
                if not getattr(chat, "username", None): return
            text = event.message.message or ""
            if not fits(text): return
            chat = await event.get_chat()
            title = getattr(chat, "title", None) or getattr(chat, "username", None)
            link = f"https://t.me/{chat.username}/{event.message.id}" if getattr(chat, "username", None) else None
            msg = f"🛰 Совпадение\nЧат: {title}\n{now_iso()}\n{link or ''}\n—\n{text[:1000]}"
            await client.send_message("me", msg)
            if webhook:
                try: requests.post(webhook, json={"chat": title,"text":text,"link":link})
                except: pass
        except Exception: pass
    await client.run_until_disconnected()

# ---------- BOT ----------
async def cmd_start(u, c): await u.message.reply_text("Привет! /connect чтобы подключить аккаунт.")
async def cmd_connect(u,c): await u.message.reply_text("Введите телефон: /phone +79991234567")
async def cmd_phone(u,c):
    if not c.args: return await u.message.reply_text("Формат: /phone +7999...")
    m=await start_login(u.effective_user.id, c.args[0]); await u.message.reply_text(m)
async def cmd_code(u,c):
    if not c.args: return await u.message.reply_text("Формат: /code 12345")
    m=await confirm_code(u.effective_user.id,c.args[0]); await u.message.reply_text(m)
async def cmd_password(u,c):
    if not c.args: return await u.message.reply_text("Формат: /password пароль")
    m=await confirm_password(u.effective_user.id," ".join(c.args)); await u.message.reply_text(m)

async def cmd_keywords(u,c):
    txt=u.message.text.partition(" ")[2].strip()
    with db() as x:x.execute("UPDATE sessions SET keywords=? WHERE tg_id=?", (txt,u.effective_user.id))
    await u.message.reply_text("KEYWORDS обновлены.")
async def cmd_negative(u,c):
    txt=u.message.text.partition(" ")[2].strip()
    with db() as x:x.execute("UPDATE sessions SET negative=? WHERE tg_id=?", (txt,u.effective_user.id))
    await u.message.reply_text("NEGATIVE обновлены.")
async def cmd_status(u,c):
    with db() as x:s=x.execute("SELECT keywords,negative,only_public FROM sessions WHERE tg_id=?",(u.effective_user.id,)).fetchone()
    await u.message.reply_text(str(dict(s)) if s else "Нет сессии.")

# ---------- KEEP-ALIVE ----------
async def keepalive(_): return web.Response(text="OK")
async def start_keepalive():
    app=web.Application(); app.router.add_get("/",keepalive)
    r=web.AppRunner(app); await r.setup(); s=web.TCPSite(r,"0.0.0.0",PORT); await s.start()

async def main():
    init_db()
    await start_keepalive()
    a=Application.builder().token(BOT_TOKEN).build()
    a.add_handler(CommandHandler("start",cmd_start))
    a.add_handler(CommandHandler("connect",cmd_connect))
    a.add_handler(CommandHandler("phone",cmd_phone))
    a.add_handler(CommandHandler("code",cmd_code))
    a.add_handler(CommandHandler("password",cmd_password))
    a.add_handler(CommandHandler("keywords",cmd_keywords))
    a.add_handler(CommandHandler("negative",cmd_negative))
    a.add_handler(CommandHandler("status",cmd_status))
    await a.run_polling(allowed_updates=[])
import asyncio
from telegram.ext import ApplicationBuilder, CommandHandler

async def start(update, context):
    await update.message.reply_text("Бот запущен и работает!")

async def main():
    app = ApplicationBuilder().token("ТОКЕН_ТВОЕГО_БОТА").build()

    app.add_handler(CommandHandler("start", start))

    print("✅ Бот запущен. Ожидаю команды...")
    await app.run_polling()

if __name__ == "__main__":
    asyncio.run(main())
