import os
import asyncio
from telethon import TelegramClient, events
from telethon.sessions import StringSession
from telethon.errors import (
    PhoneNumberInvalidError, PhoneCodeInvalidError, SessionPasswordNeededError
)
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# === Конфигурация ===
API_ID = int(os.environ.get("API_ID"))
API_HASH = os.environ.get("API_HASH")
BOT_TOKEN = os.environ.get("BOT_TOKEN")

# Временное хранилище данных пользователей
user_sessions = {}
user_keywords = {}


# === /connect ===
async def connect(update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Введите номер телефона (пример: +79991234567)")
    context.user_data["awaiting_phone"] = True


# === Обработка всех сообщений ===
async def handle_message(update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text.strip()

    # 1. Пользователь вводит номер телефона
    if context.user_data.get("awaiting_phone"):
        phone = text
        try:
            session = StringSession()
            client = TelegramClient(session, API_ID, API_HASH)
            await client.connect()
            await client.send_code_request(phone)

            user_sessions[user_id] = {"client": client, "session": session, "phone": phone}
            context.user_data["awaiting_phone"] = False
            context.user_data["awaiting_code"] = True

            await update.message.reply_text("Код отправлен. Введите код из Telegram:")
        except PhoneNumberInvalidError:
            await update.message.reply_text("❌ Неверный номер телефона.")
        return

    # 2. Пользователь вводит код
    if context.user_data.get("awaiting_code"):
        code = text
        data = user_sessions.get(user_id)
        if not data:
            await update.message.reply_text("Нет активной попытки входа. Используйте /connect")
            return

        client = data["client"]
        phone = data["phone"]

        try:
            await client.sign_in(phone=phone, code=code)
            context.user_data["awaiting_code"] = False
            await update.message.reply_text("✅ Успешный вход. Теперь введите ключевые слова через запятую:")
            context.user_data["awaiting_keywords"] = True
        except PhoneCodeInvalidError:
            await update.message.reply_text("❌ Неверный код.")
        except SessionPasswordNeededError:
            await update.message.reply_text("⚠️ У вас включена двухэтапная аутентификация. Вход невозможен.")
        return

    # 3. Пользователь вводит ключевые слова
    if context.user_data.get("awaiting_keywords"):
        keywords = [k.strip().lower() for k in text.split(",") if k.strip()]
        user_keywords[user_id] = keywords
        context.user_data["awaiting_keywords"] = False

        await update.message.reply_text(f"🔍 Ключевые слова сохранены: {', '.join(keywords)}\nМониторинг запущен.")
        asyncio.create_task(start_monitoring(user_id))
        return


# === Мониторинг сообщений ===
async def start_monitoring(user_id: int):
    data = user_sessions[user_id]
    client = data["client"]
    keywords = user_keywords.get(user_id, [])

    @client.on(events.NewMessage(incoming=True))
    async def handler(event):
        try:
            text = (event.message.message or "").lower()
            if any(k in text for k in keywords):
                chat = await event.get_chat()
                title = getattr(chat, "title", None) or getattr(chat, "username", None)
                await client.send_message(
                    "me",
                    f"🛰 Найдено совпадение!\nЧат: {title}\n\n{text[:1000]}"
                )
        except Exception:
            pass

    await client.run_until_disconnected()


# === Запуск ===
async def main():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("connect", connect))
    app.add_handler(CommandHandler("start", connect))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    print("✅ Бот запущен и готов к работе.")
    await app.run_polling()


if __name__ == "__main__":
    asyncio.run(main())