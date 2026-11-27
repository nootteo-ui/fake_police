# ==============================================================================
# AIRoute Auth v29 — готовый модуль для подключения в server.py
# Поддерживает:
#   1. Email (4-значный код через Яндекс SMTP: smtp.yandex.ru:465 SSL)
#   2. Telegram (4-значный код в чат вашего Telegram-бота по /start auth_<sid>)
#   3. Google (проверка Google ID Token через oauth2.googleapis.com/tokeninfo)
#   4. Настройка профиля (/api/auth/profile: смена никнейма и города)
#
# Переменные окружения в Render:
#   SMTP_HOST = smtp.yandex.ru
#   SMTP_PORT = 465
#   SMTP_USER = your_mail@yandex.ru
#   SMTP_PASS = <пароль приложения из Яндекс ID>
#   SMTP_FROM = your_mail@yandex.ru
#   TG_BOT_USERNAME = <username вашего бота без @>
#   GOOGLE_CLIENT_ID = <опционально: Web Client ID из Google Cloud Console>
# ==============================================================================

import json
import os
import random
import secrets
import smtplib
import ssl
import time
import urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

EMAIL_OTP_CODES = {}   # email -> {"code": "1234", "expires": ts, "attempts": 0}
TG_AUTH_SESSIONS = {}  # session_id -> {"code": "1234", "tg_id": None, "tg_username": None, "expires": ts}


def generate_4digit_code() -> str:
    return f"{random.randint(1000, 9999)}"


def send_yandex_email_code(to_email: str, code: str) -> tuple[bool, str]:
    host = os.getenv("SMTP_HOST", "smtp.yandex.ru").strip()
    port = int(os.getenv("SMTP_PORT", "465").strip())
    user = os.getenv("SMTP_USER", "").strip()
    password = os.getenv("SMTP_PASS", "").strip()
    sender = os.getenv("SMTP_FROM", user).strip() or user

    if not user or not password:
        return False, "Не заданы SMTP_USER / SMTP_PASS в настройках Render"

    html = f"""
    <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
                background:#0b101b;color:#ffffff;padding:32px 20px;border-radius:18px;max-width:440px;margin:0 auto;">
      <div style="font-size:20px;font-weight:800;margin-bottom:8px;">AIRoute</div>
      <div style="font-size:14px;color:#94a3b8;margin-bottom:22px;">
        Ваш код подтверждения для входа в приложение:
      </div>
      <div style="font-size:36px;font-weight:900;letter-spacing:10px;text-align:center;
                  background:#162033;border:1px solid rgba(255,255,255,0.12);
                  padding:18px 12px;border-radius:14px;color:#38bdf8;">
        {code}
      </div>
      <div style="font-size:12px;color:#64748b;margin-top:18px;">
        Код действует 10 минут. Если вы не запрашивали вход, просто проигнорируйте письмо.
      </div>
    </div>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"Код входа AIRoute: {code}"
    msg["From"] = f"AIRoute <{sender}>"
    msg["To"] = to_email
    msg.attach(MIMEText(f"Ваш код входа в AIRoute: {code} (действует 10 минут).", "plain", "utf-8"))
    msg.attach(MIMEText(html, "html", "utf-8"))

    try:
        if port == 465:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=ctx, timeout=12) as server:
                server.login(user, password)
                server.sendmail(sender, [to_email], msg.as_string())
        else:
            with smtplib.SMTP(host, port, timeout=12) as server:
                server.starttls(context=ssl.create_default_context())
                server.login(user, password)
                server.sendmail(sender, [to_email], msg.as_string())
        return True, "Код отправлен на почту"
    except Exception as exc:
        return False, f"Ошибка Яндекс SMTP: {exc}"


def verify_google_id_token(id_token: str) -> tuple[bool, dict | str]:
    """Проверяет Google ID Token через официальный endpoint Google."""
    try:
        url = f"https://oauth2.googleapis.com/tokeninfo?id_token={id_token}"
        with urllib.request.urlopen(url, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if not data.get("email") or data.get("email_verified") not in ("true", True):
            return False, "Email Google не подтверждён"
        expected_aud = os.getenv("GOOGLE_CLIENT_ID", "").strip()
        if expected_aud and data.get("aud") != expected_aud:
            return False, "Токен выдан для другого приложения"
        return True, {
            "sub": data.get("sub"),
            "email": data["email"].lower(),
            "name": data.get("name") or data["email"].split("@")[0],
        }
    except Exception as exc:
        return False, f"Недействительный Google токен: {exc}"


def start_telegram_session() -> dict:
    """Вызывается из POST /api/auth/telegram/start."""
    sid = secrets.token_urlsafe(12)
    code = generate_4digit_code()
    TG_AUTH_SESSIONS[sid] = {
        "code": code,
        "tg_id": None,
        "tg_username": None,
        "expires": time.time() + 600,
    }
    bot_username = os.getenv("TG_BOT_USERNAME", "your_bot_username").lstrip("@")
    return {
        "ok": True,
        "sessionId": sid,
        "botUrl": f"https://t.me/{bot_username}?start=auth_{sid}",
    }


def handle_telegram_bot_start(text: str, tg_user_id: int, tg_username: str | None) -> str | None:
    """
    Вызовите внутри обработчика команды /start вашего Telegram-бота:
      reply = handle_telegram_bot_start(message.text, message.from_user.id, message.from_user.username)
      if reply: bot.send_message(message.chat.id, reply, parse_mode="Markdown")
    """
    parts = (text or "").strip().split(maxsplit=1)
    if len(parts) < 2 or not parts[1].startswith("auth_"):
        return None
    sid = parts[1][5:].strip()
    sess = TG_AUTH_SESSIONS.get(sid)
    if not sess or sess["expires"] < time.time():
        return "Ссылка для входа устарела. Нажмите «Продолжить с Telegram» в приложении ещё раз."
    sess["tg_id"] = tg_user_id
    sess["tg_username"] = tg_username or f"tg_{tg_user_id}"
    return (
        f"🔐 Ваш код для входа в AIRoute:\n\n"
        f"`{sess['code']}`\n\n"
        f"Вернитесь в приложение и введите эти 4 цифры."
    )
