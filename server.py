#!/usr/bin/env python3
"""
Fake Police / AIRoute — сервер с синхронизацией меток, регистрацией/входом по Email с кодом,
песочницей «Новичка», автоматическим и ручным теневым баном (Shadowban),
удалением комментариев, журналом действий пользователей и ПК веб-админкой (/admin).
Только стандартный Python 3 + SQLite (без сторонних библиотек).
Запуск: python server.py
"""

import gzip
import hashlib
import hmac
import json
import math
import os
import random
import re
import secrets
import signal
import smtplib
import socket
import sqlite3
import ssl
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse
from urllib.request import Request, urlopen

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8000"))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "fake_police.db")).strip() or os.path.join(BASE_DIR, "fake_police.db")
INDEX_PATH = os.path.join(BASE_DIR, "index.html")
ADMIN_HTML_PATH = os.path.join(BASE_DIR, "admin.html")

# ================= НАСТРОЙКИ SMTP (ЯНДЕКС ПОЧТА / КОДЫ ПОДТВЕРЖДЕНИЯ) =================
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.yandex.ru").strip() or "smtp.yandex.ru"
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
SMTP_USER = os.environ.get("SMTP_USER", "").strip()
SMTP_PASS = os.environ.get("SMTP_PASS", "").strip()
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER or "noreply@airoute.app").strip()
BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "").strip()
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
# ======================================================================================

# ================= НАСТРОЙКИ ВНЕШНЕЙ СИНХРОНИЗАЦИИ И TELEGRAM =================
EXT_SYNC_ENABLED = True
EXT_API_BASE = "https://new-prod-api.easyroutes.ru/mobile_api/v2/posts"
EXT_API_URL = f"{EXT_API_BASE}/cached?key=0"
EXT_SYNC_INTERVAL = 25          # секунд между опросами списка точек
EXT_COMMENTS_MAX_PER_CYCLE = 15 # максимум запросов к /comments за один цикл (защита от бана)
EXT_COMMENTS_DELAY_SEC = 0.2    # пауза между запросами комментариев
EXT_PREFIX = "ext-er-"

TG_NOTIFY_ENABLED = True
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "ВСТАВЬ_СВОЙ_ТОКЕН_СЮДА").strip()
TG_CHAT_ID = os.environ.get("TG_CHAT_ID", "ВСТАВЬ_СВОЙ_CHAT_ID_СЮДА").strip()
TG_BOT_USERNAME = os.environ.get("TG_BOT_USERNAME", "").strip().lstrip("@")
TG_AUTH_POLLING = os.environ.get("TG_AUTH_POLLING", "1").strip().lower() not in ("0", "false", "no")
TG_AUTH_LOCK = threading.Lock()
TG_AUTH_SESSIONS = {}  # session_id -> {"code": "1234", "tg_id": None, "tg_username": None, "expires": ts}
# ==============================================================================

# Облачный автобэкап в приватный GitHub Gist
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()
BACKUP_GIST_ID = os.environ.get("BACKUP_GIST_ID", "").strip()
BACKUP_FILENAME = "fake_police_backup.json"
BACKUP_INTERVAL_SEC = max(60, int(os.environ.get("BACKUP_INTERVAL_SEC", "900")))  # раз в 15 минут
BACKUP_LOCK = threading.Lock()
BACKUP_DIRTY = False
BACKUP_LAST_AT = 0.0

# Кэш публичного ответа /api/markers в памяти (+ готовый gzip)
MARKERS_CACHE_LOCK = threading.Lock()
MARKERS_CACHE = None

ADMIN_USERNAME = os.environ.get("ADMIN_USER", "").strip()
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
DEFAULT_YANDEX_KEY = os.environ.get("YANDEX_API_KEY", "").strip()
SESSION_TTL_SEC = 30 * 24 * 3600  # 30 дней

DB_LOCK = threading.Lock()
RATE_LOCK = threading.Lock()
RATE_BUCKETS = defaultdict(deque)

# Кэш внешних комментариев в памяти: {raw_post_id: {"count": int, "comments": list}}
EXT_COMMENTS_CACHE = {}

# Онлайн-мониторинг активных клиентов приложения: {client_key: dict}
ONLINE_LOCK = threading.Lock()
ONLINE_CLIENTS = {}
ONLINE_TTL_MS = 65 * 1000  # 65 секунд с последнего запроса/пинга


def now_ms():
    return int(time.time() * 1000)


def db_connect():
    conn = sqlite3.connect(DB_PATH, timeout=15.0)
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def invalidate_markers_cache():
    global MARKERS_CACHE
    with MARKERS_CACHE_LOCK:
        MARKERS_CACHE = None


def hash_password(password, salt_hex=None):
    if not salt_hex:
        salt_hex = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 120_000)
    return salt_hex, dk.hex()


def verify_password(password, salt_hex, expected_hash):
    _, calc = hash_password(password, salt_hex)
    return hmac.compare_digest(calc, expected_hash)


def haversine_m(lat1, lng1, lat2, lng2):
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lng2 - lng1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return r * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def check_rate_limit(key, max_calls, window_sec):
    now = time.time()
    with RATE_LOCK:
        q = RATE_BUCKETS[key]
        while q and now - q[0] > window_sec:
            q.popleft()
        if len(q) >= max_calls:
            retry_after = max(1, int(window_sec - (now - q[0])))
            return False, retry_after
        q.append(now)
        return True, 0


def export_db_snapshot():
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        return {
            "users": conn.execute(
                """
                SELECT id, username, password_hash, salt, role, created_at, rating,
                       markers_count, votes_count, comments_count,
                       email, device_id, confirmed_markers, rejected_markers,
                       is_blocked, blocked_until, shadowbanned, shadowbanned_until, block_reason
                FROM users
                """
            ).fetchall(),
            "sessions": conn.execute(
                "SELECT token, user_id, expires_at, created_at FROM sessions"
            ).fetchall(),
            "markers": conn.execute(
                """
                SELECT id, type, lat, lng, address, created_at, last_confirmed_at,
                       confirmations, dismissals, comments_json, created_by,
                       status, shadowbanned, dismiss_weight, confirmed_by_senior
                FROM markers
                WHERE id NOT LIKE ?
                """,
                (f"{EXT_PREFIX}%",),
            ).fetchall(),
            "marker_votes": conn.execute(
                "SELECT marker_id, device_id, vote, created_at FROM marker_votes WHERE marker_id NOT LIKE ?",
                (f"{EXT_PREFIX}%",),
            ).fetchall(),
            "marker_comment_rewards": conn.execute(
                "SELECT marker_id, user_id, created_at FROM marker_comment_rewards"
            ).fetchall(),
            "settings": conn.execute(
                "SELECT key, value, updated_at FROM settings"
            ).fetchall(),
            "saved_at": now_ms(),
        }


def push_cloud_backup():
    if not (GITHUB_TOKEN and BACKUP_GIST_ID):
        return
    try:
        snapshot = export_db_snapshot()
        body = json.dumps(
            {"files": {BACKUP_FILENAME: {"content": json.dumps(snapshot, ensure_ascii=False)}}},
            ensure_ascii=False,
        ).encode("utf-8")
        req = Request(
            f"https://api.github.com/gists/{BACKUP_GIST_ID}",
            data=body,
            method="PATCH",
            headers={
                "Authorization": f"Bearer {GITHUB_TOKEN}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "FakePoliceServer/1.0",
                "Content-Type": "application/json",
            },
        )
        with urlopen(req, timeout=12) as resp:
            resp.read()
        print("[Fake Police] Облачный бэкап в GitHub Gist сохранён", flush=True)
    except Exception as exc:
        print(f"[Fake Police] Ошибка сохранения бэкапа в Gist: {exc}", flush=True)


def schedule_cloud_backup():
    global BACKUP_DIRTY
    if not (GITHUB_TOKEN and BACKUP_GIST_ID):
        return
    with BACKUP_LOCK:
        BACKUP_DIRTY = True


def flush_cloud_backup_if_dirty():
    global BACKUP_DIRTY, BACKUP_LAST_AT
    if not (GITHUB_TOKEN and BACKUP_GIST_ID):
        return
    with BACKUP_LOCK:
        if not BACKUP_DIRTY:
            return
        BACKUP_DIRTY = False
        BACKUP_LAST_AT = time.time()
    push_cloud_backup()


def start_cloud_backup_thread():
    if not (GITHUB_TOKEN and BACKUP_GIST_ID):
        return

    def worker():
        global BACKUP_DIRTY, BACKUP_LAST_AT
        print(f"[Fake Police] Плановый Gist-бэкап запущен (интервал: {BACKUP_INTERVAL_SEC} сек)", flush=True)
        while True:
            time.sleep(30)
            should_push = False
            with BACKUP_LOCK:
                if BACKUP_DIRTY and (time.time() - BACKUP_LAST_AT) >= BACKUP_INTERVAL_SEC:
                    BACKUP_DIRTY = False
                    BACKUP_LAST_AT = time.time()
                    should_push = True
            if should_push:
                push_cloud_backup()

    t = threading.Thread(target=worker, daemon=True)
    t.start()


def restore_cloud_backup():
    if not (GITHUB_TOKEN and BACKUP_GIST_ID):
        return
    try:
        req = Request(
            f"https://api.github.com/gists/{BACKUP_GIST_ID}",
            method="GET",
            headers={
                "Authorization": f"Bearer {GITHUB_TOKEN}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "FakePoliceServer/1.0",
            },
        )
        with urlopen(req, timeout=12) as resp:
            gist_data = json.loads(resp.read().decode("utf-8"))
        files = gist_data.get("files") or {}
        file_obj = files.get(BACKUP_FILENAME)
        if not file_obj or not file_obj.get("content"):
            print("[Fake Police] Облачный бэкап пока пуст — начинаем с чистой базы", flush=True)
            return
        snap = json.loads(file_obj["content"])
        with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
            for row in snap.get("users") or []:
                defaults = [0, "", "", 0, 0, 0, None, 0, None, ""]
                padded = list(row)
                while len(padded) < 19:
                    padded.append(defaults[len(padded) - 9])
                conn.execute(
                    """
                    INSERT OR IGNORE INTO users
                    (id, username, password_hash, salt, role, created_at, rating,
                     markers_count, votes_count, comments_count,
                     email, device_id, confirmed_markers, rejected_markers,
                     is_blocked, blocked_until, shadowbanned, shadowbanned_until, block_reason)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    padded[:19],
                )
            for row in snap.get("sessions") or []:
                conn.execute(
                    "INSERT OR IGNORE INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
                    row[:4],
                )
            for row in snap.get("markers") or []:
                m_defaults = [None, "active", 0, 0.0, 0]
                padded = list(row)
                while len(padded) < 15:
                    padded.append(m_defaults[len(padded) - 10])
                conn.execute(
                    """
                    INSERT OR IGNORE INTO markers
                    (id, type, lat, lng, address, created_at, last_confirmed_at,
                     confirmations, dismissals, comments_json, created_by,
                     status, shadowbanned, dismiss_weight, confirmed_by_senior)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    padded[:15],
                )
            for row in snap.get("marker_votes") or []:
                conn.execute(
                    "INSERT OR IGNORE INTO marker_votes (marker_id, device_id, vote, created_at) VALUES (?, ?, ?, ?)",
                    row[:4],
                )
            for row in snap.get("marker_comment_rewards") or []:
                conn.execute(
                    "INSERT OR IGNORE INTO marker_comment_rewards (marker_id, user_id, created_at) VALUES (?, ?, ?)",
                    row[:3],
                )
            for row in snap.get("settings") or []:
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
                    row[:3],
                )
            conn.commit()
        invalidate_markers_cache()
        print(
            f"[Fake Police] База восстановлена из GitHub Gist (пользователей: {len(snap.get('users') or [])}, меток: {len(snap.get('markers') or [])})",
            flush=True,
        )
    except Exception as exc:
        print(f"[Fake Police] Не удалось восстановить бэкап из Gist: {exc}", flush=True)


def init_db():
    db_dir = os.path.dirname(os.path.abspath(DB_PATH))
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    with db_connect() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS markers (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                lat REAL NOT NULL,
                lng REAL NOT NULL,
                address TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_confirmed_at INTEGER NOT NULL,
                confirmations INTEGER NOT NULL DEFAULT 0,
                dismissals INTEGER NOT NULL DEFAULT 0,
                comments_json TEXT NOT NULL DEFAULT '[]',
                created_by INTEGER DEFAULT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                shadowbanned INTEGER NOT NULL DEFAULT 0,
                dismiss_weight REAL NOT NULL DEFAULT 0.0,
                confirmed_by_senior INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        for m_col in (
            "created_by INTEGER DEFAULT NULL",
            "status TEXT NOT NULL DEFAULT 'active'",
            "shadowbanned INTEGER NOT NULL DEFAULT 0",
            "dismiss_weight REAL NOT NULL DEFAULT 0.0",
            "confirmed_by_senior INTEGER NOT NULL DEFAULT 0",
        ):
            try:
                conn.execute(f"ALTER TABLE markers ADD COLUMN {m_col}")
            except sqlite3.OperationalError:
                pass

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS marker_votes (
                marker_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                vote TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (marker_id, device_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS marker_comment_rewards (
                marker_id TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (marker_id, user_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ext_notified (
                ext_id TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ext_overrides (
                marker_id TEXT PRIMARY KEY,
                deleted INTEGER NOT NULL DEFAULT 0,
                type_override TEXT DEFAULT NULL,
                lat_override REAL DEFAULT NULL,
                lng_override REAL DEFAULT NULL,
                address_override TEXT DEFAULT NULL,
                desc_override TEXT DEFAULT NULL,
                conf_override INTEGER DEFAULT NULL,
                admin_conf_delta INTEGER NOT NULL DEFAULT 0,
                admin_dism_delta INTEGER NOT NULL DEFAULT 0,
                local_last_confirmed_at INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ext_deleted_comments (
                marker_id TEXT NOT NULL,
                author TEXT NOT NULL,
                text TEXT NOT NULL,
                ts INTEGER NOT NULL,
                PRIMARY KEY (marker_id, author, text, ts)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_at INTEGER NOT NULL,
                rating INTEGER NOT NULL DEFAULT 0,
                markers_count INTEGER NOT NULL DEFAULT 0,
                votes_count INTEGER NOT NULL DEFAULT 0,
                comments_count INTEGER NOT NULL DEFAULT 0,
                email TEXT NOT NULL DEFAULT '',
                device_id TEXT NOT NULL DEFAULT '',
                confirmed_markers INTEGER NOT NULL DEFAULT 0,
                rejected_markers INTEGER NOT NULL DEFAULT 0,
                is_blocked INTEGER NOT NULL DEFAULT 0,
                blocked_until INTEGER DEFAULT NULL,
                shadowbanned INTEGER NOT NULL DEFAULT 0,
                shadowbanned_until INTEGER DEFAULT NULL,
                block_reason TEXT NOT NULL DEFAULT ''
            )
            """
        )
        for col_def in (
            "rating INTEGER NOT NULL DEFAULT 0",
            "markers_count INTEGER NOT NULL DEFAULT 0",
            "votes_count INTEGER NOT NULL DEFAULT 0",
            "comments_count INTEGER NOT NULL DEFAULT 0",
            "email TEXT NOT NULL DEFAULT ''",
            "device_id TEXT NOT NULL DEFAULT ''",
            "confirmed_markers INTEGER NOT NULL DEFAULT 0",
            "rejected_markers INTEGER NOT NULL DEFAULT 0",
            "is_blocked INTEGER NOT NULL DEFAULT 0",
            "blocked_until INTEGER DEFAULT NULL",
            "shadowbanned INTEGER NOT NULL DEFAULT 0",
            "shadowbanned_until INTEGER DEFAULT NULL",
            "block_reason TEXT NOT NULL DEFAULT ''",
            "city TEXT NOT NULL DEFAULT ''",
            "avatar_index INTEGER NOT NULL DEFAULT 0",
            "tg_id TEXT NOT NULL DEFAULT ''",
            "google_sub TEXT NOT NULL DEFAULT ''",
        ):
            try:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col_def}")
            except sqlite3.OperationalError:
                pass

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS email_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                purpose TEXT NOT NULL,
                code TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS user_actions (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                action_type TEXT NOT NULL,
                title TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '',
                lat REAL DEFAULT NULL,
                lng REAL DEFAULT NULL,
                ts INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_marker_votes_device ON marker_votes(device_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_markers_status_sb ON markers(status, shadowbanned)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_markers_created_by ON markers(created_by)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)")
        if DEFAULT_YANDEX_KEY:
            existing_key = conn.execute("SELECT value FROM settings WHERE key = 'yandex_api_key'").fetchone()
            if not existing_key:
                conn.execute(
                    "INSERT INTO settings (key, value, updated_at) VALUES ('yandex_api_key', ?, ?)",
                    (DEFAULT_YANDEX_KEY, now_ms()),
                )
        conn.commit()
    restore_cloud_backup()
    with sqlite3.connect(DB_PATH) as conn:
        if ADMIN_USERNAME and ADMIN_PASSWORD:
            conn.execute("DELETE FROM users WHERE role = 'admin' AND username != ?", (ADMIN_USERNAME,))
            salt, pwd_hash = hash_password(ADMIN_PASSWORD)
            row = conn.execute("SELECT id FROM users WHERE username = ?", (ADMIN_USERNAME,)).fetchone()
            if not row:
                conn.execute(
                    "INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, 'admin', ?)",
                    (ADMIN_USERNAME, pwd_hash, salt, now_ms()),
                )
            else:
                conn.execute(
                    "UPDATE users SET password_hash = ?, salt = ?, role = 'admin' WHERE id = ?",
                    (pwd_hash, salt, row[0]),
                )
        conn.commit()


# ================= ЖУРНАЛ ДЕЙСТВИЙ, ПЕСОЧНИЦА НОВИЧКА И SHADOWBAN =================

def log_user_action(conn, user_id, action_type, title, details="", lat=None, lng=None):
    if user_id is None:
        return
    conn.execute(
        """
        INSERT INTO user_actions (id, user_id, action_type, title, details, lat, lng, ts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (f"act-{now_ms()}-{secrets.token_hex(3)}", int(user_id), action_type, title, str(details or "")[:300], lat, lng, now_ms()),
    )


def record_online_client(user=None, device_id="", ip="", platform="", city=""):
    dev = str(device_id or "").strip()[:80]
    if user:
        key = f"user:{user['id']}"
    elif dev:
        key = f"dev:{dev}"
    else:
        key = f"ip:{ip}"
    cur_now = now_ms()
    with ONLINE_LOCK:
        prev = ONLINE_CLIENTS.get(key) or {}
        ONLINE_CLIENTS[key] = {
            "key": key,
            "userId": user["id"] if user else None,
            "username": user["username"] if user else "Гость",
            "role": user["role"] if user else "guest",
            "isAdmin": bool(user and user.get("role") == "admin"),
            "deviceId": dev or prev.get("deviceId", ""),
            "platform": str(platform or prev.get("platform", "")).strip()[:24],
            "city": str(city or prev.get("city", "")).strip()[:60],
            "ip": str(ip or ""),
            "lastSeen": cur_now,
            "firstSeen": prev.get("firstSeen", cur_now),
        }


def get_online_clients_snapshot():
    cur_now = now_ms()
    active = []
    with ONLINE_LOCK:
        stale_keys = [k for k, v in ONLINE_CLIENTS.items() if (cur_now - int(v.get("lastSeen") or 0)) > ONLINE_TTL_MS]
        for k in stale_keys:
            ONLINE_CLIENTS.pop(k, None)
        for v in ONLINE_CLIENTS.values():
            item = dict(v)
            item["agoSec"] = max(0, int((cur_now - int(v["lastSeen"])) / 1000))
            active.append(item)
    active.sort(key=lambda x: (-int(x["userId"] is not None), x["agoSec"]))
    auth_cnt = sum(1 for x in active if x["userId"] is not None)
    return {
        "onlineCount": len(active),
        "authenticatedCount": auth_cnt,
        "guestCount": len(active) - auth_cnt,
        "clients": active,
    }


def _send_via_brevo(to_email, subject, plain_body, html_body):
    payload = json.dumps({
        "sender": {"name": "AIRoute", "email": SMTP_FROM},
        "to": [{"email": to_email}],
        "subject": subject,
        "textContent": plain_body,
        "htmlContent": html_body,
    }, ensure_ascii=False).encode("utf-8")
    req = Request(
        "https://api.brevo.com/v3/smtp/email",
        data=payload,
        method="POST",
        headers={
            "accept": "application/json",
            "api-key": BREVO_API_KEY,
            "content-type": "application/json",
            "User-Agent": "AIRouteServer/1.0",
        },
    )
    with urlopen(req, timeout=10) as resp:
        resp.read()
    return True


def _resolve_ipv4(host, port):
    infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    if not infos:
        return host
    return infos[0][4][0]


def send_code_email(to_email, code, purpose="auth"):
    subject = f"Код входа AIRoute: {code}"
    action_label = "регистрации" if purpose == "register" else "входа"
    plain_body = (
        f"Ваш код подтверждения для {action_label} в AIRoute: {code}\n"
        f"Код действует 10 минут. Никому не сообщайте его."
    )
    html_body = f"""
    <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
                background:#0b101b;color:#ffffff;padding:32px 20px;border-radius:18px;max-width:440px;margin:0 auto;">
      <div style="font-size:20px;font-weight:800;margin-bottom:8px;">AIRoute</div>
      <div style="font-size:14px;color:#94a3b8;margin-bottom:22px;">
        Ваш код подтверждения для {action_label} в приложение:
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

    # 1. Приоритет: Brevo HTTP API (порт 443 — никогда не блокируется на Render)
    if BREVO_API_KEY:
        return _send_via_brevo(to_email, subject, plain_body, html_body)

    if not (SMTP_HOST and SMTP_USER and SMTP_PASS):
        print(f"[AIRoute DEV EMAIL -> {to_email}] {subject}: {code}", flush=True)
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"AIRoute <{SMTP_FROM}>"
    msg["To"] = to_email
    msg.attach(MIMEText(plain_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    # 2. SMTP с принудительным IPv4 (убирает [Errno 101] Network is unreachable по IPv6 на Render)
    ipv4_host = _resolve_ipv4(SMTP_HOST, SMTP_PORT)
    ctx = ssl.create_default_context()
    if SMTP_PORT == 465:
        with smtplib.SMTP_SSL(timeout=10, context=ctx) as server:
            server._host = SMTP_HOST
            server.connect(ipv4_host, SMTP_PORT)
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, [to_email], msg.as_string())
    else:
        with smtplib.SMTP(timeout=10) as server:
            server.connect(ipv4_host, SMTP_PORT)
            server.ehlo()
            server.starttls(context=ctx)
            server.ehlo()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, [to_email], msg.as_string())
    return True


def is_user_blocked_row(is_blocked, blocked_until):
    now = now_ms()
    if blocked_until is not None and int(blocked_until) > 0:
        return int(blocked_until) > now
    return bool(is_blocked)


def is_user_shadowbanned_row(shadowbanned, shadowbanned_until):
    now = now_ms()
    if shadowbanned_until is not None and int(shadowbanned_until) > 0:
        return int(shadowbanned_until) > now
    return bool(shadowbanned)


def evaluate_auto_shadowban(conn, user_id):
    """Автоматический временный теневой бан на 24ч при доле отклонённых меток > 80% или рейтинге < 0."""
    if user_id is None:
        return False
    row = conn.execute(
        """
        SELECT role, rating, confirmed_markers, rejected_markers, shadowbanned, shadowbanned_until
        FROM users WHERE id = ?
        """,
        (int(user_id),),
    ).fetchone()
    if not row or row[0] == "admin":
        return False

    rating = int(row[1] or 0)
    conf = int(row[2] or 0)
    rej = int(row[3] or 0)
    total = conf + rej

    bad_ratio = total >= 3 and (rej / total) > 0.80
    neg_rating = rating < 0

    if bad_ratio or neg_rating:
        if not is_user_shadowbanned_row(row[4], row[5]):
            until = now_ms() + 24 * 3600 * 1000
            conn.execute(
                "UPDATE users SET shadowbanned = 1, shadowbanned_until = ? WHERE id = ?",
                (until, int(user_id)),
            )
            reason = "рейтинг ушёл в минус" if neg_rating else f"отклонено {rej} из {total} меток (> 80%)"
            log_user_action(conn, user_id, "moderation", "Автоматический теневой бан (24 ч)", reason)
        return True
    return False


# ================= ВНЕШНЯЯ РЕТРАНСЛЯЦИЯ ТОЧЕК, КОММЕНТАРИЕВ И TELEGRAM =================

def parse_iso_ms(val, fallback_ms):
    if not val:
        return fallback_ms
    try:
        dt = datetime.fromisoformat(str(val).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except Exception:
        return fallback_ms


def build_ext_summary_text(item, include_policemen=False):
    parts = []
    if include_policemen:
        policemen = item.get("policemen_count")
        if policemen:
            parts.append(f"👮 Экипажей: {policemen}")
    if item.get("is_police_raid"):
        parts.append("🚨 Рейд")
    if item.get("is_motobat"):
        parts.append("🏍 Мотобат")
    if item.get("is_truck_point"):
        parts.append("🚛 Грузовой пост")
    if item.get("is_constant"):
        parts.append("📌 Постоянный пост")
    return " | ".join(parts)


def fetch_ext_json(url, timeout=15):
    req = Request(
        url,
        method="GET",
        headers={
            "User-Agent": "okhttp/4.12.0",
            "Authorization": "Bearer",
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
        },
    )
    with urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        if resp.headers.get("Content-Encoding", "").lower() == "gzip":
            raw = gzip.decompress(raw)
        return json.loads(raw.decode("utf-8"))


def fetch_external_points():
    return fetch_ext_json(EXT_API_URL, timeout=15)


def fetch_external_comments(raw_post_id, cur_now_ms):
    url = f"{EXT_API_BASE}/{raw_post_id}/comments"
    data = fetch_ext_json(url, timeout=10)
    if not isinstance(data, list):
        return []
    parsed = []
    for c in data:
        if not isinstance(c, dict):
            continue
        if c.get("is_visible") is False or c.get("is_rejected") is True or c.get("is_on_moderation") is True:
            continue
        text = str(c.get("text") or "").strip()[:400]
        if not text:
            continue
        author_obj = c.get("author") if isinstance(c.get("author"), dict) else {}
        author_name = str(author_obj.get("full_name") or "Пользователь").strip()[:40] or "Пользователь"
        if author_name.lower() == "безымянный райдер":
            author_name = "Пользователь"
        ts = parse_iso_ms(c.get("created_at"), cur_now_ms)
        parsed.append({
            "author": author_name,
            "text": text,
            "ts": ts,
            "source": "ext",
            "extId": c.get("id"),
        })
    parsed.sort(key=lambda x: x["ts"])
    return parsed


def send_telegram_alert(item, ext_comments=None):
    if not (TG_NOTIFY_ENABLED and TG_BOT_TOKEN and TG_CHAT_ID):
        return
    if "ВСТАВЬ_СВОЙ" in TG_BOT_TOKEN or "ВСТАВЬ_СВОЙ" in TG_CHAT_ID:
        return
    lat = item["lat"]
    lon = item["lon"]
    address = item.get("address") or "Адрес не указан"
    summary = build_ext_summary_text(item, include_policemen=True)
    approves = item.get("approve_marks_count", 0)
    declines = item.get("decline_marks_count", 0)

    yandex_url = f"https://yandex.ru/maps/?pt={lon},{lat}&z=16&l=map"
    google_url = f"https://maps.google.com/?q={lat},{lon}"

    lines = [
        f"📍 <b>Новая точка</b> (ID: <code>{item['id']}</code>)",
        f"🗺 {address}",
        f"Координаты: <code>{lat}, {lon}</code>",
    ]
    if summary:
        lines.append(summary)
    if ext_comments:
        lines.append(f"💬 {ext_comments[0]['text']}")
    lines.append(f"👍 {approves} / 👎 {declines}")
    lines.append("")
    lines.append(f"<a href='{yandex_url}'>Яндекс Карты</a> | <a href='{google_url}'>Google Maps</a>")

    payload = json.dumps({
        "chat_id": TG_CHAT_ID,
        "text": "\n".join(lines),
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }, ensure_ascii=False).encode("utf-8")

    try:
        req = Request(
            f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urlopen(req, timeout=10) as resp:
            resp.read()
    except Exception as exc:
        print(f"[Fake Police] Ошибка отправки в Telegram: {exc}", flush=True)


def sync_external_once():
    try:
        data = fetch_external_points()
    except Exception as exc:
        print(f"[Fake Police] Ошибка внешнего API: {exc}", flush=True)
        return

    if not isinstance(data, dict):
        return
    items = data.get("updated") or []
    if not items:
        return

    cur_now = now_ms()
    active_ids = []
    active_raw_ids = set()
    to_notify = []

    fetched_comments_count = 0
    for item in items:
        raw_id = item.get("id")
        if raw_id is None:
            continue
        active_raw_ids.add(raw_id)
        c_count = int(item.get("comments_count") or 0)
        if c_count <= 0:
            EXT_COMMENTS_CACHE[raw_id] = {"count": 0, "comments": []}
            continue

        cached = EXT_COMMENTS_CACHE.get(raw_id)
        if cached and cached["count"] == c_count:
            continue

        if fetched_comments_count >= EXT_COMMENTS_MAX_PER_CYCLE:
            continue

        try:
            ext_cmts = fetch_external_comments(raw_id, cur_now)
            EXT_COMMENTS_CACHE[raw_id] = {"count": c_count, "comments": ext_cmts}
            fetched_comments_count += 1
            time.sleep(EXT_COMMENTS_DELAY_SEC)
        except Exception as exc:
            print(f"[Fake Police] Ошибка загрузки комментариев для поста {raw_id}: {exc}", flush=True)

    for old_id in list(EXT_COMMENTS_CACHE.keys()):
        if old_id not in active_raw_ids:
            EXT_COMMENTS_CACHE.pop(old_id, None)

    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        first_run = conn.execute("SELECT COUNT(*) FROM ext_notified").fetchone()[0] == 0

        deleted_cmts = set()
        for dc in conn.execute("SELECT marker_id, author, text, ts FROM ext_deleted_comments").fetchall():
            deleted_cmts.add((str(dc[0]), str(dc[1]), str(dc[2]), int(dc[3])))

        overrides_map = {}
        for ov in conn.execute(
            """
            SELECT marker_id, deleted, type_override, lat_override, lng_override,
                   address_override, desc_override, conf_override,
                   admin_conf_delta, admin_dism_delta, local_last_confirmed_at
            FROM ext_overrides
            """
        ).fetchall():
            overrides_map[ov[0]] = {
                "deleted": int(ov[1] or 0),
                "type_override": ov[2],
                "lat_override": ov[3],
                "lng_override": ov[4],
                "address_override": ov[5],
                "desc_override": ov[6],
                "conf_override": ov[7],
                "admin_conf_delta": int(ov[8] or 0),
                "admin_dism_delta": int(ov[9] or 0),
                "local_last_confirmed_at": int(ov[10] or 0),
            }

        for item in items:
            raw_id = item.get("id")
            lat = item.get("lat")
            lon = item.get("lon")
            if raw_id is None or lat is None or lon is None:
                continue

            marker_id = f"{EXT_PREFIX}{raw_id}"
            active_ids.append(marker_id)

            ov = overrides_map.get(marker_id)
            if ov and ov["deleted"]:
                continue

            m_type = ov["type_override"] if (ov and ov["type_override"]) else "dps"
            lat_f = float(ov["lat_override"]) if (ov and ov["lat_override"] is not None) else float(lat)
            lng_f = float(ov["lng_override"]) if (ov and ov["lng_override"] is not None) else float(lon)
            address = (
                ov["address_override"]
                if (ov and ov["address_override"])
                else str(item.get("address") or f"{lat_f:.4f}, {lng_f:.4f}")[:240]
            )

            created_at = parse_iso_ms(item.get("created_at"), cur_now)
            last_confirmed = parse_iso_ms(
                item.get("last_approved_at") or item.get("updated_at") or item.get("created_at"),
                created_at,
            )
            if ov and ov["local_last_confirmed_at"] > last_confirmed:
                last_confirmed = ov["local_last_confirmed_at"]

            ext_approves = max(0, int(item.get("approve_marks_count") or 0))
            ext_declines = max(0, int(item.get("decline_marks_count") or 0))

            local_conf = 0
            local_dism = 0
            for v_type, cnt in conn.execute(
                "SELECT vote, COUNT(*) FROM marker_votes WHERE marker_id = ? GROUP BY vote",
                (marker_id,),
            ).fetchall():
                if v_type == "confirm":
                    local_conf = cnt
                elif v_type == "dismiss":
                    local_dism = cnt

            admin_conf = ov["admin_conf_delta"] if ov else 0
            admin_dism = ov["admin_dism_delta"] if ov else 0

            if ov and ov["conf_override"] is not None:
                total_conf = max(0, int(ov["conf_override"]) + local_conf + admin_conf)
            else:
                total_conf = max(0, ext_approves + local_conf + admin_conf)
            total_dism = max(0, ext_declines + local_dism + admin_dism)

            existing_row = conn.execute(
                "SELECT comments_json FROM markers WHERE id = ?",
                (marker_id,),
            ).fetchone()
            local_comments = []
            prev_ext_comments = []
            if existing_row:
                try:
                    prev_all = json.loads(existing_row[0] or "[]")
                    if isinstance(prev_all, list):
                        for c in prev_all:
                            if c.get("author") == "Сводка" or c.get("source") == "admin_desc":
                                continue
                            if c.get("source") == "ext":
                                prev_ext_comments.append(c)
                            else:
                                local_comments.append(c)
                except Exception:
                    pass

            cached_entry = EXT_COMMENTS_CACHE.get(raw_id)
            raw_ext_comments = cached_entry["comments"] if cached_entry is not None else prev_ext_comments
            ext_comments = [
                c for c in raw_ext_comments
                if (marker_id, str(c.get("author", "")), str(c.get("text", "")), int(c.get("ts") or 0)) not in deleted_cmts
            ]

            comments = []
            if ov and ov["desc_override"] is not None:
                if ov["desc_override"]:
                    comments.append({"author": "Админ", "text": ov["desc_override"], "ts": last_confirmed, "source": "admin_desc"})
            else:
                summary_text = build_ext_summary_text(item, include_policemen=False)
                if summary_text:
                    comments.append({"author": "Сводка", "text": summary_text, "ts": last_confirmed})

            merged_user_comments = ext_comments + local_comments
            merged_user_comments.sort(key=lambda x: int(x.get("ts") or 0))
            comments.extend(merged_user_comments)
            comments_json = json.dumps(comments[:50], ensure_ascii=False)

            conn.execute(
                """
                INSERT INTO markers
                (id, type, lat, lng, address, created_at, last_confirmed_at, confirmations, dismissals, comments_json, created_by, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 'active')
                ON CONFLICT(id) DO UPDATE SET
                    type = excluded.type,
                    lat = excluded.lat,
                    lng = excluded.lng,
                    address = excluded.address,
                    last_confirmed_at = excluded.last_confirmed_at,
                    confirmations = excluded.confirmations,
                    dismissals = excluded.dismissals,
                    comments_json = excluded.comments_json
                """,
                (marker_id, m_type, lat_f, lng_f, address, created_at, last_confirmed, total_conf, total_dism, comments_json),
            )

            seen = conn.execute("SELECT 1 FROM ext_notified WHERE ext_id = ?", (marker_id,)).fetchone()
            if not seen:
                conn.execute(
                    "INSERT OR IGNORE INTO ext_notified (ext_id, created_at) VALUES (?, ?)",
                    (marker_id, cur_now),
                )
                if not first_run:
                    to_notify.append((item, ext_comments))

        if active_ids:
            placeholders = ",".join("?" for _ in active_ids)
            conn.execute(
                f"DELETE FROM markers WHERE id LIKE ? AND id NOT IN ({placeholders})",
                [f"{EXT_PREFIX}%"] + active_ids,
            )
            conn.execute(
                f"DELETE FROM marker_votes WHERE marker_id LIKE ? AND marker_id NOT IN ({placeholders})",
                [f"{EXT_PREFIX}%"] + active_ids,
            )
            conn.execute(
                f"DELETE FROM ext_overrides WHERE marker_id LIKE ? AND marker_id NOT IN ({placeholders})",
                [f"{EXT_PREFIX}%"] + active_ids,
            )
            conn.execute(
                f"DELETE FROM ext_deleted_comments WHERE marker_id LIKE ? AND marker_id NOT IN ({placeholders})",
                [f"{EXT_PREFIX}%"] + active_ids,
            )
        conn.commit()
    invalidate_markers_cache()

    if first_run:
        print(
            f"[Fake Police] Первичная синхронизация: загружено {len(active_ids)} внешних точек (комментарии подгружены для {fetched_comments_count})",
            flush=True,
        )
    elif to_notify:
        print(f"[Fake Police] Новых внешних точек: {len(to_notify)} (всего активных: {len(active_ids)})", flush=True)
        for item, ext_cmts in to_notify:
            send_telegram_alert(item, ext_cmts)
            time.sleep(0.35)


def start_external_sync_thread():
    if not EXT_SYNC_ENABLED:
        return

    def worker():
        print(f"[Fake Police] Фоновая ретрансляция точек и комментариев запущена (интервал: {EXT_SYNC_INTERVAL} сек)", flush=True)
        while True:
            sync_external_once()
            time.sleep(EXT_SYNC_INTERVAL)

    t = threading.Thread(target=worker, daemon=True)
    t.start()

# =========================================================================


def get_setting(key, default=""):
    with db_connect() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row[0] if row else default


def set_setting(key, value):
    now = now_ms()
    with DB_LOCK, db_connect() as conn:
        conn.execute(
            """
            INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (key, str(value or ""), now),
        )
        conn.commit()
    invalidate_markers_cache()
    schedule_cloud_backup()


def create_session(user_id):
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
            (token, user_id, now + SESSION_TTL_SEC, now),
        )
        conn.commit()
    schedule_cloud_backup()
    return token


def format_user_dict(
    uid,
    username,
    role,
    rating=0,
    markers_count=0,
    votes_count=0,
    comments_count=0,
    email="",
    created_at=0,
    confirmed_markers=0,
    rejected_markers=0,
    is_blocked=0,
    blocked_until=None,
    shadowbanned=0,
    shadowbanned_until=None,
    block_reason="",
):
    blocked_active = is_user_blocked_row(is_blocked, blocked_until)
    shadow_active = is_user_shadowbanned_row(shadowbanned, shadowbanned_until)
    return {
        "id": uid,
        "username": username,
        "role": role,
        "isAdmin": role == "admin",
        "email": str(email or ""),
        "createdAt": int(created_at or 0),
        "rating": int(rating or 0),
        "markersCount": int(markers_count or 0),
        "confirmedMarkers": int(confirmed_markers or 0),
        "rejectedMarkers": int(rejected_markers or 0),
        "votesCount": int(votes_count or 0),
        "commentsCount": int(comments_count or 0),
        "isBlocked": blocked_active,
        "blockedUntil": blocked_until if blocked_active else None,
        "blockReason": str(block_reason or "") if blocked_active else "",
        "shadowbanned": shadow_active,
        "shadowbannedUntil": shadowbanned_until if shadow_active else None,
    }


def award_user_rating(conn, user_id, points=0, markers_delta=0, votes_delta=0, comments_delta=0):
    if user_id is None:
        return
    conn.execute(
        """
        UPDATE users
        SET rating = rating + ?,
            markers_count = MAX(0, markers_count + ?),
            votes_count = MAX(0, votes_count + ?),
            comments_count = MAX(0, comments_count + ?)
        WHERE id = ?
        """,
        (int(points), int(markers_delta), int(votes_delta), int(comments_delta), int(user_id)),
    )
    if int(points) < 0:
        evaluate_auto_shadowban(conn, user_id)


def get_user_by_token(token):
    if not token:
        return None
    now = int(time.time())
    with db_connect() as conn:
        row = conn.execute(
            """
            SELECT u.id, u.username, u.role, s.expires_at,
                   u.rating, u.markers_count, u.votes_count, u.comments_count,
                   u.email, u.created_at, u.confirmed_markers, u.rejected_markers,
                   u.is_blocked, u.blocked_until, u.shadowbanned, u.shadowbanned_until,
                   u.block_reason
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token = ?
            """,
            (token,),
        ).fetchone()
    if not row:
        return None
    if row[3] < now:
        with DB_LOCK, db_connect() as conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
        return None
    return format_user_dict(
        row[0], row[1], row[2], row[4], row[5], row[6], row[7],
        email=row[8], created_at=row[9], confirmed_markers=row[10], rejected_markers=row[11],
        is_blocked=row[12], blocked_until=row[13], shadowbanned=row[14], shadowbanned_until=row[15],
        block_reason=row[16],
    )


def _generate_unique_username(conn, base_name=""):
    clean = re.sub(r"[^A-Za-zА-Яа-яЁё0-9 _.-]", "", str(base_name or "")).strip()
    if len(clean) < 2:
        clean = f"Водитель {random.randint(1000, 9999)}"
    clean = clean[:24].strip()
    candidate = clean
    for _ in range(25):
        exists = conn.execute("SELECT 1 FROM users WHERE lower(username) = lower(?)", (candidate,)).fetchone()
        if not exists:
            return candidate
        suffix = str(random.randint(100, 9999))
        candidate = f"{clean[:19].strip()}_{suffix}"
    return f"user_{secrets.token_hex(4)}"


def _fetch_user_dict_by_id(conn, user_id):
    row = conn.execute(
        """
        SELECT id, username, role, rating, markers_count, votes_count, comments_count,
               email, created_at, confirmed_markers, rejected_markers,
               is_blocked, blocked_until, shadowbanned, shadowbanned_until, block_reason,
               city, avatar_index
        FROM users WHERE id = ?
        """,
        (int(user_id),),
    ).fetchone()
    if not row:
        return None
    u = format_user_dict(
        row[0], row[1], row[2], row[3], row[4], row[5], row[6],
        email=row[7], created_at=row[8], confirmed_markers=row[9], rejected_markers=row[10],
        is_blocked=row[11], blocked_until=row[12], shadowbanned=row[13], shadowbanned_until=row[14],
        block_reason=row[15],
    )
    u["city"] = str(row[16] or "")
    u["avatarIndex"] = int(row[17] or 0)
    return u


def send_email_verification_code(email, purpose="auth", username=None):
    email = str(email or "").strip().lower()
    purpose = str(purpose or "auth").strip().lower()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return {"ok": False, "error": "Укажите корректный адрес электронной почты"}

    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        existing = conn.execute("SELECT id FROM users WHERE lower(email) = ?", (email,)).fetchone()
        if purpose == "register" and existing:
            return {"ok": False, "error": "Эта почта уже зарегистрирована"}
        if purpose == "login" and not existing:
            return {"ok": False, "error": "Аккаунт с такой почтой не найден"}

        # Новый единый поток v29 (purpose == 'auth') использует 4-значный код
        code = f"{random.randint(1000, 9999)}" if purpose == "auth" else f"{random.randint(100000, 999999)}"
        conn.execute(
            "INSERT INTO email_codes (email, purpose, code, expires_at, used) VALUES (?, ?, ?, ?, 0)",
            (email, purpose, code, now_ms() + 10 * 60 * 1000),
        )
        conn.commit()

    sent_smtp = False
    try:
        sent_smtp = send_code_email(email, code, purpose)
    except Exception as exc:
        print(f"[Fake Police] Ошибка SMTP при отправке кода на {email}: {exc}", flush=True)
        return {"ok": False, "error": "Не удалось отправить письмо. Проверьте SMTP_USER / SMTP_PASS Яндекса на Render."}

    if sent_smtp:
        return {"ok": True, "message": f"Код подтверждения отправлен на {email}"}
    return {"ok": True, "message": f"SMTP не настроен (тест-код: {code})"}


def verify_email_auth_code(email, code, device_id=""):
    email = str(email or "").strip().lower()
    code = str(code or "").strip()
    device_id = str(device_id or "").strip()[:80]
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return {"ok": False, "error": "Некорректный email"}
    if not re.match(r"^\d{4,6}$", code):
        return {"ok": False, "error": "Введите 4-значный код из письма"}

    cur_now = now_ms()
    is_new_user = False
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        code_row = conn.execute(
            """
            SELECT id, code, expires_at FROM email_codes
            WHERE lower(email) = ? AND used = 0
            ORDER BY id DESC LIMIT 1
            """,
            (email,),
        ).fetchone()
        if not code_row or str(code_row[1]) != code:
            return {"ok": False, "error": "Неверный код подтверждения"}
        if int(code_row[2]) < cur_now:
            return {"ok": False, "error": "Срок действия кода истёк. Запросите новый код."}

        conn.execute("UPDATE email_codes SET used = 1 WHERE id = ?", (code_row[0],))

        existing = conn.execute("SELECT id FROM users WHERE lower(email) = ?", (email,)).fetchone()
        if existing:
            user_id = existing[0]
            log_user_action(conn, user_id, "auth", "Вход по коду с почты", email)
        else:
            is_new_user = True
            uname = _generate_unique_username(conn, email.split("@")[0])
            salt, pwd_hash = hash_password(secrets.token_urlsafe(24))
            cur = conn.execute(
                """
                INSERT INTO users (username, password_hash, salt, role, created_at, email, device_id)
                VALUES (?, ?, ?, 'user', ?, ?, ?)
                """,
                (uname, pwd_hash, salt, cur_now, email, device_id),
            )
            user_id = cur.lastrowid
            log_user_action(conn, user_id, "auth", "Регистрация по Email (4-значный код)", email)

        user_dict = _fetch_user_dict_by_id(conn, user_id)
        conn.commit()

    token = create_session(user_id)
    return {"ok": True, "token": token, "user": user_dict, "isNewUser": is_new_user}


def auth_with_google(id_token, email_hint="", display_name="", device_id=""):
    id_token = str(id_token or "").strip()
    device_id = str(device_id or "").strip()[:80]
    if not id_token:
        return {"ok": False, "error": "Не передан Google ID Token"}

    try:
        req = Request(
            f"https://oauth2.googleapis.com/tokeninfo?id_token={id_token}",
            method="GET",
            headers={"User-Agent": "AIRouteServer/1.0"},
        )
        with urlopen(req, timeout=8) as resp:
            info = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        print(f"[Fake Police] Ошибка проверки Google токена: {exc}", flush=True)
        return {"ok": False, "error": "Недействительный Google токен"}

    email = str(info.get("email") or email_hint or "").strip().lower()
    sub = str(info.get("sub") or "").strip()
    verified = info.get("email_verified") in (True, "true", "True", 1)
    if not email or not verified:
        return {"ok": False, "error": "Email в Google аккаунте не подтверждён"}
    if GOOGLE_CLIENT_ID and info.get("aud") != GOOGLE_CLIENT_ID:
        return {"ok": False, "error": "Google токен выдан для другого приложения"}

    name_base = str(info.get("name") or display_name or email.split("@")[0]).strip()
    cur_now = now_ms()
    is_new_user = False

    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        row = None
        if sub:
            row = conn.execute("SELECT id FROM users WHERE google_sub = ?", (sub,)).fetchone()
        if not row:
            row = conn.execute("SELECT id FROM users WHERE lower(email) = ?", (email,)).fetchone()

        if row:
            user_id = row[0]
            if sub:
                conn.execute("UPDATE users SET google_sub = ? WHERE id = ?", (sub, user_id))
            log_user_action(conn, user_id, "auth", "Вход через Google", email)
        else:
            is_new_user = True
            uname = _generate_unique_username(conn, name_base)
            salt, pwd_hash = hash_password(secrets.token_urlsafe(24))
            cur = conn.execute(
                """
                INSERT INTO users (username, password_hash, salt, role, created_at, email, device_id, google_sub)
                VALUES (?, ?, ?, 'user', ?, ?, ?, ?)
                """,
                (uname, pwd_hash, salt, cur_now, email, device_id, sub),
            )
            user_id = cur.lastrowid
            log_user_action(conn, user_id, "auth", "Регистрация через Google", email)

        user_dict = _fetch_user_dict_by_id(conn, user_id)
        conn.commit()

    token = create_session(user_id)
    return {"ok": True, "token": token, "user": user_dict, "isNewUser": is_new_user}


def _resolve_tg_bot_username():
    global TG_BOT_USERNAME
    if TG_BOT_USERNAME:
        return TG_BOT_USERNAME
    if not TG_BOT_TOKEN or "ВСТАВЬ_СВОЙ" in TG_BOT_TOKEN:
        return ""
    try:
        req = Request(f"https://api.telegram.org/bot{TG_BOT_TOKEN}/getMe", method="GET")
        with urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if data.get("ok") and isinstance(data.get("result"), dict):
            uname = str(data["result"].get("username") or "").strip().lstrip("@")
            if uname:
                TG_BOT_USERNAME = uname
                return uname
    except Exception as exc:
        print(f"[Fake Police] Не удалось получить username Telegram-бота: {exc}", flush=True)
    return ""


def start_telegram_auth():
    bot_username = _resolve_tg_bot_username()
    if not bot_username:
        return {"ok": False, "error": "На сервере не настроен TG_BOT_TOKEN / TG_BOT_USERNAME"}

    sid = secrets.token_urlsafe(12)
    code = f"{random.randint(1000, 9999)}"
    now_ts = time.time()
    with TG_AUTH_LOCK:
        # Чистим просроченные сессии
        expired = [k for k, v in TG_AUTH_SESSIONS.items() if v["expires"] < now_ts]
        for k in expired:
            TG_AUTH_SESSIONS.pop(k, None)
        TG_AUTH_SESSIONS[sid] = {
            "code": code,
            "tg_id": None,
            "tg_username": None,
            "tg_name": None,
            "expires": now_ts + 600,
        }
    return {
        "ok": True,
        "sessionId": sid,
        "botUrl": f"https://t.me/{bot_username}?start=auth_{sid}",
    }


def verify_telegram_auth_code(session_id, code, device_id=""):
    sid = str(session_id or "").strip()
    code = str(code or "").strip()
    device_id = str(device_id or "").strip()[:80]
    if not sid or not re.match(r"^\d{4}$", code):
        return {"ok": False, "error": "Введите 4-значный код из Telegram-бота"}

    with TG_AUTH_LOCK:
        sess = TG_AUTH_SESSIONS.get(sid)
        if not sess or sess["expires"] < time.time():
            TG_AUTH_SESSIONS.pop(sid, None)
            return {"ok": False, "error": "Сессия устарела. Нажмите «Продолжить с Telegram» ещё раз."}
        if str(sess["code"]) != code:
            return {"ok": False, "error": "Неверный код из Telegram"}
        if not sess.get("tg_id"):
            return {"ok": False, "error": "Сначала нажмите «Start» в открывшемся Telegram-боте"}
        tg_id = str(sess["tg_id"])
        tg_username = str(sess.get("tg_username") or "").strip()
        tg_name = str(sess.get("tg_name") or tg_username or f"tg_{tg_id}").strip()
        TG_AUTH_SESSIONS.pop(sid, None)

    cur_now = now_ms()
    is_new_user = False
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT id FROM users WHERE tg_id = ?", (tg_id,)).fetchone()
        if row:
            user_id = row[0]
            log_user_action(conn, user_id, "auth", "Вход через Telegram", f"@{tg_username or tg_id}")
        else:
            is_new_user = True
            uname = _generate_unique_username(conn, tg_name)
            salt, pwd_hash = hash_password(secrets.token_urlsafe(24))
            cur = conn.execute(
                """
                INSERT INTO users (username, password_hash, salt, role, created_at, email, device_id, tg_id)
                VALUES (?, ?, ?, 'user', ?, '', ?, ?)
                """,
                (uname, pwd_hash, salt, cur_now, device_id, tg_id),
            )
            user_id = cur.lastrowid
            log_user_action(conn, user_id, "auth", "Регистрация через Telegram", f"@{tg_username or tg_id}")

        user_dict = _fetch_user_dict_by_id(conn, user_id)
        conn.commit()

    token = create_session(user_id)
    return {"ok": True, "token": token, "user": user_dict, "isNewUser": is_new_user}


def _tg_send_simple_message(chat_id, text):
    if not TG_BOT_TOKEN or "ВСТАВЬ_СВОЙ" in TG_BOT_TOKEN:
        return
    payload = json.dumps({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
    }, ensure_ascii=False).encode("utf-8")
    try:
        req = Request(
            f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urlopen(req, timeout=8) as resp:
            resp.read()
    except Exception as exc:
        print(f"[Fake Police] Ошибка ответа Telegram-бота: {exc}", flush=True)


def start_telegram_auth_polling_thread():
    if not TG_AUTH_POLLING:
        return
    if not TG_BOT_TOKEN or "ВСТАВЬ_СВОЙ" in TG_BOT_TOKEN:
        return

    def worker():
        bot_name = _resolve_tg_bot_username()
        print(f"[Fake Police] Telegram-авторизация запущена (@{bot_name or 'bot'})", flush=True)
        offset = 0
        while True:
            try:
                url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/getUpdates?timeout=20&offset={offset}&allowed_updates=%5B%22message%22%5D"
                req = Request(url, method="GET")
                with urlopen(req, timeout=28) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                if not data.get("ok"):
                    time.sleep(5)
                    continue
                for upd in data.get("result") or []:
                    offset = max(offset, int(upd.get("update_id", 0)) + 1)
                    msg = upd.get("message") or {}
                    text = str(msg.get("text") or "").strip()
                    if not text.startswith("/start"):
                        continue
                    parts = text.split(maxsplit=1)
                    if len(parts) < 2 or not parts[1].startswith("auth_"):
                        continue
                    sid = parts[1][5:].strip()
                    chat_id = (msg.get("chat") or {}).get("id")
                    from_u = msg.get("from") or {}
                    tg_uid = from_u.get("id")
                    tg_uname = from_u.get("username") or ""
                    tg_first = from_u.get("first_name") or ""
                    if not chat_id or not tg_uid:
                        continue
                    with TG_AUTH_LOCK:
                        sess = TG_AUTH_SESSIONS.get(sid)
                        if not sess or sess["expires"] < time.time():
                            reply = "Ссылка для входа устарела. Нажмите «Продолжить с Telegram» в приложении ещё раз."
                        else:
                            sess["tg_id"] = str(tg_uid)
                            sess["tg_username"] = tg_uname
                            sess["tg_name"] = tg_first or tg_uname or f"tg_{tg_uid}"
                            reply = (
                                f"🔐 <b>Ваш код для входа в AIRoute:</b>\n\n"
                                f"<code>{sess['code']}</code>\n\n"
                                f"Вернитесь в приложение и введите эти 4 цифры."
                            )
                    _tg_send_simple_message(chat_id, reply)
            except Exception as exc:
                err_s = str(exc)
                if "409" in err_s:
                    # Если другой процесс использует этот же токен на polling — ждём дольше и не спамим
                    time.sleep(30)
                else:
                    time.sleep(5)

    t = threading.Thread(target=worker, daemon=True)
    t.start()


def update_user_profile(user_id, username, city="", avatar_index=None):
    clean_name = re.sub(r"\s+", " ", str(username or "")).strip()
    if len(clean_name) < 2 or len(clean_name) > 28:
        return {"ok": False, "error": "Никнейм должен быть от 2 до 28 символов"}
    if not re.match(r"^[A-Za-zА-Яа-яЁё0-9 _.-]{2,28}$", clean_name):
        return {"ok": False, "error": "В никнейме допустимы буквы, цифры, пробел и _ . -"}

    clean_city = str(city or "").strip()[:80]
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        conflict = conn.execute(
            "SELECT id FROM users WHERE lower(username) = lower(?) AND id != ?",
            (clean_name, int(user_id)),
        ).fetchone()
        if conflict:
            return {"ok": False, "error": "Такой никнейм уже занят, выберите другой"}

        if avatar_index is not None:
            conn.execute(
                "UPDATE users SET username = ?, city = ?, avatar_index = ? WHERE id = ?",
                (clean_name, clean_city, int(avatar_index), int(user_id)),
            )
        else:
            conn.execute(
                "UPDATE users SET username = ?, city = ? WHERE id = ?",
                (clean_name, clean_city, int(user_id)),
            )
        log_user_action(conn, user_id, "profile", "Обновлён профиль", f"{clean_name} · {clean_city}")
        user_dict = _fetch_user_dict_by_id(conn, user_id)
        conn.commit()

    schedule_cloud_backup()
    return {"ok": True, "user": user_dict}


def register_user(username, password, email="", code="", device_id="", elapsed_ms=3000, honeypot=""):
    if str(honeypot or "").strip():
        return {"ok": False, "error": "Регистрация отклонена антибот-фильтром"}
    if int(elapsed_ms or 3000) < 1200:
        return {"ok": False, "error": "Слишком быстрая отправка формы"}

    username = str(username or "").strip()
    password = str(password or "")
    email = str(email or "").strip().lower()
    code = str(code or "").strip()
    device_id = str(device_id or "").strip()[:80]

    if not re.match(r"^[A-Za-zА-Яа-яЁё0-9_.-]{3,24}$", username):
        return {"ok": False, "error": "Логин: от 3 до 24 символов (буквы, цифры, _ . -)"}
    if len(password) < 6 or len(password) > 64:
        return {"ok": False, "error": "Пароль должен быть от 6 до 64 символов"}
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return {"ok": False, "error": "Укажите корректный адрес электронной почты"}
    if not re.match(r"^\d{6}$", code):
        return {"ok": False, "error": "Введите 6-значный код подтверждения из письма"}

    salt, pwd_hash = hash_password(password)
    cur_now = now_ms()
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        if conn.execute("SELECT id FROM users WHERE lower(email) = ?", (email,)).fetchone():
            return {"ok": False, "error": "Этот email уже зарегистрирован"}

        if device_id:
            dev_acc_count = conn.execute(
                "SELECT COUNT(*) FROM users WHERE device_id = ?",
                (device_id,),
            ).fetchone()[0]
            if dev_acc_count >= 3:
                return {"ok": False, "error": "Достигнут лимит регистраций с одного устройства"}

        code_row = conn.execute(
            """
            SELECT id, code, expires_at FROM email_codes
            WHERE lower(email) = ? AND purpose = 'register' AND used = 0
            ORDER BY id DESC LIMIT 1
            """,
            (email,),
        ).fetchone()
        if not code_row or str(code_row[1]) != code:
            return {"ok": False, "error": "Неверный код подтверждения почты"}
        if int(code_row[2]) < cur_now:
            return {"ok": False, "error": "Срок действия кода истёк. Запросите новый код."}

        try:
            cur = conn.execute(
                """
                INSERT INTO users (username, password_hash, salt, role, created_at, email, device_id)
                VALUES (?, ?, ?, 'user', ?, ?, ?)
                """,
                (username, pwd_hash, salt, cur_now, email, device_id),
            )
            user_id = cur.lastrowid
            conn.execute("UPDATE email_codes SET used = 1 WHERE id = ?", (code_row[0],))
            log_user_action(conn, user_id, "auth", "Регистрация аккаунта", f"Email: {email}")
            conn.commit()
        except sqlite3.IntegrityError:
            return {"ok": False, "error": "Такой логин уже занят"}

    token = create_session(user_id)
    return {
        "ok": True,
        "token": token,
        "user": format_user_dict(user_id, username, "user", 0, 0, 0, 0, email=email, created_at=cur_now),
    }


def login_user(username_or_email, password):
    ident = str(username_or_email or "").strip()
    password = str(password or "")
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            """
            SELECT id, username, password_hash, salt, role, rating, markers_count, votes_count, comments_count,
                   email, created_at, confirmed_markers, rejected_markers,
                   is_blocked, blocked_until, shadowbanned, shadowbanned_until, block_reason
            FROM users
            WHERE username = ? OR (email != '' AND lower(email) = lower(?))
            """,
            (ident, ident),
        ).fetchone()
        if not row or not verify_password(password, row[3], row[2]):
            return {"ok": False, "error": "Неверный логин/почта или пароль"}
        log_user_action(conn, row[0], "auth", "Вход в аккаунт", "По паролю")
        conn.commit()
    token = create_session(row[0])
    return {
        "ok": True,
        "token": token,
        "user": format_user_dict(
            row[0], row[1], row[4], row[5], row[6], row[7], row[8],
            email=row[9], created_at=row[10], confirmed_markers=row[11], rejected_markers=row[12],
            is_blocked=row[13], blocked_until=row[14], shadowbanned=row[15], shadowbanned_until=row[16],
            block_reason=row[17],
        ),
    }


def login_user_by_email_code(email, code):
    email = str(email or "").strip().lower()
    code = str(code or "").strip()
    cur_now = now_ms()
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            """
            SELECT id, username, password_hash, salt, role, rating, markers_count, votes_count, comments_count,
                   email, created_at, confirmed_markers, rejected_markers,
                   is_blocked, blocked_until, shadowbanned, shadowbanned_until, block_reason
            FROM users WHERE lower(email) = ?
            """,
            (email,),
        ).fetchone()
        if not row:
            return {"ok": False, "error": "Аккаунт с такой почтой не найден"}
        code_row = conn.execute(
            """
            SELECT id, code, expires_at FROM email_codes
            WHERE lower(email) = ? AND purpose = 'login' AND used = 0
            ORDER BY id DESC LIMIT 1
            """,
            (email,),
        ).fetchone()
        if not code_row or str(code_row[1]) != code:
            return {"ok": False, "error": "Неверный код подтверждения"}
        if int(code_row[2]) < cur_now:
            return {"ok": False, "error": "Срок действия кода истёк"}
        conn.execute("UPDATE email_codes SET used = 1 WHERE id = ?", (code_row[0],))
        log_user_action(conn, row[0], "auth", "Вход в аккаунт", f"По коду с почты ({email})")
        conn.commit()
    token = create_session(row[0])
    return {
        "ok": True,
        "token": token,
        "user": format_user_dict(
            row[0], row[1], row[4], row[5], row[6], row[7], row[8],
            email=row[9], created_at=row[10], confirmed_markers=row[11], rejected_markers=row[12],
            is_blocked=row[13], blocked_until=row[14], shadowbanned=row[15], shadowbanned_until=row[16],
            block_reason=row[17],
        ),
    }


def logout_token(token):
    if not token:
        return
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()


def row_to_marker(row, viewer_user_id=None, is_admin=False):
    try:
        raw_comments = json.loads(row[9] or "[]")
        if not isinstance(raw_comments, list):
            raw_comments = []
    except Exception:
        raw_comments = []

    comments = []
    for c in raw_comments:
        if not isinstance(c, dict):
            continue
        if str(c.get("author") or "").strip().lower() == "безымянный райдер":
            c["author"] = "Пользователь"
        # Комментарии в теневом бане видит только сам автор (и админ)
        if c.get("shadowbanned") and not is_admin:
            if viewer_user_id is None or str(c.get("authorId")) != str(viewer_user_id):
                continue
        comments.append(c)

    return {
        "id": row[0],
        "type": row[1],
        "lat": row[2],
        "lng": row[3],
        "address": row[4],
        "createdAt": row[5],
        "lastConfirmedAt": row[6],
        "confirmations": row[7],
        "dismissals": row[8],
        "comments": comments,
        "createdBy": row[10] if len(row) > 10 else None,
    }


DPS_EXPIRE_MS = 3 * 3600 * 1000


def cleanup_expired_dps(conn):
    cutoff = now_ms() - DPS_EXPIRE_MS
    expired = conn.execute(
        "SELECT id FROM markers WHERE type = 'dps' AND id NOT LIKE ? AND last_confirmed_at < ?",
        (f"{EXT_PREFIX}%", cutoff),
    ).fetchall()
    if expired:
        ids = [r[0] for r in expired]
        placeholders = ",".join("?" for _ in ids)
        conn.execute(f"DELETE FROM markers WHERE id IN ({placeholders})", ids)
        conn.execute(f"DELETE FROM marker_votes WHERE marker_id IN ({placeholders})", ids)
        conn.execute(f"DELETE FROM marker_comment_rewards WHERE marker_id IN ({placeholders})", ids)
        conn.commit()
        return len(ids)
    return 0


def start_cleanup_thread():
    def worker():
        while True:
            time.sleep(60)
            try:
                with DB_LOCK, db_connect() as conn:
                    removed = cleanup_expired_dps(conn)
                if removed:
                    invalidate_markers_cache()
            except Exception as exc:
                print(f"[Fake Police] Ошибка фоновой очистки ДПС: {exc}", flush=True)

    t = threading.Thread(target=worker, daemon=True)
    t.start()


def get_voter_votes(voter_key):
    if not voter_key:
        return {}
    with db_connect() as conn:
        vrows = conn.execute(
            "SELECT marker_id, vote FROM marker_votes WHERE device_id = ?",
            (voter_key,),
        ).fetchall()
    return {r[0]: r[1] for r in vrows}


def _get_public_markers_cache():
    global MARKERS_CACHE
    with MARKERS_CACHE_LOCK:
        if MARKERS_CACHE is not None:
            return MARKERS_CACHE

    with db_connect() as conn:
        rows = conn.execute(
            """
            SELECT id, type, lat, lng, address, created_at, last_confirmed_at,
                   confirmations, dismissals, comments_json, created_by, status, shadowbanned
            FROM markers
            ORDER BY last_confirmed_at DESC
            """
        ).fetchall()
        key_row = conn.execute("SELECT value FROM settings WHERE key = 'yandex_api_key'").fetchone()
        yandex_key = key_row[0] if key_row else ""

    public_markers = []
    special_user_ids = set()

    for r in rows:
        status = r[11] or "active"
        is_sb = int(r[12] or 0) == 1
        author_id = r[10]

        if status != "active" or is_sb:
            if author_id is not None:
                special_user_ids.add(int(author_id))
            continue

        try:
            raw_comments = json.loads(r[9] or "[]")
            if not isinstance(raw_comments, list):
                raw_comments = []
        except Exception:
            raw_comments = []

        comments = []
        for c in raw_comments:
            if not isinstance(c, dict):
                continue
            if str(c.get("author") or "").strip().lower() == "безымянный райдер":
                c["author"] = "Пользователь"
            if c.get("shadowbanned"):
                if c.get("authorId") is not None:
                    try:
                        special_user_ids.add(int(c["authorId"]))
                    except Exception:
                        pass
                continue
            comments.append(c)

        public_markers.append({
            "id": r[0],
            "type": r[1],
            "lat": r[2],
            "lng": r[3],
            "address": r[4],
            "createdAt": r[5],
            "lastConfirmedAt": r[6],
            "confirmations": r[7],
            "dismissals": r[8],
            "comments": comments,
            "createdBy": author_id,
        })

    markers_json_str = json.dumps(public_markers, ensure_ascii=False, separators=(",", ":"))
    yandex_key_json = json.dumps(yandex_key, ensure_ascii=False)
    empty_json_str = (
        '{"isBlocked":false,"markers":'
        + markers_json_str
        + ',"userVotes":{},"yandexApiKey":'
        + yandex_key_json
        + "}"
    )
    empty_bytes = empty_json_str.encode("utf-8")
    empty_gzip = gzip.compress(empty_bytes, compresslevel=5)

    entry = {
        "special_user_ids": special_user_ids,
        "markers_json_str": markers_json_str,
        "yandex_key_json": yandex_key_json,
        "empty_bytes": empty_bytes,
        "empty_gzip": empty_gzip,
    }
    with MARKERS_CACHE_LOCK:
        MARKERS_CACHE = entry
    return entry


def list_markers(voter_key="", include_author=False, viewer_user_id=None):
    with db_connect() as conn:
        rows = conn.execute(
            """
            SELECT m.id, m.type, m.lat, m.lng, m.address, m.created_at, m.last_confirmed_at,
                   m.confirmations, m.dismissals, m.comments_json, m.created_by, u.username,
                   m.status, m.shadowbanned
            FROM markers m
            LEFT JOIN users u ON u.id = m.created_by
            ORDER BY m.last_confirmed_at DESC
            """
        ).fetchall()
        votes = {}
        if voter_key:
            vrows = conn.execute(
                "SELECT marker_id, vote FROM marker_votes WHERE device_id = ?",
                (voter_key,),
            ).fetchall()
            votes = {r[0]: r[1] for r in vrows}
    result = []
    for r in rows:
        status = r[12] or "active"
        is_sb = int(r[13] or 0) == 1
        author_id = r[10]
        is_own = viewer_user_id is not None and author_id is not None and int(author_id) == int(viewer_user_id)

        # Метки в очереди проверки ('pending') показываем автору и админу
        if status != "active" and not is_own and not include_author:
            continue
        # Метки пользователя в теневом бане видит только он сам и админ
        if is_sb and not include_author and not is_own:
            continue

        item = row_to_marker(r, viewer_user_id=viewer_user_id, is_admin=include_author)
        if include_author:
            item["status"] = status
            item["shadowbanned"] = is_sb
            item["adminOnly"] = bool(is_sb or status != "active")
            if str(r[0]).startswith(EXT_PREFIX):
                item["createdByUsername"] = "Автосинк API"
            else:
                item["createdByUsername"] = r[11] if len(r) > 11 and r[11] else "Неизвестно"
        result.append(item)
    return result, votes


def upsert_marker(data, check_duplicate=True, created_by=None, is_admin=False):
    now = now_ms()
    m_id = str(data.get("id") or f"mk-{now}")[:80]
    m_type = str(data.get("type") or "dps")
    if m_type not in ("dps", "dtp", "camera", "works"):
        m_type = "dps"
    lat = float(data["lat"])
    lng = float(data["lng"])
    if not (-90 <= lat <= 90 and -180 <= lng <= 180):
        raise ValueError("Некорректные координаты")
    address = str(data.get("address") or f"{lat:.4f}, {lng:.4f}")[:240]
    created_at = int(data.get("createdAt") or now)
    last_confirmed_at = int(data.get("lastConfirmedAt") or created_at)
    confirmations = max(0, int(data.get("confirmations") or 0))
    dismissals = max(0, int(data.get("dismissals") or 0))
    comments = data.get("comments") if isinstance(data.get("comments"), list) else []

    status = "active"
    marker_shadowbanned = 0

    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        if created_by is not None and not is_admin:
            u_row = conn.execute(
                "SELECT rating, shadowbanned, shadowbanned_until FROM users WHERE id = ?",
                (int(created_by),),
            ).fetchone()
            if u_row:
                u_rating = int(u_row[0] or 0)
                if is_user_shadowbanned_row(u_row[1], u_row[2]):
                    marker_shadowbanned = 1
                    for c in comments:
                        if isinstance(c, dict):
                            c["shadowbanned"] = True
                            c["authorId"] = int(created_by)
                elif u_rating < 45:
                    # Песочница ранга «Новичок»: не более 2 активных меток в час, остальные идут на проверку админу
                    hour_ago = now - 3600 * 1000
                    recent_user_cnt = conn.execute(
                        "SELECT COUNT(*) FROM markers WHERE created_by = ? AND created_at > ?",
                        (int(created_by), hour_ago),
                    ).fetchone()[0]
                    if recent_user_cnt >= 2:
                        status = "pending"

        comments_json = json.dumps(comments[:50], ensure_ascii=False)

        if check_duplicate and status == "active" and marker_shadowbanned == 0:
            recent = conn.execute(
                "SELECT lat, lng FROM markers WHERE type = ? AND status = 'active' AND shadowbanned = 0 AND created_at > ?",
                (m_type, now - 15 * 60 * 1000),
            ).fetchall()
            for r_lat, r_lng in recent:
                if haversine_m(lat, lng, r_lat, r_lng) < 100:
                    return None, "Рядом (в пределах 100 м) уже есть такая свежая метка", False

        cur = conn.execute(
            """
            INSERT OR IGNORE INTO markers
            (id, type, lat, lng, address, created_at, last_confirmed_at, confirmations, dismissals, comments_json, created_by, status, shadowbanned)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (m_id, m_type, lat, lng, address, created_at, last_confirmed_at, confirmations, dismissals, comments_json, created_by, status, marker_shadowbanned),
        )
        if cur.rowcount > 0 and created_by is not None:
            award_user_rating(conn, created_by, points=0, markers_delta=1)
            action_title = "Метка отправлена на проверку (лимит новичка 2/ч)" if status == "pending" else f"Поставлена метка ({m_type.upper()})"
            log_user_action(conn, created_by, "marker_pending" if status == "pending" else "marker_create", action_title, address, lat, lng)
        conn.commit()
    invalidate_markers_cache()
    schedule_cloud_backup()
    return m_id, None, (status == "pending")


def vote_marker(marker_id, voter_key, vote, user_id=None, is_admin=False):
    if vote not in ("confirm", "dismiss"):
        return {"ok": False, "error": "invalid_vote"}
    now = now_ms()
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            """
            SELECT confirmations, dismissals, created_by, dismiss_weight, confirmed_by_senior, address
            FROM markers WHERE id = ?
            """,
            (marker_id,),
        ).fetchone()
        if not row:
            return {"ok": False, "error": "not_found"}

        voter_rating = 100 if is_admin else 0
        voter_shadowbanned = False
        if user_id is not None:
            u_row = conn.execute(
                "SELECT rating, shadowbanned, shadowbanned_until FROM users WHERE id = ?",
                (int(user_id),),
            ).fetchone()
            if u_row:
                voter_rating = int(u_row[0] or 0)
                voter_shadowbanned = is_user_shadowbanned_row(u_row[1], u_row[2]) and not is_admin

        if not is_admin:
            if user_id is not None and row[2] is not None and int(row[2]) == int(user_id):
                return {"ok": False, "error": "Нельзя подтверждать или отклонять собственную метку"}
            existing = conn.execute(
                "SELECT vote FROM marker_votes WHERE marker_id = ? AND device_id = ?",
                (marker_id, voter_key),
            ).fetchone()
            if existing:
                return {"ok": False, "error": "Вы уже голосовали по этой метке", "vote": existing[0]}
            conn.execute(
                "INSERT INTO marker_votes (marker_id, device_id, vote, created_at) VALUES (?, ?, ?, ?)",
                (marker_id, voter_key, vote, now),
            )

        prev_confirmations = int(row[0] or 0)
        confirmations, dismissals = prev_confirmations, int(row[1] or 0)
        author_id = row[2]
        dismiss_weight = float(row[3] or 0.0)
        confirmed_by_senior = int(row[4] or 0)
        marker_addr = row[5] or marker_id

        # Если голосующий в теневом бане — его голос не влияет на счётчики чужих постов
        if voter_shadowbanned:
            log_user_action(conn, user_id, "vote", f"Голос ({vote}) в теневом бане (игнорирован)", marker_addr)
            conn.commit()
            return {"ok": True, "confirmations": confirmations, "dismissals": dismissals}

        is_ext = marker_id.startswith(EXT_PREFIX)
        if vote == "confirm":
            confirmations += 1
            if is_admin or voter_rating >= 150:
                confirmed_by_senior = 1
            conn.execute(
                "UPDATE markers SET confirmations = ?, last_confirmed_at = ?, confirmed_by_senior = ? WHERE id = ?",
                (confirmations, now, confirmed_by_senior, marker_id),
            )
            if is_ext:
                conn.execute(
                    """
                    INSERT INTO ext_overrides (marker_id, admin_conf_delta, local_last_confirmed_at, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(marker_id) DO UPDATE SET
                        admin_conf_delta = admin_conf_delta + excluded.admin_conf_delta,
                        local_last_confirmed_at = MAX(local_last_confirmed_at, excluded.local_last_confirmed_at),
                        updated_at = excluded.updated_at
                    """,
                    (marker_id, 1 if is_admin else 0, now, now),
                )
        else:
            dismissals += 1
            # Песочница «Новичок»: голос новичка (< 45 очков) имеет вес 0.34 (нужно 3 новичка против Штурмана/Патрульного)
            weight = 0.34 if (not is_admin and voter_rating < 45) else 1.0
            dismiss_weight += weight

            should_remove = False
            if not is_ext:
                if confirmed_by_senior == 1:
                    should_remove = dismiss_weight >= 1.0 and dismissals >= 3
                else:
                    should_remove = dismissals >= 3 and dismissals >= confirmations

            if should_remove:
                conn.execute("DELETE FROM markers WHERE id = ?", (marker_id,))
                conn.execute("DELETE FROM marker_votes WHERE marker_id = ?", (marker_id,))
                conn.execute("DELETE FROM marker_comment_rewards WHERE marker_id = ?", (marker_id,))
                if author_id is not None:
                    conn.execute(
                        "UPDATE users SET rejected_markers = rejected_markers + 1 WHERE id = ?",
                        (int(author_id),),
                    )
                    if prev_confirmations == 0:
                        award_user_rating(conn, author_id, points=-1)
                    else:
                        evaluate_auto_shadowban(conn, author_id)
                if user_id is not None:
                    award_user_rating(conn, user_id, points=2, votes_delta=1)
                    log_user_action(conn, user_id, "vote", "Снята неактуальная метка («Нет на месте»)", marker_addr)
                conn.commit()
                invalidate_markers_cache()
                schedule_cloud_backup()
                return {"ok": True, "removed": True}

            conn.execute(
                "UPDATE markers SET dismissals = ?, dismiss_weight = ? WHERE id = ?",
                (dismissals, dismiss_weight, marker_id),
            )
            if is_ext and is_admin:
                conn.execute(
                    """
                    INSERT INTO ext_overrides (marker_id, admin_dism_delta, updated_at)
                    VALUES (?, 1, ?)
                    ON CONFLICT(marker_id) DO UPDATE SET
                        admin_dism_delta = admin_dism_delta + 1,
                        updated_at = excluded.updated_at
                    """,
                    (marker_id, now),
                )

        if user_id is not None:
            award_user_rating(conn, user_id, points=2, votes_delta=1)
            log_user_action(
                conn,
                user_id,
                "vote",
                "Подтвердил метку" if vote == "confirm" else "Отметил «Нет на месте»",
                marker_addr,
            )
            if vote == "confirm" and author_id is not None and int(author_id) != int(user_id):
                author_pts = 10 if prev_confirmations == 0 else 5
                if prev_confirmations == 0:
                    conn.execute(
                        "UPDATE users SET confirmed_markers = confirmed_markers + 1 WHERE id = ?",
                        (int(author_id),),
                    )
                award_user_rating(conn, author_id, points=author_pts)
        conn.commit()
    invalidate_markers_cache()
    schedule_cloud_backup()
    return {"ok": True, "confirmations": confirmations, "dismissals": dismissals}


def add_comment(marker_id, author, text, ts=None, user_id=None, is_admin=False):
    clean_text = str(text or "").strip()[:400]
    if not clean_text:
        return {"ok": False, "error": "Пустой комментарий"}
    clean_author = str(author or "Водитель").strip()[:40] or "Водитель"
    ts_val = int(ts or now_ms())
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        is_sb = False
        if user_id is not None and not is_admin:
            u_row = conn.execute(
                """
                SELECT rating, confirmed_markers, created_at, shadowbanned, shadowbanned_until
                FROM users WHERE id = ?
                """,
                (int(user_id),),
            ).fetchone()
            if u_row:
                u_rating = int(u_row[0] or 0)
                u_conf = int(u_row[1] or 0)
                u_created = int(u_row[2] or 0)
                is_sb = is_user_shadowbanned_row(u_row[3], u_row[4])
                # Песочница «Новичок»: комментарии открываются после 1 подтверждённой метки ИЛИ спустя 12ч
                if u_rating < 45 and u_conf < 1 and (now_ms() - u_created) < 12 * 3600 * 1000:
                    return {
                        "ok": False,
                        "error": "Песочница «Новичок»: комментарии откроются после 1 подтверждённой метки или спустя 12 ч после регистрации",
                    }

        row = conn.execute(
            "SELECT comments_json, address FROM markers WHERE id = ?",
            (marker_id,),
        ).fetchone()
        if not row:
            return {"ok": False, "error": "Метка не найдена"}
        try:
            comments = json.loads(row[0] or "[]")
        except Exception:
            comments = []
        if comments and comments[-1].get("text", "").lower() == clean_text.lower():
            return {"ok": False, "error": "Такой комментарий уже только что был отправлен"}

        cmt_obj = {"author": clean_author, "text": clean_text, "ts": ts_val}
        if user_id is not None:
            cmt_obj["authorId"] = int(user_id)
        if is_sb:
            cmt_obj["shadowbanned"] = True

        comments.append(cmt_obj)
        conn.execute(
            "UPDATE markers SET comments_json = ? WHERE id = ?",
            (json.dumps(comments[-50:], ensure_ascii=False), marker_id),
        )
        rewarded = False
        if user_id is not None:
            log_user_action(conn, user_id, "comment", f"Комментарий к метке ({row[1] or marker_id})", clean_text)
            if not is_sb:
                cur_r = conn.execute(
                    "INSERT OR IGNORE INTO marker_comment_rewards (marker_id, user_id, created_at) VALUES (?, ?, ?)",
                    (marker_id, int(user_id), ts_val),
                )
                if cur_r.rowcount > 0:
                    rewarded = True
                    award_user_rating(conn, user_id, points=3, comments_delta=1)
                else:
                    award_user_rating(conn, user_id, points=0, comments_delta=1)
        conn.commit()
    invalidate_markers_cache()
    schedule_cloud_backup()
    return {"ok": True, "rewarded": rewarded}


def delete_comment_admin(marker_id, author, text, ts):
    clean_author = str(author or "").strip()
    clean_text = str(text or "").strip()
    ts_int = int(ts or 0)
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT comments_json FROM markers WHERE id = ?",
            (marker_id,),
        ).fetchone()
        if not row:
            return {"ok": False, "error": "Метка не найдена"}
        try:
            comments = json.loads(row[0] or "[]")
            if not isinstance(comments, list):
                comments = []
        except Exception:
            comments = []

        new_comments = []
        removed = False
        for c in comments:
            if not isinstance(c, dict):
                continue
            c_author = str(c.get("author") or "").strip()
            c_text = str(c.get("text") or "").strip()
            c_ts = int(c.get("ts") or 0)
            if not removed and c_text == clean_text and (ts_int == 0 or c_ts == ts_int) and (not clean_author or c_author == clean_author):
                removed = True
                if marker_id.startswith(EXT_PREFIX) and c.get("source") == "ext":
                    conn.execute(
                        "INSERT OR IGNORE INTO ext_deleted_comments (marker_id, author, text, ts) VALUES (?, ?, ?, ?)",
                        (marker_id, c_author, c_text, c_ts),
                    )
                continue
            new_comments.append(c)

        conn.execute(
            "UPDATE markers SET comments_json = ? WHERE id = ?",
            (json.dumps(new_comments[:50], ensure_ascii=False), marker_id),
        )
        conn.commit()
    invalidate_markers_cache()
    if not marker_id.startswith(EXT_PREFIX):
        schedule_cloud_backup()
    return {"ok": True}


def update_marker_admin(marker_id, data):
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT type, lat, lng, address, comments_json, confirmations FROM markers WHERE id = ?",
            (marker_id,),
        ).fetchone()
        if not row:
            return {"ok": False, "error": "Метка не найдена"}

        m_type = row[0]
        if "type" in data and str(data["type"]) in ("dps", "dtp", "camera", "works"):
            m_type = str(data["type"])

        lat = row[1]
        lng = row[2]
        if "lat" in data and "lng" in data:
            new_lat = float(data["lat"])
            new_lng = float(data["lng"])
            if not (-90 <= new_lat <= 90 and -180 <= new_lng <= 180):
                return {"ok": False, "error": "Некорректные координаты"}
            lat, lng = new_lat, new_lng

        address = row[3]
        if "address" in data and str(data["address"] or "").strip():
            address = str(data["address"]).strip()[:240]

        comments_json = row[4]
        if "description" in data:
            desc = str(data["description"] or "").strip()[:400]
            try:
                comments = json.loads(comments_json or "[]")
                if not isinstance(comments, list):
                    comments = []
            except Exception:
                comments = []
            if desc:
                if comments:
                    comments[0]["text"] = desc
                else:
                    comments.append({"author": "Админ", "text": desc, "ts": now_ms()})
            elif comments:
                comments.pop(0)
            comments_json = json.dumps(comments[:50], ensure_ascii=False)

        confirmations = int(row[5] or 0)
        if "confirmations" in data and data["confirmations"] is not None:
            try:
                confirmations = max(0, min(999, int(data["confirmations"])))
            except Exception:
                pass

        conn.execute(
            "UPDATE markers SET type = ?, lat = ?, lng = ?, address = ?, comments_json = ?, confirmations = ? WHERE id = ?",
            (m_type, lat, lng, address, comments_json, confirmations, marker_id),
        )
        if marker_id.startswith(EXT_PREFIX):
            cur_now = now_ms()
            conn.execute(
                "INSERT OR IGNORE INTO ext_overrides (marker_id, updated_at) VALUES (?, ?)",
                (marker_id, cur_now),
            )
            if "type" in data and str(data["type"]) in ("dps", "dtp", "camera", "works"):
                conn.execute("UPDATE ext_overrides SET type_override = ?, updated_at = ? WHERE marker_id = ?", (m_type, cur_now, marker_id))
            if "lat" in data and "lng" in data:
                conn.execute("UPDATE ext_overrides SET lat_override = ?, lng_override = ?, updated_at = ? WHERE marker_id = ?", (lat, lng, cur_now, marker_id))
            if "address" in data and str(data["address"] or "").strip():
                conn.execute("UPDATE ext_overrides SET address_override = ?, updated_at = ? WHERE marker_id = ?", (address, cur_now, marker_id))
            if "description" in data:
                desc_val = str(data["description"] or "").strip()[:400]
                conn.execute("UPDATE ext_overrides SET desc_override = ?, updated_at = ? WHERE marker_id = ?", (desc_val, cur_now, marker_id))
            if "confirmations" in data and data["confirmations"] is not None:
                local_conf = conn.execute(
                    "SELECT COUNT(*) FROM marker_votes WHERE marker_id = ? AND vote = 'confirm'",
                    (marker_id,),
                ).fetchone()[0]
                conn.execute(
                    "UPDATE ext_overrides SET conf_override = ?, admin_conf_delta = 0, updated_at = ? WHERE marker_id = ?",
                    (max(0, confirmations - local_conf), cur_now, marker_id),
                )
        conn.commit()
    invalidate_markers_cache()
    if not marker_id.startswith(EXT_PREFIX):
        schedule_cloud_backup()
    return {"ok": True}


def delete_marker(marker_id):
    cur_now = now_ms()
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT confirmations, created_by FROM markers WHERE id = ?",
            (marker_id,),
        ).fetchone()
        if row and row[1] is not None:
            conn.execute(
                "UPDATE users SET rejected_markers = rejected_markers + 1 WHERE id = ?",
                (int(row[1]),),
            )
            if int(row[0] or 0) == 0:
                award_user_rating(conn, row[1], points=-1)
            else:
                evaluate_auto_shadowban(conn, row[1])
        conn.execute("DELETE FROM markers WHERE id = ?", (marker_id,))
        conn.execute("DELETE FROM marker_votes WHERE marker_id = ?", (marker_id,))
        conn.execute("DELETE FROM marker_comment_rewards WHERE marker_id = ?", (marker_id,))
        if marker_id.startswith(EXT_PREFIX):
            conn.execute(
                """
                INSERT INTO ext_overrides (marker_id, deleted, updated_at)
                VALUES (?, 1, ?)
                ON CONFLICT(marker_id) DO UPDATE SET deleted = 1, updated_at = excluded.updated_at
                """,
                (marker_id, cur_now),
            )
        conn.commit()
    invalidate_markers_cache()
    if not marker_id.startswith(EXT_PREFIX):
        schedule_cloud_backup()
    return {"ok": True}


# ================= АДМИН-ФУНКЦИИ (ОЧЕРЕДЬ НОВИЧКОВ, ЮЗЕРЫ, БАН, SHADOWBAN) =================

def list_pending_markers_admin():
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            """
            SELECT m.id, m.type, m.lat, m.lng, m.address, m.created_at, m.last_confirmed_at,
                   m.confirmations, m.dismissals, m.comments_json, m.created_by, u.username
            FROM markers m
            LEFT JOIN users u ON u.id = m.created_by
            WHERE m.status = 'pending'
            ORDER BY m.created_at DESC
            """
        ).fetchall()
    res = []
    for r in rows:
        item = row_to_marker(r, is_admin=True)
        item["createdByUsername"] = r[11] if r[11] else "Новичок"
        res.append(item)
    return res


def approve_pending_marker_admin(marker_id):
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT created_by, address FROM markers WHERE id = ?",
            (marker_id,),
        ).fetchone()
        if not row:
            return {"ok": False, "error": "Метка не найдена"}
        conn.execute("UPDATE markers SET status = 'active' WHERE id = ?", (marker_id,))
        if row[0] is not None:
            conn.execute(
                "UPDATE users SET confirmed_markers = confirmed_markers + 1 WHERE id = ?",
                (int(row[0]),),
            )
            log_user_action(conn, row[0], "moderation", "Метка новичка одобрена админом", row[1] or marker_id)
        conn.commit()
    invalidate_markers_cache()
    schedule_cloud_backup()
    return {"ok": True}


def list_users_admin(query=""):
    q = str(query or "").strip().lower()
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        if q:
            rows = conn.execute(
                """
                SELECT id, username, role, rating, markers_count, votes_count, comments_count,
                       email, created_at, confirmed_markers, rejected_markers,
                       is_blocked, blocked_until, shadowbanned, shadowbanned_until, block_reason
                FROM users
                WHERE lower(username) LIKE ? OR lower(email) LIKE ?
                ORDER BY created_at DESC LIMIT 150
                """,
                (f"%{q}%", f"%{q}%"),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, username, role, rating, markers_count, votes_count, comments_count,
                       email, created_at, confirmed_markers, rejected_markers,
                       is_blocked, blocked_until, shadowbanned, shadowbanned_until, block_reason
                FROM users
                ORDER BY created_at DESC LIMIT 150
                """
            ).fetchall()
    return [
        format_user_dict(
            r[0], r[1], r[2], r[3], r[4], r[5], r[6],
            email=r[7], created_at=r[8], confirmed_markers=r[9], rejected_markers=r[10],
            is_blocked=r[11], blocked_until=r[12], shadowbanned=r[13], shadowbanned_until=r[14],
            block_reason=r[15],
        )
        for r in rows
    ]


def list_user_actions_admin(user_id):
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            """
            SELECT id, action_type, title, details, lat, lng, ts
            FROM user_actions
            WHERE user_id = ?
            ORDER BY ts DESC LIMIT 200
            """,
            (int(user_id),),
        ).fetchall()
    return [
        {
            "id": r[0],
            "actionType": r[1],
            "title": r[2],
            "details": r[3],
            "lat": r[4],
            "lng": r[5],
            "ts": r[6],
        }
        for r in rows
    ]


def set_user_block_admin(user_id, blocked, duration_hours=None, reason=""):
    clean_reason = str(reason or "").strip()[:240]
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        if blocked:
            until = (now_ms() + int(duration_hours) * 3600 * 1000) if (duration_hours and int(duration_hours) > 0) else None
            conn.execute(
                "UPDATE users SET is_blocked = 1, blocked_until = ?, block_reason = ? WHERE id = ?",
                (until, clean_reason, int(user_id)),
            )
            detail = f"На {duration_hours} ч" if (duration_hours and int(duration_hours) > 0) else "Навсегда"
            if clean_reason:
                detail += f" · {clean_reason}"
            log_user_action(conn, user_id, "moderation", "Блокировка аккаунта админом", detail)
        else:
            conn.execute(
                "UPDATE users SET is_blocked = 0, blocked_until = NULL, block_reason = '' WHERE id = ?",
                (int(user_id),),
            )
            log_user_action(conn, user_id, "moderation", "Блокировка снята админом", clean_reason)
        conn.commit()
    schedule_cloud_backup()
    return {"ok": True}


def delete_user_admin(user_id, actor_user_id):
    uid = int(user_id)
    if uid == int(actor_user_id):
        return {"ok": False, "error": "Нельзя удалить собственный аккаунт администратора"}
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT role FROM users WHERE id = ?", (uid,)).fetchone()
        if not row:
            return {"ok": False, "error": "Пользователь не найден"}
        if row[0] == "admin":
            return {"ok": False, "error": "Нельзя удалить учётную запись администратора"}

        conn.execute("DELETE FROM sessions WHERE user_id = ?", (uid,))
        conn.execute("DELETE FROM user_actions WHERE user_id = ?", (uid,))
        conn.execute("DELETE FROM marker_comment_rewards WHERE user_id = ?", (uid,))
        conn.execute("DELETE FROM marker_votes WHERE device_id = ?", (f"user:{uid}",))
        conn.execute("DELETE FROM markers WHERE created_by = ? AND (status != 'active' OR shadowbanned = 1)", (uid,))
        conn.execute("UPDATE markers SET created_by = NULL WHERE created_by = ?", (uid,))
        conn.execute("DELETE FROM users WHERE id = ?", (uid,))
        conn.commit()
    with ONLINE_LOCK:
        ONLINE_CLIENTS.pop(f"user:{uid}", None)
    invalidate_markers_cache()
    schedule_cloud_backup()
    return {"ok": True}


def set_user_shadowban_admin(user_id, shadowbanned, duration_hours=24, reason=""):
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        if shadowbanned:
            hours = max(1, int(duration_hours or 24))
            until = now_ms() + hours * 3600 * 1000
            conn.execute(
                "UPDATE users SET shadowbanned = 1, shadowbanned_until = ? WHERE id = ?",
                (until, int(user_id)),
            )
            detail = f"На {hours} ч" + (f" · {reason}" if reason else "")
            log_user_action(conn, user_id, "moderation", "Назначен временный теневой бан", detail)
        else:
            conn.execute(
                "UPDATE users SET shadowbanned = 0, shadowbanned_until = NULL WHERE id = ?",
                (int(user_id),),
            )
            log_user_action(conn, user_id, "moderation", "Теневой бан снят админом", reason)
        conn.commit()
    schedule_cloud_backup()
    return {"ok": True}


class FakePoliceHandler(BaseHTTPRequestHandler):
    def _client_ip(self):
        xff = self.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0]

    def _bearer_token(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        return ""

    def _current_user(self):
        return get_user_by_token(self._bearer_token())

    def _send_cors_headers(self):
        origin = self.headers.get("Origin", "*")
        self.send_header("Access-Control-Allow-Origin", origin if origin else "*")
        self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Max-Age", "86400")

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self):
        self.send_response(200)
        self._send_cors_headers()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _accepts_gzip(self):
        return "gzip" in (self.headers.get("Accept-Encoding") or "").lower()

    def _send_raw_json_bytes(self, raw_bytes, gzip_bytes=None, status=200):
        use_gzip = self._accepts_gzip() and (gzip_bytes is not None or len(raw_bytes) > 512)
        if use_gzip:
            body = gzip_bytes if gzip_bytes is not None else gzip.compress(raw_bytes, compresslevel=5)
        else:
            body = raw_bytes
        self.send_response(status)
        self._send_cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        if use_gzip:
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Vary", "Origin, Accept-Encoding")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, obj, status=200):
        raw_bytes = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._send_raw_json_bytes(raw_bytes, status=status)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0 or length > 2_000_000:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def _serve_html(self, file_path, inject_sync=True):
        if not os.path.exists(file_path):
            self.send_error(404, f"{os.path.basename(file_path)} not found")
            return
        with open(file_path, "r", encoding="utf-8") as f:
            html = f.read()
        if inject_sync and "</head>" in html:
            html = html.replace("</head>", "<script>window.__FP_SYNC_ENABLED__ = true;</script>\n</head>", 1)
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path in ("/", "/index.html", "/fake_police.html", "/yandex_navigator.html"):
            self._serve_html(INDEX_PATH, inject_sync=True)
            return
        if path in ("/admin", "/admin.html"):
            self._serve_html(ADMIN_HTML_PATH, inject_sync=False)
            return
        if path == "/api/config":
            self._send_json({"ok": True, "yandexApiKey": get_setting("yandex_api_key", "")})
            return
        if path == "/api/auth/me":
            user = self._current_user()
            self._send_json({"ok": bool(user), "user": user})
            return
        if path == "/api/markers":
            user = self._current_user()
            dev_id = (qs.get("deviceId") or [""])[0][:80]
            plat = (qs.get("platform") or [""])[0][:24]
            city = (qs.get("city") or [""])[0][:60]
            record_online_client(user=user, device_id=dev_id, ip=self._client_ip(), platform=plat, city=city)

            if user and user.get("isBlocked"):
                self._send_json({
                    "isBlocked": True,
                    "blockedUntil": user.get("blockedUntil"),
                    "blockReason": user.get("blockReason", ""),
                    "markers": [],
                    "userVotes": {},
                })
                return

            voter_key = f"user:{user['id']}" if user else dev_id
            is_admin = bool(user and user["role"] == "admin")
            viewer_id = user["id"] if user else None

            if not is_admin:
                cache = _get_public_markers_cache()
                if viewer_id is None or viewer_id not in cache["special_user_ids"]:
                    votes = get_voter_votes(voter_key)
                    if not votes:
                        self._send_raw_json_bytes(cache["empty_bytes"], gzip_bytes=cache["empty_gzip"])
                        return
                    votes_json = json.dumps(votes, ensure_ascii=False, separators=(",", ":"))
                    raw_bytes = (
                        '{"isBlocked":false,"markers":'
                        + cache["markers_json_str"]
                        + ',"userVotes":'
                        + votes_json
                        + ',"yandexApiKey":'
                        + cache["yandex_key_json"]
                        + "}"
                    ).encode("utf-8")
                    self._send_raw_json_bytes(raw_bytes)
                    return

            markers, votes = list_markers(voter_key, include_author=is_admin, viewer_user_id=viewer_id)
            self._send_json({
                "isBlocked": False,
                "markers": markers,
                "userVotes": votes,
                "yandexApiKey": get_setting("yandex_api_key", ""),
            })
            return

        if path == "/api/admin/online":
            user = self._current_user()
            if not user or user["role"] != "admin":
                self._send_json({"ok": False, "error": "Доступ только для администратора"}, 403)
                return
            snap = get_online_clients_snapshot()
            self._send_json({"ok": True, **snap})
            return

        # Админ GET-маршруты (очередь новичков, список юзеров, журнал действий юзера)
        if path == "/api/admin/markers/pending":
            user = self._current_user()
            if not user or user["role"] != "admin":
                self._send_json({"ok": False, "error": "Доступ только для администратора"}, 403)
                return
            self._send_json({"ok": True, "markers": list_pending_markers_admin()})
            return

        if path == "/api/admin/users":
            user = self._current_user()
            if not user or user["role"] != "admin":
                self._send_json({"ok": False, "error": "Доступ только для администратора"}, 403)
                return
            q = (qs.get("q") or [""])[0]
            self._send_json({"ok": True, "users": list_users_admin(q)})
            return

        parts = [p for p in path.split("/") if p]
        if len(parts) == 5 and parts[0] == "api" and parts[1] == "admin" and parts[2] == "users" and parts[4] == "actions":
            user = self._current_user()
            if not user or user["role"] != "admin":
                self._send_json({"ok": False, "error": "Доступ только для администратора"}, 403)
                return
            uid = unquote(parts[3])
            self._send_json({"ok": True, "actions": list_user_actions_admin(uid)})
            return

        self.send_error(404, "Not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        ip = self._client_ip()
        try:
            payload = self._read_json()
        except Exception:
            self._send_json({"ok": False, "error": "Некорректный JSON"}, 400)
            return

        if path == "/api/auth/send-email-code":
            ok, wait = check_rate_limit(f"email_code:{ip}", 8, 300)
            if not ok:
                self._send_json({"ok": False, "error": f"Слишком много запросов кода. Подождите {wait} сек."}, 429)
                return
            res = send_email_verification_code(
                payload.get("email"),
                payload.get("purpose", "auth"),
                payload.get("username"),
            )
            self._send_json(res, 200 if res.get("ok") else 400)
            return

        if path == "/api/auth/verify-email-code":
            ok, wait = check_rate_limit(f"auth:{ip}", 15, 300)
            if not ok:
                self._send_json({"ok": False, "error": f"Слишком много попыток. Подождите {wait} сек."}, 429)
                return
            res = verify_email_auth_code(
                payload.get("email"),
                payload.get("code"),
                device_id=payload.get("deviceId", ""),
            )
            self._send_json(res, 200 if res.get("ok") else 401)
            return

        if path == "/api/auth/google":
            ok, wait = check_rate_limit(f"auth:{ip}", 15, 300)
            if not ok:
                self._send_json({"ok": False, "error": f"Слишком много попыток. Подождите {wait} сек."}, 429)
                return
            res = auth_with_google(
                payload.get("idToken"),
                email_hint=payload.get("email", ""),
                display_name=payload.get("displayName", ""),
                device_id=payload.get("deviceId", ""),
            )
            self._send_json(res, 200 if res.get("ok") else 401)
            return

        if path == "/api/auth/telegram/start":
            ok, wait = check_rate_limit(f"tg_auth:{ip}", 10, 300)
            if not ok:
                self._send_json({"ok": False, "error": f"Слишком много запросов. Подождите {wait} сек."}, 429)
                return
            res = start_telegram_auth()
            self._send_json(res, 200 if res.get("ok") else 400)
            return

        if path == "/api/auth/telegram/verify":
            ok, wait = check_rate_limit(f"auth:{ip}", 15, 300)
            if not ok:
                self._send_json({"ok": False, "error": f"Слишком много попыток. Подождите {wait} сек."}, 429)
                return
            res = verify_telegram_auth_code(
                payload.get("sessionId"),
                payload.get("code"),
                device_id=payload.get("deviceId", ""),
            )
            self._send_json(res, 200 if res.get("ok") else 401)
            return

        if path == "/api/auth/register":
            ok, wait = check_rate_limit(f"auth:{ip}", 10, 300)
            if not ok:
                self._send_json({"ok": False, "error": f"Слишком много попыток. Подождите {wait} сек."}, 429)
                return
            res = register_user(
                payload.get("username"),
                payload.get("password"),
                email=payload.get("email", ""),
                code=payload.get("code", ""),
                device_id=payload.get("deviceId", ""),
                elapsed_ms=payload.get("elapsedMs", 3000),
                honeypot=payload.get("website", ""),
            )
            self._send_json(res, 201 if res.get("ok") else 400)
            return

        if path == "/api/auth/login":
            ok, wait = check_rate_limit(f"auth:{ip}", 10, 300)
            if not ok:
                self._send_json({"ok": False, "error": f"Слишком много попыток. Подождите {wait} сек."}, 429)
                return
            res = login_user(payload.get("username") or payload.get("email"), payload.get("password"))
            self._send_json(res, 200 if res.get("ok") else 401)
            return

        if path == "/api/auth/login-code":
            ok, wait = check_rate_limit(f"auth:{ip}", 10, 300)
            if not ok:
                self._send_json({"ok": False, "error": f"Слишком много попыток. Подождите {wait} сек."}, 429)
                return
            res = login_user_by_email_code(payload.get("email"), payload.get("code"))
            self._send_json(res, 200 if res.get("ok") else 401)
            return

        if path == "/api/auth/logout":
            logout_token(self._bearer_token())
            self._send_json({"ok": True})
            return

        if path == "/api/ping":
            user = self._current_user()
            record_online_client(
                user=user,
                device_id=payload.get("deviceId", ""),
                ip=self._client_ip(),
                platform=payload.get("platform", ""),
                city=payload.get("city", ""),
            )
            self._send_json({
                "ok": True,
                "isBlocked": bool(user and user.get("isBlocked")),
                "blockedUntil": user.get("blockedUntil") if user else None,
                "blockReason": user.get("blockReason", "") if user else "",
            })
            return

        user = self._current_user()
        if not user:
            self._send_json({"ok": False, "error": "Войдите в аккаунт для этого действия"}, 401)
            return

        if user.get("isBlocked"):
            self._send_json({"ok": False, "error": "Ваш аккаунт временно заблокирован"}, 403)
            return

        if path == "/api/auth/profile":
            res = update_user_profile(
                user["id"],
                payload.get("username"),
                city=payload.get("city", ""),
                avatar_index=payload.get("avatarIndex"),
            )
            self._send_json(res, 200 if res.get("ok") else 400)
            return

        is_admin = user["role"] == "admin"

        if path == "/api/admin/yandex-key":
            if not is_admin:
                self._send_json({"ok": False, "error": "Изменять API-ключ Яндекса может только администратор"}, 403)
                return
            new_key = str(payload.get("yandexApiKey") or "").strip()[:120]
            set_setting("yandex_api_key", new_key)
            self._send_json({"ok": True, "yandexApiKey": new_key})
            return

        if path == "/api/markers":
            if not is_admin:
                ok1, wait1 = check_rate_limit(f"mk_cool:{user['id']}", 1, 60)
                if not ok1:
                    self._send_json({"ok": False, "error": f"Защита от спама: следующую метку можно поставить через {wait1} сек."}, 429)
                    return
                ok2, _ = check_rate_limit(f"mk_hour:{user['id']}", 5, 3600)
                if not ok2:
                    self._send_json({"ok": False, "error": "Лимит: не более 5 меток в час"}, 429)
                    return
            try:
                if isinstance(payload.get("comments"), list) and payload["comments"]:
                    payload["comments"][0]["author"] = user["username"]
                m_id, dup_err, is_pending = upsert_marker(
                    payload,
                    check_duplicate=not is_admin,
                    created_by=user["id"],
                    is_admin=is_admin,
                )
                if dup_err:
                    self._send_json({"ok": False, "error": dup_err}, 409)
                    return
                resp_obj = {"ok": True, "id": m_id}
                if is_pending:
                    resp_obj["pendingModeration"] = True
                    resp_obj["status"] = "pending"
                    resp_obj["message"] = "Лимит новичка (2/час): метка отправлена на проверку админу"
                self._send_json(resp_obj, 201)
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, 400)
            return

        if path == "/api/markers/import":
            if not is_admin:
                self._send_json({"ok": False, "error": "Импорт доступен только администратору"}, 403)
                return
            arr = payload.get("markers") if isinstance(payload, dict) else []
            added = 0
            if isinstance(arr, list):
                for item in arr:
                    if isinstance(item, dict) and "lat" in item and "lng" in item:
                        try:
                            upsert_marker(item, check_duplicate=False, is_admin=True)
                            added += 1
                        except Exception:
                            pass
            self._send_json({"ok": True, "added": added})
            return

        parts = [p for p in path.split("/") if p]

        # Удаление комментария админом: POST /api/markers/<marker_id>/comments/delete
        if len(parts) == 5 and parts[0] == "api" and parts[1] == "markers" and parts[3] == "comments" and parts[4] == "delete":
            if not is_admin:
                self._send_json({"ok": False, "error": "Удалять комментарии может только администратор"}, 403)
                return
            marker_id = unquote(parts[2])
            res = delete_comment_admin(
                marker_id,
                payload.get("author"),
                payload.get("text"),
                payload.get("ts"),
            )
            self._send_json(res, 200 if res.get("ok") else 400)
            return

        # Админ: одобрение метки из очереди новичков: POST /api/admin/markers/<marker_id>/approve
        if len(parts) == 5 and parts[0] == "api" and parts[1] == "admin" and parts[2] == "markers" and parts[4] == "approve":
            if not is_admin:
                self._send_json({"ok": False, "error": "Доступ только для администратора"}, 403)
                return
            marker_id = unquote(parts[3])
            res = approve_pending_marker_admin(marker_id)
            self._send_json(res, 200 if res.get("ok") else 400)
            return

        # Админ: блокировка/разблокировка и теневой бан: POST /api/admin/users/<user_id>/(block|shadowban)
        if len(parts) == 5 and parts[0] == "api" and parts[1] == "admin" and parts[2] == "users":
            if not is_admin:
                self._send_json({"ok": False, "error": "Доступ только для администратора"}, 403)
                return
            target_uid = unquote(parts[3])
            sub_action = parts[4]
            if sub_action == "block":
                res = set_user_block_admin(
                    target_uid,
                    bool(payload.get("blocked")),
                    payload.get("durationHours"),
                    str(payload.get("reason") or "").strip(),
                )
                self._send_json(res)
                return
            if sub_action == "shadowban":
                res = set_user_shadowban_admin(
                    target_uid,
                    bool(payload.get("shadowbanned")),
                    payload.get("durationHours", 24),
                    str(payload.get("reason") or "").strip(),
                )
                self._send_json(res)
                return
            if sub_action == "delete":
                res = delete_user_admin(target_uid, user["id"])
                self._send_json(res, 200 if res.get("ok") else 400)
                return

        if len(parts) == 4 and parts[0] == "api" and parts[1] == "markers":
            marker_id = unquote(parts[2])
            action = parts[3]
            if action == "vote":
                if not is_admin:
                    ok1, wait1 = check_rate_limit(f"vote_cool:{user['id']}", 1, 30)
                    if not ok1:
                        self._send_json({"ok": False, "error": f"Таймаут: подтверждать можно раз в 30 сек. Подождите {wait1} сек."}, 429)
                        return
                    ok2, wait2 = check_rate_limit(f"vote_hour:{user['id']}", 15, 3600)
                    if not ok2:
                        self._send_json({"ok": False, "error": f"Лимит: не более 15 подтверждений в час. Подождите {max(1, wait2 // 60)} мин."}, 429)
                        return
                res = vote_marker(
                    marker_id,
                    f"user:{user['id']}",
                    payload.get("vote"),
                    user_id=user["id"],
                    is_admin=is_admin,
                )
                self._send_json(res, 200 if res.get("ok") else 409)
                return
            if action == "comment":
                if not is_admin:
                    ok1, wait1 = check_rate_limit(f"cmt_cool:{user['id']}", 1, 45)
                    if not ok1:
                        self._send_json({"ok": False, "error": f"Таймаут: следующий комментарий через {wait1} сек."}, 429)
                        return
                    ok2, wait2 = check_rate_limit(f"cmt_hour:{user['id']}", 10, 3600)
                    if not ok2:
                        self._send_json({"ok": False, "error": f"Лимит: не более 10 комментариев в час. Подождите {max(1, wait2 // 60)} мин."}, 429)
                        return
                res = add_comment(
                    marker_id,
                    user["username"],
                    payload.get("text"),
                    payload.get("ts"),
                    user_id=user["id"],
                    is_admin=is_admin,
                )
                self._send_json(res, 200 if res.get("ok") else 400)
                return
            if action == "edit":
                if not is_admin:
                    self._send_json({"ok": False, "error": "Редактировать метки может только администратор"}, 403)
                    return
                try:
                    res = update_marker_admin(marker_id, payload)
                    self._send_json(res, 200 if res.get("ok") else 400)
                except Exception as exc:
                    self._send_json({"ok": False, "error": str(exc)}, 400)
                return

        self._send_json({"ok": False, "error": "unknown_endpoint"}, 404)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "markers":
            user = self._current_user()
            if not user:
                self._send_json({"ok": False, "error": "Требуется авторизация"}, 401)
                return
            if user["role"] != "admin":
                self._send_json({"ok": False, "error": "Удалять метки может только администратор"}, 403)
                return
            marker_id = unquote(parts[2])
            self._send_json(delete_marker(marker_id))
            return
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "admin" and parts[2] == "users":
            user = self._current_user()
            if not user or user["role"] != "admin":
                self._send_json({"ok": False, "error": "Доступ только для администратора"}, 403)
                return
            target_uid = unquote(parts[3])
            res = delete_user_admin(target_uid, user["id"])
            self._send_json(res, 200 if res.get("ok") else 400)
            return
        self.send_error(404, "unknown_endpoint")

    def log_message(self, fmt, *args):
        print(f"[Fake Police] {self._client_ip()} - {fmt % args}")


if __name__ == "__main__":
    init_db()
    start_cleanup_thread()
    start_cloud_backup_thread()
    start_external_sync_thread()
    start_telegram_auth_polling_thread()
    server = ThreadingHTTPServer((HOST, PORT), FakePoliceHandler)

    def _handle_sigterm(signum, frame):
        flush_cloud_backup_if_dirty()
        raise SystemExit(0)

    try:
        signal.signal(signal.SIGTERM, _handle_sigterm)
    except Exception:
        pass

    print(f"Fake Police сервер запущен: http://localhost:{PORT}", flush=True)
    print(f"Веб-админка для ПК: http://localhost:{PORT}/admin", flush=True)
    print(
        f"База данных: {DB_PATH} (WAL) | Админ: {ADMIN_USERNAME or 'не задан'} | "
        f"Gist-бэкап: {'ВКЛ (раз в ' + str(BACKUP_INTERVAL_SEC // 60) + ' мин)' if (GITHUB_TOKEN and BACKUP_GIST_ID) else 'ВЫКЛ'}",
        flush=True,
    )
    try:
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        flush_cloud_backup_if_dirty()
        print("\nСервер остановлен.")
