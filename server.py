#!/usr/bin/env python3
"""
Fake Police — сервер с синхронизацией меток, авторизацией (user/admin),
общим API-ключом Яндекс Карт (управляется админом), защитой от спама,
фоновой ретрансляцией внешних точек ДПС, их комментариев и уведомлениями в Telegram.
Только стандартный Python 3 + SQLite (без сторонних библиотек).
Запуск: python server.py
"""

import gzip
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse
from urllib.request import Request, urlopen

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8000"))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "fake_police.db")).strip() or os.path.join(BASE_DIR, "fake_police.db")
INDEX_PATH = os.path.join(BASE_DIR, "index.html")

# ================= НАСТРОЙКИ ВНЕШНЕЙ СИНХРОНИЗАЦИИ И TELEGRAM =================
EXT_SYNC_ENABLED = True
EXT_API_BASE = "https://new-prod-api.easyroutes.ru/mobile_api/v2/posts"
EXT_API_URL = f"{EXT_API_BASE}/cached?key=0"
EXT_SYNC_INTERVAL = 25          # секунд между опросами списка точек
EXT_COMMENTS_MAX_PER_CYCLE = 15 # максимум запросов к /comments за один цикл (защита от бана)
EXT_COMMENTS_DELAY_SEC = 0.2    # пауза между запросами комментариев
EXT_PREFIX = "ext-er-"

# Вставь свой токен и chat_id (или задай переменные окружения TG_BOT_TOKEN и TG_CHAT_ID)
TG_NOTIFY_ENABLED = True
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "ВСТАВЬ_СВОЙ_ТОКЕН_СЮДА").strip()
TG_CHAT_ID = os.environ.get("TG_CHAT_ID", "ВСТАВЬ_СВОЙ_CHAT_ID_СЮДА").strip()
# ==============================================================================

# Облачный автобэкап в приватный GitHub Gist (чтобы Render Free не сбрасывал базу после перезагрузки)
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()
BACKUP_GIST_ID = os.environ.get("BACKUP_GIST_ID", "").strip()
BACKUP_FILENAME = "fake_police_backup.json"
BACKUP_LOCK = threading.Lock()
BACKUP_TIMER = None

ADMIN_USERNAME = os.environ.get("ADMIN_USER", "").strip()
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
DEFAULT_YANDEX_KEY = os.environ.get("YANDEX_API_KEY", "").strip()
SESSION_TTL_SEC = 30 * 24 * 3600  # 30 дней

DB_LOCK = threading.Lock()
RATE_LOCK = threading.Lock()
RATE_BUCKETS = defaultdict(deque)

# Кэш внешних комментариев в памяти: {raw_post_id: {"count": int, "comments": list}}
EXT_COMMENTS_CACHE = {}


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
                "SELECT id, username, password_hash, salt, role, created_at, rating, markers_count, votes_count, comments_count FROM users"
            ).fetchall(),
            "sessions": conn.execute(
                "SELECT token, user_id, expires_at, created_at FROM sessions"
            ).fetchall(),
            "markers": conn.execute(
                """
                SELECT id, type, lat, lng, address, created_at, last_confirmed_at,
                       confirmations, dismissals, comments_json, created_by
                FROM markers
                WHERE id NOT LIKE ?
                """,
                (f"{EXT_PREFIX}%",),
            ).fetchall(),
            "marker_votes": conn.execute(
                "SELECT marker_id, device_id, vote, created_at FROM marker_votes WHERE marker_id NOT LIKE ?",
                (f"{EXT_PREFIX}%",),
            ).fetchall(),
            "settings": conn.execute(
                "SELECT key, value, updated_at FROM settings"
            ).fetchall(),
            "saved_at": int(time.time() * 1000),
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
    global BACKUP_TIMER
    if not (GITHUB_TOKEN and BACKUP_GIST_ID):
        return
    with BACKUP_LOCK:
        if BACKUP_TIMER is not None:
            BACKUP_TIMER.cancel()
        BACKUP_TIMER = threading.Timer(2.0, push_cloud_backup)
        BACKUP_TIMER.daemon = True
        BACKUP_TIMER.start()


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
                padded = list(row) + [0] * max(0, 10 - len(row))
                conn.execute(
                    """
                    INSERT OR IGNORE INTO users
                    (id, username, password_hash, salt, role, created_at, rating, markers_count, votes_count, comments_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    padded[:10],
                )
            for row in snap.get("sessions") or []:
                conn.execute(
                    "INSERT OR IGNORE INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
                    row[:4],
                )
            for row in snap.get("markers") or []:
                padded = list(row) + [None] * max(0, 11 - len(row))
                conn.execute(
                    """
                    INSERT OR IGNORE INTO markers
                    (id, type, lat, lng, address, created_at, last_confirmed_at, confirmations, dismissals, comments_json, created_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    padded[:11],
                )
            for row in snap.get("marker_votes") or []:
                conn.execute(
                    "INSERT OR IGNORE INTO marker_votes (marker_id, device_id, vote, created_at) VALUES (?, ?, ?, ?)",
                    row[:4],
                )
            for row in snap.get("settings") or []:
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
                    row[:3],
                )
            conn.commit()
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
    with sqlite3.connect(DB_PATH) as conn:
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
                created_by INTEGER DEFAULT NULL
            )
            """
        )
        try:
            conn.execute("ALTER TABLE markers ADD COLUMN created_by INTEGER DEFAULT NULL")
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
                comments_count INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        for col_def in (
            "rating INTEGER NOT NULL DEFAULT 0",
            "markers_count INTEGER NOT NULL DEFAULT 0",
            "votes_count INTEGER NOT NULL DEFAULT 0",
            "comments_count INTEGER NOT NULL DEFAULT 0",
        ):
            try:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col_def}")
            except sqlite3.OperationalError:
                pass
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
        if DEFAULT_YANDEX_KEY:
            existing_key = conn.execute("SELECT value FROM settings WHERE key = 'yandex_api_key'").fetchone()
            if not existing_key:
                conn.execute(
                    "INSERT INTO settings (key, value, updated_at) VALUES ('yandex_api_key', ?, ?)",
                    (DEFAULT_YANDEX_KEY, int(time.time() * 1000)),
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
                    (ADMIN_USERNAME, pwd_hash, salt, int(time.time() * 1000)),
                )
            else:
                conn.execute(
                    "UPDATE users SET password_hash = ?, salt = ?, role = 'admin' WHERE id = ?",
                    (pwd_hash, salt, row[0]),
                )
        conn.commit()


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


def fetch_external_comments(raw_post_id, now_ms):
    """Загружает видимые комментарии для конкретной точки по её ID."""
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
        ts = parse_iso_ms(c.get("created_at"), now_ms)
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

    now_ms = int(time.time() * 1000)
    active_ids = []
    active_raw_ids = set()
    to_notify = []

    # 1. Вне блокировки БД аккуратно докачиваем комментарии только для точек с новыми комментариями
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
            ext_cmts = fetch_external_comments(raw_id, now_ms)
            EXT_COMMENTS_CACHE[raw_id] = {"count": c_count, "comments": ext_cmts}
            fetched_comments_count += 1
            time.sleep(EXT_COMMENTS_DELAY_SEC)
        except Exception as exc:
            print(f"[Fake Police] Ошибка загрузки комментариев для поста {raw_id}: {exc}", flush=True)

    # Очищаем кэш от исчезнувших точек
    for old_id in list(EXT_COMMENTS_CACHE.keys()):
        if old_id not in active_raw_ids:
            EXT_COMMENTS_CACHE.pop(old_id, None)

    # 2. Записываем актуальные точки, статистику и комментарии в SQLite с учётом локальных правок (ext_overrides)
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        first_run = conn.execute("SELECT COUNT(*) FROM ext_notified").fetchone()[0] == 0

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
                # Метка была удалена админом на нашем сайте — не возвращаем её
                continue

            m_type = ov["type_override"] if (ov and ov["type_override"]) else "dps"
            lat_f = float(ov["lat_override"]) if (ov and ov["lat_override"] is not None) else float(lat)
            lng_f = float(ov["lng_override"]) if (ov and ov["lng_override"] is not None) else float(lon)
            address = (
                ov["address_override"]
                if (ov and ov["address_override"])
                else str(item.get("address") or f"{lat_f:.4f}, {lng_f:.4f}")[:240]
            )

            created_at = parse_iso_ms(item.get("created_at"), now_ms)
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

            # Разбираем существующие комментарии из БД: сохраняем локальные комментарии пользователей сайта
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
            ext_comments = cached_entry["comments"] if cached_entry is not None else prev_ext_comments

            # Собираем итоговый список: описание админа (если задано) / сводка, затем внешние + локальные комментарии
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
                (id, type, lat, lng, address, created_at, last_confirmed_at, confirmations, dismissals, comments_json, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
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
                    (marker_id, now_ms),
                )
                if not first_run:
                    to_notify.append((item, ext_comments))

        # Удаляем внешние точки и их локальные переопределения, если они исчезли с исходного сервера
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
        conn.commit()

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
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row[0] if row else default


def set_setting(key, value):
    now = int(time.time() * 1000)
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (key, str(value or ""), now),
        )
        conn.commit()
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


def format_user_dict(uid, username, role, rating=0, markers_count=0, votes_count=0, comments_count=0):
    return {
        "id": uid,
        "username": username,
        "role": role,
        "rating": int(rating or 0),
        "markersCount": int(markers_count or 0),
        "votesCount": int(votes_count or 0),
        "commentsCount": int(comments_count or 0),
    }


def award_user_rating(conn, user_id, points=0, markers_delta=0, votes_delta=0, comments_delta=0):
    if user_id is None:
        return
    conn.execute(
        """
        UPDATE users
        SET rating = MAX(0, rating + ?),
            markers_count = MAX(0, markers_count + ?),
            votes_count = MAX(0, votes_count + ?),
            comments_count = MAX(0, comments_count + ?)
        WHERE id = ?
        """,
        (int(points), int(markers_delta), int(votes_delta), int(comments_delta), int(user_id)),
    )


def get_user_by_token(token):
    if not token:
        return None
    now = int(time.time())
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            """
            SELECT u.id, u.username, u.role, s.expires_at,
                   u.rating, u.markers_count, u.votes_count, u.comments_count
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token = ?
            """,
            (token,),
        ).fetchone()
        if not row:
            return None
        if row[3] < now:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
            return None
        return format_user_dict(row[0], row[1], row[2], row[4], row[5], row[6], row[7])


def register_user(username, password):
    username = str(username or "").strip()
    password = str(password or "")
    if not re.match(r"^[A-Za-zА-Яа-яЁё0-9_.-]{3,24}$", username):
        return {"ok": False, "error": "Логин: от 3 до 24 символов (буквы, цифры, _ . -)"}
    if len(password) < 6 or len(password) > 64:
        return {"ok": False, "error": "Пароль должен быть от 6 до 64 символов"}

    salt, pwd_hash = hash_password(password)
    now_ms = int(time.time() * 1000)
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        try:
            cur = conn.execute(
                "INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, 'user', ?)",
                (username, pwd_hash, salt, now_ms),
            )
            user_id = cur.lastrowid
            conn.commit()
        except sqlite3.IntegrityError:
            return {"ok": False, "error": "Такой логин уже занят"}
    token = create_session(user_id)
    return {"ok": True, "token": token, "user": format_user_dict(user_id, username, "user", 0, 0, 0, 0)}


def login_user(username, password):
    username = str(username or "").strip()
    password = str(password or "")
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT id, username, password_hash, salt, role, rating, markers_count, votes_count, comments_count FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if not row or not verify_password(password, row[3], row[2]):
        return {"ok": False, "error": "Неверный логин или пароль"}
    token = create_session(row[0])
    return {
        "ok": True,
        "token": token,
        "user": format_user_dict(row[0], row[1], row[4], row[5], row[6], row[7], row[8]),
    }


def logout_token(token):
    if not token:
        return
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()


def row_to_marker(row):
    try:
        comments = json.loads(row[9] or "[]")
        if not isinstance(comments, list):
            comments = []
        for c in comments:
            if isinstance(c, dict) and str(c.get("author") or "").strip().lower() == "безымянный райдер":
                c["author"] = "Пользователь"
    except Exception:
        comments = []
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


DPS_EXPIRE_MS = 3 * 3600 * 1000  # 3 часа без подтверждения (для ручных меток)


def cleanup_expired_dps(conn):
    cutoff = int(time.time() * 1000) - DPS_EXPIRE_MS
    expired = conn.execute(
        "SELECT id FROM markers WHERE type = 'dps' AND id NOT LIKE ? AND last_confirmed_at < ?",
        (f"{EXT_PREFIX}%", cutoff),
    ).fetchall()
    if expired:
        ids = [r[0] for r in expired]
        placeholders = ",".join("?" for _ in ids)
        conn.execute(f"DELETE FROM markers WHERE id IN ({placeholders})", ids)
        conn.execute(f"DELETE FROM marker_votes WHERE marker_id IN ({placeholders})", ids)
        conn.commit()


def list_markers(voter_key="", include_author=False):
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        cleanup_expired_dps(conn)
        rows = conn.execute(
            """
            SELECT m.id, m.type, m.lat, m.lng, m.address, m.created_at, m.last_confirmed_at,
                   m.confirmations, m.dismissals, m.comments_json, m.created_by, u.username
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
        item = row_to_marker(r)
        if include_author:
            if str(r[0]).startswith(EXT_PREFIX):
                item["createdByUsername"] = "Автосинк API"
            else:
                item["createdByUsername"] = r[11] if len(r) > 11 and r[11] else "Неизвестно"
        result.append(item)
    return result, votes


def upsert_marker(data, check_duplicate=True, created_by=None):
    now = int(time.time() * 1000)
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
    comments_json = json.dumps(comments[:50], ensure_ascii=False)

    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        if check_duplicate:
            recent = conn.execute(
                "SELECT lat, lng FROM markers WHERE type = ? AND created_at > ?",
                (m_type, now - 15 * 60 * 1000),
            ).fetchall()
            for r_lat, r_lng in recent:
                if haversine_m(lat, lng, r_lat, r_lng) < 100:
                    return None, "Рядом (в пределах 100 м) уже есть такая свежая метка"

        cur = conn.execute(
            """
            INSERT OR IGNORE INTO markers
            (id, type, lat, lng, address, created_at, last_confirmed_at, confirmations, dismissals, comments_json, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (m_id, m_type, lat, lng, address, created_at, last_confirmed_at, confirmations, dismissals, comments_json, created_by),
        )
        if cur.rowcount > 0 and created_by is not None:
            award_user_rating(conn, created_by, points=10, markers_delta=1)
        conn.commit()
    schedule_cloud_backup()
    return m_id, None


def vote_marker(marker_id, voter_key, vote, user_id=None, is_admin=False):
    if vote not in ("confirm", "dismiss"):
        return {"ok": False, "error": "invalid_vote"}
    now = int(time.time() * 1000)
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT confirmations, dismissals, created_by FROM markers WHERE id = ?",
            (marker_id,),
        ).fetchone()
        if not row:
            return {"ok": False, "error": "not_found"}

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
        confirmations, dismissals = row[0], row[1]
        is_ext = marker_id.startswith(EXT_PREFIX)
        if vote == "confirm":
            confirmations += 1
            conn.execute(
                "UPDATE markers SET confirmations = ?, last_confirmed_at = ? WHERE id = ?",
                (confirmations, now, marker_id),
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
            if not is_ext and dismissals >= 3 and dismissals >= confirmations:
                conn.execute("DELETE FROM markers WHERE id = ?", (marker_id,))
                conn.execute("DELETE FROM marker_votes WHERE marker_id = ?", (marker_id,))
                if user_id is not None:
                    award_user_rating(conn, user_id, points=2, votes_delta=1)
                conn.commit()
                schedule_cloud_backup()
                return {"ok": True, "removed": True}
            conn.execute(
                "UPDATE markers SET dismissals = ? WHERE id = ?",
                (dismissals, marker_id),
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
            if vote == "confirm" and row[2] is not None and int(row[2]) != int(user_id):
                award_user_rating(conn, row[2], points=5)
        conn.commit()
    schedule_cloud_backup()
    return {"ok": True, "confirmations": confirmations, "dismissals": dismissals}


def add_comment(marker_id, author, text, ts=None, user_id=None):
    clean_text = str(text or "").strip()[:400]
    if not clean_text:
        return {"ok": False, "error": "Пустой комментарий"}
    clean_author = str(author or "Водитель").strip()[:40] or "Водитель"
    ts_val = int(ts or int(time.time() * 1000))
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT comments_json FROM markers WHERE id = ?",
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
        comments.append({"author": clean_author, "text": clean_text, "ts": ts_val})
        conn.execute(
            "UPDATE markers SET comments_json = ? WHERE id = ?",
            (json.dumps(comments[-50:], ensure_ascii=False), marker_id),
        )
        if user_id is not None:
            award_user_rating(conn, user_id, points=3, comments_delta=1)
        conn.commit()
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
                    comments.append({"author": "Админ", "text": desc, "ts": int(time.time() * 1000)})
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
            now_ms = int(time.time() * 1000)
            conn.execute(
                "INSERT OR IGNORE INTO ext_overrides (marker_id, updated_at) VALUES (?, ?)",
                (marker_id, now_ms),
            )
            if "type" in data and str(data["type"]) in ("dps", "dtp", "camera", "works"):
                conn.execute("UPDATE ext_overrides SET type_override = ?, updated_at = ? WHERE marker_id = ?", (m_type, now_ms, marker_id))
            if "lat" in data and "lng" in data:
                conn.execute("UPDATE ext_overrides SET lat_override = ?, lng_override = ?, updated_at = ? WHERE marker_id = ?", (lat, lng, now_ms, marker_id))
            if "address" in data and str(data["address"] or "").strip():
                conn.execute("UPDATE ext_overrides SET address_override = ?, updated_at = ? WHERE marker_id = ?", (address, now_ms, marker_id))
            if "description" in data:
                desc_val = str(data["description"] or "").strip()[:400]
                conn.execute("UPDATE ext_overrides SET desc_override = ?, updated_at = ? WHERE marker_id = ?", (desc_val, now_ms, marker_id))
            if "confirmations" in data and data["confirmations"] is not None:
                # Сохраняем базовое значение с учётом уже отданных локальных голосов, чтобы при следующем синке вышло ровно confirmations
                local_conf = conn.execute(
                    "SELECT COUNT(*) FROM marker_votes WHERE marker_id = ? AND vote = 'confirm'",
                    (marker_id,),
                ).fetchone()[0]
                conn.execute(
                    "UPDATE ext_overrides SET conf_override = ?, admin_conf_delta = 0, updated_at = ? WHERE marker_id = ?",
                    (max(0, confirmations - local_conf), now_ms, marker_id),
                )
        conn.commit()
    if not marker_id.startswith(EXT_PREFIX):
        schedule_cloud_backup()
    return {"ok": True}


def delete_marker(marker_id):
    now_ms = int(time.time() * 1000)
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM markers WHERE id = ?", (marker_id,))
        conn.execute("DELETE FROM marker_votes WHERE marker_id = ?", (marker_id,))
        if marker_id.startswith(EXT_PREFIX):
            conn.execute(
                """
                INSERT INTO ext_overrides (marker_id, deleted, updated_at)
                VALUES (?, 1, ?)
                ON CONFLICT(marker_id) DO UPDATE SET deleted = 1, updated_at = excluded.updated_at
                """,
                (marker_id, now_ms),
            )
        conn.commit()
    if not marker_id.startswith(EXT_PREFIX):
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

    def _send_json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0 or length > 2_000_000:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def _serve_html(self):
        if not os.path.exists(INDEX_PATH):
            self.send_error(404, "index.html not found")
            return
        with open(INDEX_PATH, "r", encoding="utf-8") as f:
            html = f.read()
        inject = "<script>window.__FP_SYNC_ENABLED__ = true;</script>\n</head>"
        if "</head>" in html:
            html = html.replace("</head>", inject, 1)
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
        if path in ("/", "/index.html", "/fake_police.html", "/yandex_navigator.html"):
            self._serve_html()
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
            qs = parse_qs(parsed.query)
            voter_key = f"user:{user['id']}" if user else (qs.get("deviceId") or [""])[0][:80]
            markers, votes = list_markers(voter_key, include_author=bool(user and user["role"] == "admin"))
            self._send_json({
                "markers": markers,
                "userVotes": votes,
                "yandexApiKey": get_setting("yandex_api_key", ""),
            })
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

        if path == "/api/auth/register":
            ok, wait = check_rate_limit(f"auth:{ip}", 10, 300)
            if not ok:
                self._send_json({"ok": False, "error": f"Слишком много попыток. Подождите {wait} сек."}, 429)
                return
            res = register_user(payload.get("username"), payload.get("password"))
            self._send_json(res, 201 if res.get("ok") else 400)
            return

        if path == "/api/auth/login":
            ok, wait = check_rate_limit(f"auth:{ip}", 10, 300)
            if not ok:
                self._send_json({"ok": False, "error": f"Слишком много попыток. Подождите {wait} сек."}, 429)
                return
            res = login_user(payload.get("username"), payload.get("password"))
            self._send_json(res, 200 if res.get("ok") else 401)
            return

        if path == "/api/auth/logout":
            logout_token(self._bearer_token())
            self._send_json({"ok": True})
            return

        user = self._current_user()
        if not user:
            self._send_json({"ok": False, "error": "Войдите в аккаунт для этого действия"}, 401)
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
                m_id, dup_err = upsert_marker(payload, check_duplicate=not is_admin, created_by=user["id"])
                if dup_err:
                    self._send_json({"ok": False, "error": dup_err}, 409)
                    return
                self._send_json({"ok": True, "id": m_id}, 201)
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
                            upsert_marker(item, check_duplicate=False)
                            added += 1
                        except Exception:
                            pass
            self._send_json({"ok": True, "added": added})
            return

        parts = [p for p in path.split("/") if p]
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "markers":
            marker_id = unquote(parts[2])
            action = parts[3]
            if action == "vote":
                if not is_admin:
                    ok, wait = check_rate_limit(f"vote:{user['id']}", 30, 3600)
                    if not ok:
                        self._send_json({"ok": False, "error": f"Слишком частые голоса. Подождите {wait} сек."}, 429)
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
                    ok1, wait1 = check_rate_limit(f"cmt_cool:{user['id']}", 1, 15)
                    if not ok1:
                        self._send_json({"ok": False, "error": f"Подождите {wait1} сек. перед следующим комментарием"}, 429)
                        return
                    ok2, _ = check_rate_limit(f"cmt_hour:{user['id']}", 20, 3600)
                    if not ok2:
                        self._send_json({"ok": False, "error": "Лимит: не более 20 комментариев в час"}, 429)
                        return
                res = add_comment(marker_id, user["username"], payload.get("text"), payload.get("ts"), user_id=user["id"])
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
        self.send_error(404, "unknown_endpoint")

    def log_message(self, fmt, *args):
        print(f"[Fake Police] {self._client_ip()} - {fmt % args}")


if __name__ == "__main__":
    init_db()
    start_external_sync_thread()
    server = ThreadingHTTPServer((HOST, PORT), FakePoliceHandler)
    print(f"Fake Police сервер запущен: http://localhost:{PORT}", flush=True)
    print(f"База данных: {DB_PATH} | Админ: {ADMIN_USERNAME or 'не задан'} | Gist-бэкап: {'ВКЛ' if (GITHUB_TOKEN and BACKUP_GIST_ID) else 'ВЫКЛ'}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nСервер остановлен.")
