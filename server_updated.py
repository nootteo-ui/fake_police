#!/usr/bin/env python3
"""
Fake Police — сервер с синхронизацией меток, авторизацией (user/admin),
общим API-ключом Яндекс Карт (управляется админом) и защитой от спама.
Только стандартный Python 3 + SQLite (без сторонних библиотек).
Запуск: python server.py
"""

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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8000"))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "fake_police.db")
INDEX_PATH = os.path.join(BASE_DIR, "index.html")

ADMIN_USERNAME = os.environ.get("ADMIN_USER", "").strip()
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
DEFAULT_YANDEX_KEY = os.environ.get("YANDEX_API_KEY", "").strip()
SESSION_TTL_SEC = 30 * 24 * 3600  # 30 дней

DB_LOCK = threading.Lock()
RATE_LOCK = threading.Lock()
RATE_BUCKETS = defaultdict(deque)


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


def init_db():
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
                confirmations INTEGER NOT NULL DEFAULT 1,
                dismissals INTEGER NOT NULL DEFAULT 0,
                comments_json TEXT NOT NULL DEFAULT '[]'
            )
            """
        )
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
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_at INTEGER NOT NULL
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
        if DEFAULT_YANDEX_KEY:
            existing_key = conn.execute("SELECT value FROM settings WHERE key = 'yandex_api_key'").fetchone()
            if not existing_key:
                conn.execute(
                    "INSERT INTO settings (key, value, updated_at) VALUES ('yandex_api_key', ?, ?)",
                    (DEFAULT_YANDEX_KEY, int(time.time() * 1000)),
                )
        # Удаляем старых админов, если логин сменился, и создаём/обновляем актуального только из переменных среды
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


def create_session(user_id):
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
            (token, user_id, now + SESSION_TTL_SEC, now),
        )
        conn.commit()
    return token


def get_user_by_token(token):
    if not token:
        return None
    now = int(time.time())
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            """
            SELECT u.id, u.username, u.role, s.expires_at
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
        return {"id": row[0], "username": row[1], "role": row[2]}


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
    return {"ok": True, "token": token, "user": {"id": user_id, "username": username, "role": "user"}}


def login_user(username, password):
    username = str(username or "").strip()
    password = str(password or "")
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT id, username, password_hash, salt, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if not row or not verify_password(password, row[3], row[2]):
        return {"ok": False, "error": "Неверный логин или пароль"}
    token = create_session(row[0])
    return {"ok": True, "token": token, "user": {"id": row[0], "username": row[1], "role": row[4]}}


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
    }


def list_markers(voter_key=""):
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            """
            SELECT id, type, lat, lng, address, created_at, last_confirmed_at,
                   confirmations, dismissals, comments_json
            FROM markers
            ORDER BY last_confirmed_at DESC
            """
        ).fetchall()
        votes = {}
        if voter_key:
            vrows = conn.execute(
                "SELECT marker_id, vote FROM marker_votes WHERE device_id = ?",
                (voter_key,),
            ).fetchall()
            votes = {r[0]: r[1] for r in vrows}
    return [row_to_marker(r) for r in rows], votes


def upsert_marker(data, check_duplicate=True):
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
    confirmations = max(1, int(data.get("confirmations") or 1))
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

        conn.execute(
            """
            INSERT OR IGNORE INTO markers
            (id, type, lat, lng, address, created_at, last_confirmed_at, confirmations, dismissals, comments_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (m_id, m_type, lat, lng, address, created_at, last_confirmed_at, confirmations, dismissals, comments_json),
        )
        conn.commit()
    return m_id, None


def vote_marker(marker_id, voter_key, vote):
    if vote not in ("confirm", "dismiss"):
        return {"ok": False, "error": "invalid_vote"}
    now = int(time.time() * 1000)
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT confirmations, dismissals FROM markers WHERE id = ?",
            (marker_id,),
        ).fetchone()
        if not row:
            return {"ok": False, "error": "not_found"}

        existing = conn.execute(
            "SELECT vote FROM marker_votes WHERE marker_id = ? AND device_id = ?",
            (marker_id, voter_key),
        ).fetchone()
        if existing:
            return {"ok": False, "error": "already_voted", "vote": existing[0]}

        conn.execute(
            "INSERT INTO marker_votes (marker_id, device_id, vote, created_at) VALUES (?, ?, ?, ?)",
            (marker_id, voter_key, vote, now),
        )
        confirmations, dismissals = row[0], row[1]
        if vote == "confirm":
            confirmations += 1
            conn.execute(
                "UPDATE markers SET confirmations = ?, last_confirmed_at = ? WHERE id = ?",
                (confirmations, now, marker_id),
            )
        else:
            dismissals += 1
            if dismissals >= 3 and dismissals >= confirmations:
                conn.execute("DELETE FROM markers WHERE id = ?", (marker_id,))
                conn.execute("DELETE FROM marker_votes WHERE marker_id = ?", (marker_id,))
                conn.commit()
                return {"ok": True, "removed": True}
            conn.execute(
                "UPDATE markers SET dismissals = ? WHERE id = ?",
                (dismissals, marker_id),
            )
        conn.commit()
    return {"ok": True, "confirmations": confirmations, "dismissals": dismissals}


def add_comment(marker_id, author, text, ts=None):
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
        conn.commit()
    return {"ok": True}


def delete_marker(marker_id):
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM markers WHERE id = ?", (marker_id,))
        conn.execute("DELETE FROM marker_votes WHERE marker_id = ?", (marker_id,))
        conn.commit()
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
            markers, votes = list_markers(voter_key)
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

        # --- Авторизация ---
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

        # --- Защищённые действия ---
        user = self._current_user()
        if not user:
            self._send_json({"ok": False, "error": "Войдите в аккаунт для этого действия"}, 401)
            return

        is_admin = user["role"] == "admin"

        # --- Общий API-ключ Яндекса (только админ) ---
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
                m_id, dup_err = upsert_marker(payload, check_duplicate=not is_admin)
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
                ok, wait = check_rate_limit(f"vote:{user['id']}", 30, 3600)
                if not ok:
                    self._send_json({"ok": False, "error": f"Слишком частые голоса. Подождите {wait} сек."}, 429)
                    return
                res = vote_marker(marker_id, f"user:{user['id']}", payload.get("vote"))
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
                res = add_comment(marker_id, user["username"], payload.get("text"), payload.get("ts"))
                self._send_json(res, 200 if res.get("ok") else 400)
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
        self._send_json({"ok": False, "error": "unknown_endpoint"}, 404)

    def log_message(self, fmt, *args):
        print(f"[Fake Police] {self._client_ip()} - {fmt % args}")


if __name__ == "__main__":
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), FakePoliceHandler)
    print(f"Fake Police сервер запущен: http://localhost:{PORT}", flush=True)
    print(f"База данных: {DB_PATH} | Админ: {ADMIN_USERNAME or 'не задан'}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nСервер остановлен.")
