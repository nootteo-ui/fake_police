#!/usr/bin/env python3
"""
Fake Police — лёгкий локальный сервер с синхронизацией меток ДПС / ДТП между всеми устройствами.
Не требует установки сторонних библиотек (только стандартный Python 3 + SQLite).
Запуск: python server.py
"""

import json
import os
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8000"))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "fake_police.db")
INDEX_PATH = os.path.join(BASE_DIR, "index.html")
DB_LOCK = threading.Lock()


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


def list_markers(device_id=""):
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
        if device_id:
            vrows = conn.execute(
                "SELECT marker_id, vote FROM marker_votes WHERE device_id = ?",
                (device_id,),
            ).fetchall()
            votes = {r[0]: r[1] for r in vrows}
    return [row_to_marker(r) for r in rows], votes


def upsert_marker(data):
    now = int(time.time() * 1000)
    m_id = str(data.get("id") or f"mk-{now}")[:80]
    m_type = str(data.get("type") or "dps")
    if m_type not in ("dps", "dtp", "camera", "works"):
        m_type = "dps"
    lat = float(data["lat"])
    lng = float(data["lng"])
    address = str(data.get("address") or f"{lat:.4f}, {lng:.4f}")[:240]
    created_at = int(data.get("createdAt") or now)
    last_confirmed_at = int(data.get("lastConfirmedAt") or created_at)
    confirmations = max(1, int(data.get("confirmations") or 1))
    dismissals = max(0, int(data.get("dismissals") or 0))
    comments = data.get("comments") if isinstance(data.get("comments"), list) else []
    comments_json = json.dumps(comments[:50], ensure_ascii=False)

    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO markers
            (id, type, lat, lng, address, created_at, last_confirmed_at, confirmations, dismissals, comments_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (m_id, m_type, lat, lng, address, created_at, last_confirmed_at, confirmations, dismissals, comments_json),
        )
        conn.commit()
    return m_id


def vote_marker(marker_id, device_id, vote):
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
            (marker_id, device_id),
        ).fetchone()
        if existing:
            return {"ok": False, "error": "already_voted", "vote": existing[0]}

        conn.execute(
            "INSERT INTO marker_votes (marker_id, device_id, vote, created_at) VALUES (?, ?, ?, ?)",
            (marker_id, device_id, vote, now),
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
        return {"ok": False, "error": "empty_comment"}
    clean_author = str(author or "Водитель").strip()[:40] or "Водитель"
    ts_val = int(ts or int(time.time() * 1000))
    with DB_LOCK, sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT comments_json FROM markers WHERE id = ?",
            (marker_id,),
        ).fetchone()
        if not row:
            return {"ok": False, "error": "not_found"}
        try:
            comments = json.loads(row[0] or "[]")
        except Exception:
            comments = []
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
        if path == "/api/markers":
            qs = parse_qs(parsed.query)
            device_id = (qs.get("deviceId") or [""])[0][:80]
            markers, votes = list_markers(device_id)
            self._send_json({"markers": markers, "userVotes": votes})
            return
        self.send_error(404, "Not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            payload = self._read_json()
        except Exception:
            self._send_json({"ok": False, "error": "invalid_json"}, 400)
            return

        if path == "/api/markers":
            try:
                m_id = upsert_marker(payload)
                self._send_json({"ok": True, "id": m_id}, 201)
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, 400)
            return

        if path == "/api/markers/import":
            arr = payload.get("markers") if isinstance(payload, dict) else []
            added = 0
            if isinstance(arr, list):
                for item in arr:
                    if isinstance(item, dict) and "lat" in item and "lng" in item:
                        try:
                            upsert_marker(item)
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
                device_id = str(payload.get("deviceId") or self.client_address[0])[:80]
                res = vote_marker(marker_id, device_id, payload.get("vote"))
                self._send_json(res, 200 if res.get("ok") else 409)
                return
            if action == "comment":
                res = add_comment(marker_id, payload.get("author"), payload.get("text"), payload.get("ts"))
                self._send_json(res, 200 if res.get("ok") else 400)
                return

        self._send_json({"ok": False, "error": "unknown_endpoint"}, 404)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "markers":
            marker_id = unquote(parts[2])
            self._send_json(delete_marker(marker_id))
            return
        self._send_json({"ok": False, "error": "unknown_endpoint"}, 404)

    def log_message(self, fmt, *args):
        print(f"[Fake Police] {self.address_string()} - {fmt % args}")


if __name__ == "__main__":
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), FakePoliceHandler)
    print(f"Fake Police сервер запущен: http://localhost:{PORT}")
    print(f"База данных меток: {DB_PATH}")
    print("Не закрывайте это окно, пока работает сайт.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nСервер остановлен.")
