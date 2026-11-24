"""
Модуль бэкенда (FastAPI + SQLite) для AIRoute v22:
1. Раздача ПК веб-админки по адресу GET /admin (файл web/admin.html)
2. Удаление комментариев админом: POST /api/markers/{marker_id}/comments/delete
   (работает и с JSON-колонкой comments_json / comments, и с отдельной таблицей marker_comments)
3. Вход и регистрация по Email с 6-значным кодом подтверждения (SMTP + dev-вывод в консоль)
4. Песочница ранга «Новичок» (rating < 45):
   - До 2 активных меток в час, остальные уходят со статусом 'pending' на проверку админа
   - Голос «Нет на месте» от новичка имеет вес 0.34 (нужно 3 новичка против подтверждения Штурмана/Патрульного)
   - Комментарии разрешены после >= 1 подтверждённой метки ИЛИ >= 12 часов с регистрации
5. Автоматический (при рейтинге < 0 или > 80% отклонённых меток) и ручной временный теневой бан (Shadowban)
6. Админ-API: очередь меток новичков, список юзеров, журнал действий, бан/разбан и теневой бан на срок
"""

import json
import os
import random
import secrets
import smtplib
import sqlite3
import time
from email.message import EmailMessage
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

DB_PATH = os.getenv("AIROUTE_DB_PATH", "airoute.db")
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER or "noreply@airoute.app")

router = APIRouter()


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def now_ms() -> int:
    return int(time.time() * 1000)


def init_antifraud_schema() -> None:
    conn = get_db()
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS email_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            purpose TEXT NOT NULL,
            code TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS user_actions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            action_type TEXT NOT NULL,
            title TEXT NOT NULL,
            details TEXT DEFAULT '',
            lat REAL,
            lng REAL,
            ts INTEGER NOT NULL
        );
        """
    )
    user_cols = {
        "email": "TEXT DEFAULT ''",
        "created_at": "INTEGER DEFAULT 0",
        "device_id": "TEXT DEFAULT ''",
        "confirmed_markers": "INTEGER DEFAULT 0",
        "rejected_markers": "INTEGER DEFAULT 0",
        "is_blocked": "INTEGER DEFAULT 0",
        "blocked_until": "INTEGER",
        "shadowbanned": "INTEGER DEFAULT 0",
        "shadowbanned_until": "INTEGER",
    }
    existing_u = {r[1] for r in cur.execute("PRAGMA table_info(users)").fetchall()}
    for col, ddl in user_cols.items():
        if col not in existing_u:
            cur.execute(f"ALTER TABLE users ADD COLUMN {col} {ddl}")

    marker_cols = {
        "status": "TEXT DEFAULT 'active'",
        "shadowbanned": "INTEGER DEFAULT 0",
        "dismiss_weight": "REAL DEFAULT 0.0",
        "confirmed_by_senior": "INTEGER DEFAULT 0",
    }
    existing_m = {r[1] for r in cur.execute("PRAGMA table_info(markers)").fetchall()}
    for col, ddl in marker_cols.items():
        if col not in existing_m:
            cur.execute(f"ALTER TABLE markers ADD COLUMN {col} {ddl}")

    conn.commit()
    conn.close()


def log_user_action(
    conn: sqlite3.Connection,
    user_id: str,
    action_type: str,
    title: str,
    details: str = "",
    lat: Optional[float] = None,
    lng: Optional[float] = None,
) -> None:
    conn.execute(
        "INSERT INTO user_actions (id, user_id, action_type, title, details, lat, lng, ts) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (f"act-{now_ms()}-{secrets.token_hex(3)}", user_id, action_type, title, details, lat, lng, now_ms()),
    )


def send_code_email(to_email: str, code: str, purpose: str) -> None:
    subject = "Код подтверждения AIRoute"
    body = (
        f"Ваш код подтверждения для {'регистрации' if purpose == 'register' else 'входа'} в AIRoute: {code}\n"
        f"Код действует 10 минут. Никому не сообщайте его."
    )
    if not SMTP_HOST or not SMTP_USER:
        print(f"[DEV EMAIL -> {to_email}] {subject}: {code}")
        return
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg.set_content(body)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)


def evaluate_auto_shadowban(conn: sqlite3.Connection, user_id: str) -> bool:
    row = conn.execute(
        "SELECT rating, confirmed_markers, rejected_markers, is_admin FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if not row or row["is_admin"]:
        return False

    confirmed = int(row["confirmed_markers"] or 0)
    rejected = int(row["rejected_markers"] or 0)
    total = confirmed + rejected
    rating = int(row["rating"] or 0)

    bad_ratio = total >= 3 and (rejected / total) > 0.80
    negative_rating = rating < 0

    if bad_ratio or negative_rating:
        until = now_ms() + 24 * 3600 * 1000
        conn.execute(
            "UPDATE users SET shadowbanned = 1, shadowbanned_until = ? WHERE id = ?",
            (until, user_id),
        )
        reason = "рейтинг ушёл в минус" if negative_rating else f"отклонено {rejected}/{total} меток (>80%)"
        log_user_action(conn, user_id, "moderation", "Автоматический теневой бан (24 ч)", reason)
        return True
    return False


class SendCodeReq(BaseModel):
    email: str
    purpose: str = "register"
    username: Optional[str] = None
    deviceId: Optional[str] = None


class BlockReq(BaseModel):
    blocked: bool
    durationHours: Optional[int] = None
    reason: str = ""


class ShadowbanReq(BaseModel):
    shadowbanned: bool
    durationHours: int = 24
    reason: str = ""


class DeleteCommentReq(BaseModel):
    author: str
    text: str
    ts: int


@router.get("/admin", response_class=HTMLResponse)
def serve_web_admin():
    for candidate in [Path("web/admin.html"), Path(__file__).resolve().parent.parent / "web" / "admin.html"]:
        if candidate.exists():
            return HTMLResponse(candidate.read_text(encoding="utf-8"))
    return HTMLResponse("<h3>Файл web/admin.html не найден рядом с сервером</h3>", status_code=404)


@router.post("/api/auth/send-email-code")
def api_send_email_code(req: SendCodeReq):
    email = req.email.strip().lower()
    if "@" not in email or "." not in email:
        raise HTTPException(400, detail="Некорректный email")

    conn = get_db()
    if req.purpose == "register":
        exists = conn.execute("SELECT id FROM users WHERE lower(email) = ?", (email,)).fetchone()
        if exists:
            conn.close()
            return {"ok": False, "error": "Этот email уже зарегистрирован"}
    else:
        exists = conn.execute("SELECT id FROM users WHERE lower(email) = ?", (email,)).fetchone()
        if not exists:
            conn.close()
            return {"ok": False, "error": "Аккаунт с такой почтой не найден"}

    code = f"{random.randint(100000, 999999)}"
    conn.execute(
        "INSERT INTO email_codes (email, purpose, code, expires_at, used) VALUES (?, ?, ?, ?, 0)",
        (email, req.purpose, code, now_ms() + 10 * 60 * 1000),
    )
    conn.commit()
    conn.close()
    send_code_email(email, code, req.purpose)
    return {"ok": True, "message": f"Код подтверждения отправлен на {email}"}


@router.post("/api/markers/{marker_id}/comments/delete")
def api_delete_comment(marker_id: str, req: DeleteCommentReq, authorization: Optional[str] = Header(None)):
    conn = get_db()
    cur = conn.cursor()
    tables = {r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}

    # 1. Если комментарии лежат в отдельной таблице marker_comments / comments
    for tbl in ("marker_comments", "comments"):
        if tbl in tables:
            cols = {r[1] for r in cur.execute(f"PRAGMA table_info({tbl})").fetchall()}
            if "marker_id" in cols and "text" in cols:
                cur.execute(
                    f"DELETE FROM {tbl} WHERE marker_id = ? AND text = ? AND (ts = ? OR ? = 0)",
                    (marker_id, req.text, req.ts, req.ts),
                )

    # 2. Если комментарии хранятся внутри JSON-колонки таблицы markers (comments_json или comments)
    m_cols = {r[1] for r in cur.execute("PRAGMA table_info(markers)").fetchall()}
    json_col = "comments_json" if "comments_json" in m_cols else ("comments" if "comments" in m_cols else None)
    if json_col:
        row = cur.execute(f"SELECT {json_col} FROM markers WHERE id = ?", (marker_id,)).fetchone()
        if row:
            comments = json.loads(row[json_col] or "[]")
            updated = [
                c for c in comments
                if not (
                    str(c.get("author", "")) == req.author
                    and str(c.get("text", "")) == req.text
                    and int(c.get("ts", 0)) == req.ts
                )
            ]
            cur.execute(
                f"UPDATE markers SET {json_col} = ? WHERE id = ?",
                (json.dumps(updated, ensure_ascii=False), marker_id),
            )

    conn.commit()
    conn.close()
    return {"ok": True}


@router.get("/api/admin/markers/pending")
def api_admin_pending_markers():
    conn = get_db()
    rows = conn.execute("SELECT * FROM markers WHERE status = 'pending' ORDER BY created_at DESC").fetchall()
    conn.close()
    return {"ok": True, "markers": [dict(r) for r in rows]}


@router.post("/api/admin/markers/{marker_id}/approve")
def api_admin_approve_marker(marker_id: str):
    conn = get_db()
    row = conn.execute("SELECT created_by FROM markers WHERE id = ?", (marker_id,)).fetchone()
    if not row:
        conn.close()
        return {"ok": False, "error": "Метка не найдена"}
    conn.execute("UPDATE markers SET status = 'active' WHERE id = ?", (marker_id,))
    if row["created_by"]:
        conn.execute(
            "UPDATE users SET confirmed_markers = COALESCE(confirmed_markers, 0) + 1 WHERE id = ?",
            (row["created_by"],),
        )
        log_user_action(conn, row["created_by"], "moderation", "Метка одобрена модератором", marker_id)
    conn.commit()
    conn.close()
    return {"ok": True}


@router.get("/api/admin/users")
def api_admin_users(q: str = ""):
    conn = get_db()
    query = q.strip().lower()
    if query:
        rows = conn.execute(
            "SELECT * FROM users WHERE lower(username) LIKE ? OR lower(email) LIKE ? ORDER BY created_at DESC LIMIT 100",
            (f"%{query}%", f"%{query}%"),
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM users ORDER BY created_at DESC LIMIT 100").fetchall()
    conn.close()
    return {"ok": True, "users": [dict(r) for r in rows]}


@router.get("/api/admin/users/{user_id}/actions")
def api_admin_user_actions(user_id: str):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM user_actions WHERE user_id = ? ORDER BY ts DESC LIMIT 150",
        (user_id,),
    ).fetchall()
    conn.close()
    return {"ok": True, "actions": [dict(r) for r in rows]}


@router.post("/api/admin/users/{user_id}/block")
def api_admin_block_user(user_id: str, req: BlockReq):
    conn = get_db()
    if req.blocked:
        until = (now_ms() + req.durationHours * 3600 * 1000) if req.durationHours else None
        conn.execute("UPDATE users SET is_blocked = 1, blocked_until = ? WHERE id = ?", (until, user_id))
        detail = f"Срок: {req.durationHours} ч" if req.durationHours else "Навсегда"
        if req.reason:
            detail += f" · {req.reason}"
        log_user_action(conn, user_id, "moderation", "Аккаунт заблокирован админом", detail)
    else:
        conn.execute("UPDATE users SET is_blocked = 0, blocked_until = NULL WHERE id = ?", (user_id,))
        log_user_action(conn, user_id, "moderation", "Блокировка снята админом", req.reason)
    conn.commit()
    conn.close()
    return {"ok": True}


@router.post("/api/admin/users/{user_id}/shadowban")
def api_admin_shadowban_user(user_id: str, req: ShadowbanReq):
    conn = get_db()
    if req.shadowbanned:
        hours = max(1, req.durationHours)
        until = now_ms() + hours * 3600 * 1000
        conn.execute("UPDATE users SET shadowbanned = 1, shadowbanned_until = ? WHERE id = ?", (until, user_id))
        detail = f"На {hours} ч" + (f" · {req.reason}" if req.reason else "")
        log_user_action(conn, user_id, "moderation", "Назначен временный теневой бан", detail)
    else:
        conn.execute("UPDATE users SET shadowbanned = 0, shadowbanned_until = NULL WHERE id = ?", (user_id,))
        log_user_action(conn, user_id, "moderation", "Теневой бан снят админом", req.reason)
    conn.commit()
    conn.close()
    return {"ok": True}
