#!/usr/bin/env python3
import os
import re
import hmac
import json
import time
import base64
import hashlib
import sqlite3
import secrets
from datetime import datetime, timezone
from aiohttp import web, WSMsgType

APP_NAME = "ehiniumChat"

BASE_DIR = "/opt/ehiniumChat"
DB_PATH = os.path.join(BASE_DIR, "ehiniumchat.db")
SECRET_PATH = os.path.join(BASE_DIR, "secret.key")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")

HOST = "0.0.0.0"
PORT = 8080

MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25 MB size limit (images can be any resolution)
COOKIE_NAME = "ehc"
COOKIE_MAX_AGE = 7 * 24 * 3600  # 7 days

URL_RE = re.compile(r"(https?://[^\s<]+)")

# In-memory websocket registry
# group_id -> set(ws)
WS_GROUPS = {}
# ws -> user_id
WS_USERS = {}
# user_id -> set(ws)
WS_BY_USER = {}


def utc_now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_secret():
    if not os.path.exists(SECRET_PATH):
        raise RuntimeError("secret.key not found")
    with open(SECRET_PATH, "r", encoding="utf-8") as f:
        s = f.read().strip()
    if not s or len(s) < 32:
        raise RuntimeError("secret.key too short")
    return bytes.fromhex(s)


SECRET = None


def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    conn = db_conn()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        display_name TEXT NOT NULL,
        password TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0,
        last_seen INTEGER NOT NULL DEFAULT 0
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS memberships (
        user_id INTEGER NOT NULL,
        group_id INTEGER NOT NULL,
        UNIQUE(user_id, group_id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS attachments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        orig_name TEXT NOT NULL,
        stored_name TEXT NOT NULL,
        mime TEXT NOT NULL,
        size INTEGER NOT NULL,
        created_at INTEGER NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        text TEXT,
        attachment_id INTEGER,
        created_at INTEGER NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS last_read (
        user_id INTEGER NOT NULL,
        group_id INTEGER NOT NULL,
        last_read_msg_id INTEGER NOT NULL DEFAULT 0,
        UNIQUE(user_id, group_id)
    )
    """)

    conn.commit()
    conn.close()


def seed_data():
    # Users and groups exactly as provided
    admin_username = "admin"
    admin_password = "pass"

    groups = {

    }

    all_usernames = set()
    for g, members in groups.items():
        for u in members:
            all_usernames.add(u)

    # Display name: keep it simple, just Title case (you can customize later)
    def display_name_for(username: str) -> str:
        return username[:1].upper() + username[1:]

    conn = db_conn()
    cur = conn.cursor()

    # Create users
    for u in sorted(all_usernames):
        pw = admin_password if u == admin_username else f"{u}123"
        is_admin = 1 if u == admin_username else 0
        dn = display_name_for(u)
        cur.execute("""
        INSERT OR IGNORE INTO users (username, display_name, password, is_admin, last_seen)
        VALUES (?, ?, ?, ?, ?)
        """, (u, dn, pw, is_admin, int(time.time())))

    # Create groups
    for gname in groups.keys():
        cur.execute("INSERT OR IGNORE INTO groups (name) VALUES (?)", (gname,))

    # Memberships and last_read rows
    cur.execute("SELECT id, username FROM users")
    user_map = {r["username"]: r["id"] for r in cur.fetchall()}

    cur.execute("SELECT id, name FROM groups")
    group_map = {r["name"]: r["id"] for r in cur.fetchall()}

    for gname, members in groups.items():
        gid = group_map[gname]
        for u in members:
            uid = user_map[u]
            cur.execute("INSERT OR IGNORE INTO memberships (user_id, group_id) VALUES (?, ?)", (uid, gid))
            cur.execute("INSERT OR IGNORE INTO last_read (user_id, group_id, last_read_msg_id) VALUES (?, ?, 0)", (uid, gid))

    conn.commit()
    conn.close()


def sign_cookie(user_id: int, exp: int) -> str:
    msg = f"{user_id}|{exp}".encode("utf-8")
    sig = hmac.new(SECRET, msg, hashlib.sha256).hexdigest()
    raw = f"{user_id}|{exp}|{sig}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8")


def verify_cookie(val: str):
    try:
        raw = base64.urlsafe_b64decode(val.encode("utf-8"))
        parts = raw.decode("utf-8").split("|")
        if len(parts) != 3:
            return None
        user_id = int(parts[0])
        exp = int(parts[1])
        sig = parts[2]
        if exp < int(time.time()):
            return None
        msg = f"{user_id}|{exp}".encode("utf-8")
        good = hmac.new(SECRET, msg, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, good):
            return None
        return user_id
    except Exception:
        return None


def get_user_id(request: web.Request):
    cookie = request.cookies.get(COOKIE_NAME)
    if not cookie:
        return None
    return verify_cookie(cookie)


def require_login(handler):
    async def wrapped(request):
        uid = get_user_id(request)
        if not uid:
            raise web.HTTPFound("/login")
        request["uid"] = uid
        return await handler(request)
    return wrapped


def require_login_api(handler):
    async def wrapped(request):
        uid = get_user_id(request)
        if not uid:
            return web.json_response({"ok": False, "error": "not_logged_in"}, status=401)
        request["uid"] = uid
        return await handler(request)
    return wrapped


def touch_last_seen(user_id: int):
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("UPDATE users SET last_seen=? WHERE id=?", (int(time.time()), user_id))
    conn.commit()
    conn.close()


def user_in_group(user_id: int, group_id: int) -> bool:
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM memberships WHERE user_id=? AND group_id=?", (user_id, group_id))
    ok = cur.fetchone() is not None
    conn.close()
    return ok


def get_user_basic(user_id: int):
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, username, display_name, is_admin, last_seen FROM users WHERE id=?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def msg_to_dict(row):
    d = {
        "id": row["id"],
        "group_id": row["group_id"],
        "user_id": row["user_id"],
        "text": row["text"] or "",
        "created_at": row["created_at"],
        "attachment": None,
        "sender": {
            "username": row["username"],
            "display_name": row["display_name"],
        }
    }
    if row["attachment_id"]:
        d["attachment"] = {
            "id": row["attachment_id"],
            "url": row["url"],
            "mime": row["mime"],
            "orig_name": row["orig_name"],
            "size": row["size"],
        }
    return d


async def page_login(request):
    uid = get_user_id(request)
    if uid:
        raise web.HTTPFound("/chat")

    html = LOGIN_HTML
    return web.Response(text=html, content_type="text/html", charset="utf-8")


async def do_login(request):
    form = await request.post()
    username = (form.get("username") or "").strip()
    password = (form.get("password") or "").strip()

    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, password FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()

    if not row or row["password"] != password:
        return web.Response(text=LOGIN_HTML.replace("{{ERROR}}", "Invalid username or password."), content_type="text/html", charset="utf-8")

    user_id = row["id"]
    exp = int(time.time()) + COOKIE_MAX_AGE
    cookie_val = sign_cookie(user_id, exp)

    touch_last_seen(user_id)

    resp = web.HTTPFound("/chat")
    resp.set_cookie(COOKIE_NAME, cookie_val, max_age=COOKIE_MAX_AGE, httponly=True, samesite="Lax")
    return resp


@require_login
async def page_chat(request):
    uid = request["uid"]
    me = get_user_basic(uid)
    touch_last_seen(uid)
    html = CHAT_HTML.replace("{{ME_USERNAME}}", me["username"]).replace("{{ME_DISPLAY}}", me["display_name"])
    return web.Response(text=html, content_type="text/html", charset="utf-8")


@require_login
async def do_logout(request):
    resp = web.HTTPFound("/login")
    resp.del_cookie(COOKIE_NAME)
    return resp


@require_login_api
async def api_me(request):
    uid = request["uid"]
    touch_last_seen(uid)
    me = get_user_basic(uid)
    return web.json_response({"ok": True, "me": me})


@require_login_api
async def api_groups(request):
    uid = request["uid"]
    touch_last_seen(uid)

    conn = db_conn()
    cur = conn.cursor()

    # Groups user is in
    cur.execute("""
    SELECT g.id, g.name
    FROM groups g
    JOIN memberships m ON m.group_id = g.id
    WHERE m.user_id=?
    ORDER BY g.name COLLATE NOCASE
    """, (uid,))
    groups = cur.fetchall()

    out = []
    for g in groups:
        gid = g["id"]

        # last message
        cur.execute("""
        SELECT msg.id, msg.text, msg.created_at, u.display_name
        FROM messages msg
        JOIN users u ON u.id = msg.user_id
        WHERE msg.group_id=?
        ORDER BY msg.id DESC
        LIMIT 1
        """, (gid,))
        last = cur.fetchone()

        # unread count
        cur.execute("SELECT last_read_msg_id FROM last_read WHERE user_id=? AND group_id=?", (uid, gid))
        lr = cur.fetchone()
        last_read_id = lr["last_read_msg_id"] if lr else 0

        cur.execute("SELECT COUNT(1) AS c FROM messages WHERE group_id=? AND id>?", (gid, last_read_id))
        unread = cur.fetchone()["c"]

        out.append({
            "id": gid,
            "name": g["name"],
            "unread": unread,
            "last_message": {
                "id": last["id"],
                "text": (last["text"] or "")[:120],
                "created_at": last["created_at"],
                "by": last["display_name"],
            } if last else None
        })

    conn.close()
    return web.json_response({"ok": True, "groups": out})


@require_login_api
async def api_group_info(request):
    uid = request["uid"]
    touch_last_seen(uid)

    group_id = int(request.query.get("group_id", "0") or "0")
    if group_id <= 0 or not user_in_group(uid, group_id):
        return web.json_response({"ok": False, "error": "forbidden"}, status=403)

    conn = db_conn()
    cur = conn.cursor()

    cur.execute("SELECT id, name FROM groups WHERE id=?", (group_id,))
    g = cur.fetchone()
    if not g:
        conn.close()
        return web.json_response({"ok": False, "error": "not_found"}, status=404)

    cur.execute("""
    SELECT u.id, u.username, u.display_name, u.last_seen
    FROM users u
    JOIN memberships m ON m.user_id = u.id
    WHERE m.group_id=?
    ORDER BY u.display_name COLLATE NOCASE
    """, (group_id,))
    members = []
    now = int(time.time())
    for r in cur.fetchall():
        last_seen = int(r["last_seen"] or 0)
        members.append({
            "id": r["id"],
            "username": r["username"],
            "display_name": r["display_name"],
            "last_seen": last_seen,
            "last_seen_ago": max(0, now - last_seen),
        })

    conn.close()
    return web.json_response({"ok": True, "group": {"id": g["id"], "name": g["name"], "members": members}})


@require_login_api
async def api_messages(request):
    uid = request["uid"]
    touch_last_seen(uid)

    group_id = int(request.query.get("group_id", "0") or "0")
    limit = int(request.query.get("limit", "10") or "10")
    before_id = int(request.query.get("before_id", "0") or "0")

    if limit < 1 or limit > 50:
        limit = 10

    if group_id <= 0 or not user_in_group(uid, group_id):
        return web.json_response({"ok": False, "error": "forbidden"}, status=403)

    conn = db_conn()
    cur = conn.cursor()

    if before_id > 0:
        cur.execute("""
        SELECT msg.id, msg.group_id, msg.user_id, msg.text, msg.attachment_id, msg.created_at,
               u.username, u.display_name,
               a.orig_name, a.stored_name, a.mime, a.size
        FROM messages msg
        JOIN users u ON u.id = msg.user_id
        LEFT JOIN attachments a ON a.id = msg.attachment_id
        WHERE msg.group_id=? AND msg.id < ?
        ORDER BY msg.id DESC
        LIMIT ?
        """, (group_id, before_id, limit))
    else:
        cur.execute("""
        SELECT msg.id, msg.group_id, msg.user_id, msg.text, msg.attachment_id, msg.created_at,
               u.username, u.display_name,
               a.orig_name, a.stored_name, a.mime, a.size
        FROM messages msg
        JOIN users u ON u.id = msg.user_id
        LEFT JOIN attachments a ON a.id = msg.attachment_id
        WHERE msg.group_id=?
        ORDER BY msg.id DESC
        LIMIT ?
        """, (group_id, limit))

    rows = cur.fetchall()
    msgs = []
    for row in rows:
        url = None
        if row["attachment_id"]:
            url = f"/uploads/{row['stored_name']}"
        msg_row = {
            "id": row["id"],
            "group_id": row["group_id"],
            "user_id": row["user_id"],
            "text": row["text"] or "",
            "created_at": row["created_at"],
            "sender": {"username": row["username"], "display_name": row["display_name"]},
            "attachment": None
        }
        if row["attachment_id"]:
            msg_row["attachment"] = {
                "id": row["attachment_id"],
                "url": url,
                "mime": row["mime"],
                "orig_name": row["orig_name"],
                "size": row["size"],
            }
        msgs.append(msg_row)

    # return ascending for UI
    msgs.reverse()

    has_more = False
    if msgs:
        oldest_id = msgs[0]["id"]
        cur.execute("SELECT 1 FROM messages WHERE group_id=? AND id < ? LIMIT 1", (group_id, oldest_id))
        has_more = cur.fetchone() is not None

    conn.close()
    return web.json_response({"ok": True, "messages": msgs, "has_more": has_more})


@require_login_api
async def api_mark_read(request):
    uid = request["uid"]
    touch_last_seen(uid)

    data = await request.json()
    group_id = int(data.get("group_id", 0) or 0)
    last_id = int(data.get("last_id", 0) or 0)

    if group_id <= 0 or not user_in_group(uid, group_id):
        return web.json_response({"ok": False, "error": "forbidden"}, status=403)

    conn = db_conn()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO last_read (user_id, group_id, last_read_msg_id)
    VALUES (?, ?, ?)
    ON CONFLICT(user_id, group_id) DO UPDATE SET last_read_msg_id=excluded.last_read_msg_id
    """, (uid, group_id, last_id))
    conn.commit()
    conn.close()

    return web.json_response({"ok": True})


@require_login_api
async def api_send(request):
    uid = request["uid"]
    touch_last_seen(uid)

    data = await request.json()
    group_id = int(data.get("group_id", 0) or 0)
    text = (data.get("text") or "").strip()
    attachment_id = int(data.get("attachment_id", 0) or 0) or None

    if group_id <= 0 or not user_in_group(uid, group_id):
        return web.json_response({"ok": False, "error": "forbidden"}, status=403)

    if not text and not attachment_id:
        return web.json_response({"ok": False, "error": "empty"}, status=400)

    now = int(time.time())

    conn = db_conn()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO messages (group_id, user_id, text, attachment_id, created_at)
    VALUES (?, ?, ?, ?, ?)
    """, (group_id, uid, text, attachment_id, now))
    msg_id = cur.lastrowid
    conn.commit()

    # Fetch full row for broadcast
    cur.execute("""
    SELECT msg.id, msg.group_id, msg.user_id, msg.text, msg.attachment_id, msg.created_at,
           u.username, u.display_name,
           a.orig_name, a.stored_name, a.mime, a.size
    FROM messages msg
    JOIN users u ON u.id = msg.user_id
    LEFT JOIN attachments a ON a.id = msg.attachment_id
    WHERE msg.id=?
    """, (msg_id,))
    row = cur.fetchone()
    conn.close()

    url = None
    if row["attachment_id"]:
        url = f"/uploads/{row['stored_name']}"

    msg_obj = {
        "type": "message",
        "message": {
            "id": row["id"],
            "group_id": row["group_id"],
            "user_id": row["user_id"],
            "text": row["text"] or "",
            "created_at": row["created_at"],
            "sender": {"username": row["username"], "display_name": row["display_name"]},
            "attachment": None
        }
    }
    if row["attachment_id"]:
        msg_obj["message"]["attachment"] = {
            "id": row["attachment_id"],
            "url": url,
            "mime": row["mime"],
            "orig_name": row["orig_name"],
            "size": row["size"],
        }

    await broadcast_to_group(group_id, msg_obj)

    return web.json_response({"ok": True, "message_id": msg_id})


@require_login_api
async def api_upload(request):
    uid = request["uid"]
    touch_last_seen(uid)

    reader = await request.multipart()

    total = 0
    file_field = None

    while True:
        part = await reader.next()
        if part is None:
            break
        if part.name == "file":
            file_field = part
            break

    if not file_field:
        return web.json_response({"ok": False, "error": "no_file"}, status=400)

    filename = file_field.filename or "upload.bin"
    mime = file_field.headers.get("Content-Type", "application/octet-stream")

    stored_name = secrets.token_hex(16) + "_" + re.sub(r"[^a-zA-Z0-9._-]+", "_", filename)[:80]
    path = os.path.join(UPLOAD_DIR, stored_name)

    with open(path, "wb") as f:
        while True:
            chunk = await file_field.read_chunk(size=1024 * 128)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_UPLOAD_BYTES:
                try:
                    f.close()
                except Exception:
                    pass
                try:
                    os.remove(path)
                except Exception:
                    pass
                return web.json_response({"ok": False, "error": "too_large", "max_bytes": MAX_UPLOAD_BYTES}, status=413)
            f.write(chunk)

    conn = db_conn()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO attachments (orig_name, stored_name, mime, size, created_at)
    VALUES (?, ?, ?, ?, ?)
    """, (filename, stored_name, mime, total, int(time.time())))
    att_id = cur.lastrowid
    conn.commit()
    conn.close()

    return web.json_response({
        "ok": True,
        "attachment": {
            "id": att_id,
            "url": f"/uploads/{stored_name}",
            "mime": mime,
            "orig_name": filename,
            "size": total
        }
    })


async def broadcast_to_group(group_id: int, payload: dict):
    conns = WS_GROUPS.get(group_id)
    if not conns:
        return
    data = json.dumps(payload)
    dead = []
    for ws in list(conns):
        try:
            await ws.send_str(data)
        except Exception:
            dead.append(ws)
    for ws in dead:
        try:
            conns.discard(ws)
        except Exception:
            pass


@require_login_api
async def ws_handler(request):
    uid = request["uid"]
    touch_last_seen(uid)

    ws = web.WebSocketResponse(heartbeat=20)
    await ws.prepare(request)

    WS_USERS[ws] = uid
    WS_BY_USER.setdefault(uid, set()).add(ws)

    # default: no subscriptions until client asks
    my_groups = set()

    async def cleanup():
        for gid in list(my_groups):
            s = WS_GROUPS.get(gid)
            if s:
                s.discard(ws)
        WS_USERS.pop(ws, None)
        if uid in WS_BY_USER:
            WS_BY_USER[uid].discard(ws)
            if not WS_BY_USER[uid]:
                WS_BY_USER.pop(uid, None)

    await ws.send_str(json.dumps({"type": "hello", "server_time": int(time.time())}))

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                except Exception:
                    continue
                t = data.get("type")

                if t == "subscribe":
                    gid = int(data.get("group_id", 0) or 0)
                    if gid > 0 and user_in_group(uid, gid):
                        WS_GROUPS.setdefault(gid, set()).add(ws)
                        my_groups.add(gid)
                        await ws.send_str(json.dumps({"type": "subscribed", "group_id": gid}))
                elif t == "unsubscribe":
                    gid = int(data.get("group_id", 0) or 0)
                    if gid in my_groups:
                        my_groups.remove(gid)
                        s = WS_GROUPS.get(gid)
                        if s:
                            s.discard(ws)
                elif t == "ping":
                    touch_last_seen(uid)
                    await ws.send_str(json.dumps({"type": "pong", "t": int(time.time())}))
            elif msg.type == WSMsgType.ERROR:
                break
    finally:
        await cleanup()

    return ws


async def index(request):
    uid = get_user_id(request)
    if uid:
        raise web.HTTPFound("/chat")
    raise web.HTTPFound("/login")


def safe_static(path):
    return web.StaticResource("/uploads", path, show_index=False, follow_symlinks=False)


def build_app():
    app = web.Application(client_max_size=MAX_UPLOAD_BYTES + 1024 * 1024)

    app.router.add_get("/", index)
    app.router.add_get("/login", page_login)
    app.router.add_post("/login", do_login)
    app.router.add_post("/logout", do_logout)

    app.router.add_get("/chat", page_chat)

    app.router.add_get("/api/me", api_me)
    app.router.add_get("/api/groups", api_groups)
    app.router.add_get("/api/group_info", api_group_info)
    app.router.add_get("/api/messages", api_messages)
    app.router.add_post("/api/mark_read", api_mark_read)
    app.router.add_post("/api/send", api_send)
    app.router.add_post("/api/upload", api_upload)

    app.router.add_get("/ws", ws_handler)

    app.router.register_resource(safe_static(UPLOAD_DIR))

    return app


LOGIN_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>ehiniumChat | Login</title>
  <style>
    :root{
      --bg:#0f172a;
      --card:#111c34;
      --card2:#0b1222;
      --text:#e5e7eb;
      --muted:#9ca3af;
      --accent:#3b82f6;
      --danger:#ef4444;
      --ok:#22c55e;
      --border:rgba(255,255,255,.08);
    }
    *{box-sizing:border-box;}
    body{
      margin:0;
      min-height:100vh;
      display:flex;
      align-items:center;
      justify-content:center;
      background:radial-gradient(1200px 600px at 30% 20%, rgba(59,130,246,.22), transparent 55%),
                 radial-gradient(900px 500px at 70% 70%, rgba(34,197,94,.14), transparent 55%),
                 var(--bg);
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
      color:var(--text);
    }
    .wrap{
      width: min(420px, 92vw);
      background: linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03));
      border:1px solid var(--border);
      border-radius:18px;
      padding:22px;
      box-shadow: 0 18px 60px rgba(0,0,0,.35);
      backdrop-filter: blur(10px);
    }
    .brand{
      display:flex;
      align-items:center;
      gap:12px;
      margin-bottom: 10px;
    }
    .logo{
      width:40px;height:40px;border-radius:12px;
      background: radial-gradient(circle at 30% 30%, rgba(59,130,246,.95), rgba(59,130,246,.25)),
                  linear-gradient(180deg, rgba(255,255,255,.18), rgba(255,255,255,0));
      border:1px solid rgba(255,255,255,.14);
      box-shadow: 0 10px 30px rgba(59,130,246,.22);
    }
    h1{font-size:18px;margin:0;}
    .sub{color:var(--muted);font-size:13px;margin:4px 0 16px;}
    .err{
      background: rgba(239,68,68,.12);
      border:1px solid rgba(239,68,68,.25);
      color:#fecaca;
      padding:10px 12px;
      border-radius:12px;
      margin: 0 0 12px;
      display:none;
      font-size:13px;
    }
    .field{margin:10px 0;}
    label{display:block;font-size:12px;color:var(--muted);margin-bottom:6px;}
    input{
      width:100%;
      padding:12px 12px;
      border-radius:12px;
      border:1px solid var(--border);
      background: rgba(10,16,30,.7);
      color: var(--text);
      outline:none;
      font-size:14px;
    }
    input:focus{border-color: rgba(59,130,246,.55); box-shadow: 0 0 0 4px rgba(59,130,246,.12);}
    button{
      width:100%;
      margin-top:12px;
      padding:12px 14px;
      border-radius:12px;
      border:1px solid rgba(59,130,246,.35);
      background: linear-gradient(180deg, rgba(59,130,246,.95), rgba(59,130,246,.65));
      color:#fff;
      font-weight:700;
      cursor:pointer;
      font-size:14px;
    }
    button:hover{filter:brightness(1.05);}
    .hint{margin-top:10px;color:var(--muted);font-size:12px;line-height:1.4;}
    .foot{margin-top:14px;color:rgba(255,255,255,.45);font-size:11px;}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="brand">
      <div class="logo"></div>
      <div>
        <h1>ehiniumChat</h1>
        <div class="sub">Private chat by ehinium</div>
      </div>
    </div>

    <div class="err" id="err">{{ERROR}}</div>

    <form method="post" action="/login" autocomplete="off">
      <div class="field">
        <label>Username</label>
        <input name="username" placeholder="username" required />
      </div>
      <div class="field">
        <label>Password</label>
        <input name="password" type="password" placeholder="password" required />
      </div>
      <button type="submit">Login</button>
    </form>
  </div>

  <script>
    (function(){
      const err = document.getElementById('err');
      if(err.textContent && err.textContent.indexOf('{{ERROR}}') === -1){
        err.style.display = 'block';
      }
    })();
  </script>
</body>
</html>
"""

CHAT_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>ehiniumChat</title>
  <style>
    :root{
      --bg:#0b1222;
      --panel:#0f1a32;
      --panel2:#0b152b;
      --panel3:#0b1020;
      --text:#e5e7eb;
      --muted:#9ca3af;
      --muted2:#6b7280;
      --accent:#3b82f6;
      --accent2:#60a5fa;
      --danger:#ef4444;
      --border:rgba(255,255,255,.08);
      --bubbleMe:#2563eb;
      --bubbleOther:#142444;
      --shadow: 0 16px 50px rgba(0,0,0,.42);
      --radius: 18px;
    }
    *{box-sizing:border-box;}
    html, body{height:100%;}
    body{
      margin:0;
      background: radial-gradient(1200px 600px at 20% 10%, rgba(59,130,246,.18), transparent 55%),
                  radial-gradient(900px 500px at 80% 80%, rgba(96,165,250,.12), transparent 55%),
                  var(--bg);
      color:var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
    }

    .app{
      height:100%;
      display:grid;
      grid-template-columns: 360px 1fr;
      gap:14px;
      padding:14px;
    }

    .card{
      background: linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.02));
      border:1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      backdrop-filter: blur(10px);
      overflow:hidden;
      min-height: 0;
    }

    .sidebar{
      display:flex;
      flex-direction:column;
      min-height:0;
    }

    .topbar{
      padding:14px;
      border-bottom:1px solid var(--border);
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:10px;
      background: rgba(10,16,30,.45);
    }
    .brand{
      display:flex; align-items:center; gap:10px;
      min-width:0;
    }
    .logo{
      width:36px;height:36px;border-radius:12px;
      background: radial-gradient(circle at 30% 30%, rgba(59,130,246,.95), rgba(59,130,246,.25));
      border:1px solid rgba(255,255,255,.14);
      flex:0 0 auto;
    }
    .brand h1{
      font-size:14px; margin:0; line-height:1.1;
      white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
    }
    .brand .me{
      font-size:11px; color:var(--muted); margin-top:2px;
      white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
    }
    .btn{
      border:1px solid var(--border);
      background: rgba(10,16,30,.55);
      color:var(--text);
      padding:9px 10px;
      border-radius:12px;
      cursor:pointer;
      font-size:12px;
    }
    .btn:hover{border-color: rgba(59,130,246,.35);}
    
    #menuBtn{display:none;}
      @media (max-width: 920px){
      #menuBtn{display:inline-flex;}
    }

    .search{
      padding:12px 14px;
      border-bottom:1px solid var(--border);
      background: rgba(10,16,30,.22);
    }
    .search input{
      width:100%;
      border:1px solid var(--border);
      background: rgba(10,16,30,.55);
      color:var(--text);
      padding:11px 12px;
      border-radius:12px;
      outline:none;
      font-size:13px;
    }
    .search input:focus{border-color: rgba(59,130,246,.55); box-shadow: 0 0 0 4px rgba(59,130,246,.12);}

    .glist{
      overflow:auto;
      min-height:0;
      padding:8px;
    }
    .gitem{
      display:flex;
      gap:12px;
      padding:12px;
      border-radius:14px;
      cursor:pointer;
      border:1px solid transparent;
    }
    .gitem:hover{
      background: rgba(255,255,255,.03);
      border-color: rgba(255,255,255,.06);
    }
    .gitem.active{
      background: rgba(59,130,246,.14);
      border-color: rgba(59,130,246,.22);
    }
    .avatar{
      width:44px;height:44px;border-radius:16px;
      background: linear-gradient(180deg, rgba(255,255,255,.08), rgba(255,255,255,.02));
      border:1px solid rgba(255,255,255,.10);
      display:flex;
      align-items:center;
      justify-content:center;
      font-weight:800;
      color: rgba(255,255,255,.85);
      flex:0 0 auto;
    }
    .gmeta{min-width:0; flex:1;}
    .gtitle{
      display:flex; align-items:center; justify-content:space-between; gap:10px;
      font-size:13px; font-weight:750;
    }
    .gname{
      white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
      direction: auto;
      unicode-bidi: plaintext;
      text-align: start;
    }
    .gtime{font-size:11px; color:var(--muted2); flex:0 0 auto;}
    .gsub{
      display:flex; align-items:center; justify-content:space-between; gap:10px;
      margin-top:4px;
      color:var(--muted);
      font-size:12px;
    }
    .gpreview{
      white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
      direction: auto;
      unicode-bidi: plaintext;
      text-align: start;
    }
    .badge{
      display:flex; align-items:center; gap:7px; flex:0 0 auto;
    }
    .dot{
      width:9px; height:9px; border-radius:9px;
      background: var(--danger);
      box-shadow: 0 0 0 4px rgba(239,68,68,.14);
      display:none;
    }
    .count{
      min-width:22px;
      height:22px;
      padding:0 7px;
      border-radius:999px;
      background: rgba(239,68,68,.18);
      border:1px solid rgba(239,68,68,.30);
      color:#fecaca;
      font-size:12px;
      font-weight:800;
      display:none;
      align-items:center;
      justify-content:center;
    }

    .main{
      display:flex;
      flex-direction:column;
      min-height:0;
    }
    .chatTop{
      padding:14px;
      border-bottom:1px solid var(--border);
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:12px;
      background: rgba(10,16,30,.45);
    }
    .chatTitle{
      min-width:0;
    }
    .chatTitle .name{
      font-weight:800;
      font-size:14px;
      white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
      direction: auto;
      unicode-bidi: plaintext;
      text-align: start;

    }
    .chatTitle .sub{
      margin-top:3px;
      font-size:12px;
      color:var(--muted);
      white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
      direction: auto;
      unicode-bidi: plaintext;
      text-align: start;

    }

    .messages{
      flex:1;
      overflow:auto;
      padding:16px 14px;
      background: rgba(10,16,30,.18);
      min-height:0;
    }
    .loadHint{
      text-align:center;
      color:var(--muted2);
      font-size:12px;
      padding:10px 0 12px;
      display:none;
    }

    .row{
      display:flex;
      margin: 10px 0;
      gap:10px;
    }
    .row.me{justify-content:flex-end;}
    .bubble{
      max-width: min(640px, 78%);
      border-radius: 16px;
      padding: 10px 12px;
      border: 1px solid rgba(255,255,255,.08);
      background: var(--bubbleOther);
      box-shadow: 0 10px 28px rgba(0,0,0,.20);
      overflow:hidden;
    }
    .row.me .bubble{
      background: linear-gradient(180deg, rgba(59,130,246,.90), rgba(37,99,235,.78));
      border-color: rgba(255,255,255,.10);
    }
    .metaLine{
      display:flex;
      align-items:baseline;
      justify-content:space-between;
      gap:10px;
      margin-bottom:6px;
    }
    .sender{
      font-size:12px;
      font-weight:800;
      color: rgba(255,255,255,.9);
    }
    .row.me .sender{display:none;}
    .time{
      font-size:11px;
      color: rgba(255,255,255,.65);
      flex:0 0 auto;
    }
    .text{
      font-size:13px;
      line-height:1.45;
      color: rgba(255,255,255,.92);
      word-wrap: break-word;
      white-space: pre-wrap;

      /* RTL/LTR auto support per message */
      direction: auto;
      unicode-bidi: plaintext;
      text-align: start;
    }

    .text a{color: #dbeafe; text-decoration: underline;}
    .row:not(.me) .text a{color:#93c5fd;}

    .att{
      margin-top:8px;
      border-radius:14px;
      border:1px solid rgba(255,255,255,.10);
      overflow:hidden;
      background: rgba(0,0,0,.22);
    }
    .att img{
      display:block;
      max-width:100%;
      height:auto;
    }
    .att .file{
      padding:10px 10px;
      font-size:12px;
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:10px;
    }
    .att .file a{color:#e5e7eb; text-decoration: underline;}
    .att .file .size{color: rgba(255,255,255,.65); font-size:11px;}

    .composer{
      border-top:1px solid var(--border);
      background: rgba(10,16,30,.45);
      padding:12px;
      display:flex;
      gap:10px;
      align-items:flex-end;
    }
    .composeBox{
      flex:1;
      border:1px solid var(--border);
      background: rgba(10,16,30,.55);
      border-radius: 16px;
      padding:10px 10px;
    }
    textarea{
      width:100%;
      resize:none;
      border:none;
      outline:none;
      background: transparent;
      color: var(--text);
      font-size:13px;
      line-height:1.35;
      min-height: 22px;
      max-height: 110px;
      overflow:auto;
      direction: auto;
      unicode-bidi: plaintext;
      text-align: start;
    }
    .composeActions{
      display:flex;
      gap:10px;
      align-items:center;
    }
    .send{
      border:1px solid rgba(59,130,246,.35);
      background: linear-gradient(180deg, rgba(59,130,246,.95), rgba(59,130,246,.65));
      color:#fff;
      font-weight:900;
      border-radius:14px;
      padding:12px 14px;
      cursor:pointer;
      font-size:13px;
      height:44px;
    }
    .send:hover{filter:brightness(1.05);}
    .iconBtn{
      width:44px;height:44px;
      border-radius:14px;
      border:1px solid var(--border);
      background: rgba(10,16,30,.55);
      color:var(--text);
      cursor:pointer;
      display:flex;
      align-items:center;
      justify-content:center;
      font-size:18px;
      user-select:none;
    }
    .iconBtn:hover{border-color: rgba(59,130,246,.35);}
    input[type="file"]{display:none;}

    .toast{
      position:fixed;
      bottom:18px;
      left:50%;
      transform:translateX(-50%);
      background: rgba(15,26,50,.92);
      border:1px solid rgba(255,255,255,.10);
      padding:10px 12px;
      border-radius:14px;
      color:var(--text);
      font-size:12px;
      box-shadow: var(--shadow);
      display:none;
      max-width: min(560px, 92vw);
    }

    .modalBack{
      position:fixed; inset:0;
      background: rgba(0,0,0,.55);
      display:none;
      align-items:center;
      justify-content:center;
      padding:16px;
    }
    .modal{
      width:min(520px, 96vw);
      background: rgba(15,26,50,.92);
      border:1px solid rgba(255,255,255,.12);
      border-radius:18px;
      box-shadow: var(--shadow);
      overflow:hidden;
    }
    .modalTop{
      padding:12px 14px;
      border-bottom:1px solid rgba(255,255,255,.10);
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:10px;
    }
    .modalTop .title{font-weight:900; font-size:14px;}
    .modalTop .x{cursor:pointer; font-size:18px; padding:4px 8px; border-radius:10px; border:1px solid rgba(255,255,255,.10);}
    .modalTop .x:hover{border-color: rgba(59,130,246,.35);}
    .modalBody{
      padding:12px 14px;
      max-height: 70vh;
      overflow:auto;
    }
    .member{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:10px;
      padding:10px 10px;
      border-radius:14px;
      border:1px solid rgba(255,255,255,.08);
      background: rgba(10,16,30,.45);
      margin-bottom:10px;
    }
    .member .left{
      min-width:0;
    }
    .member .name{font-weight:800; font-size:13px;}
    .member .user{color:var(--muted); font-size:12px; margin-top:3px;}
    .member .seen{color:var(--muted2); font-size:12px; flex:0 0 auto;}

    .backdrop{
      position:fixed;
      inset:0;
      background: rgba(0,0,0,.55);
      display:none;
      z-index: 40;
    }

    @media (max-width: 920px){
      .app{
        grid-template-columns: 1fr;
      }

      /* Sidebar becomes a drawer */
      .sidebar{
        position: fixed;
        top: 0;
        left: 0;
        bottom: 0;
        width: min(360px, 92vw);
        height: auto;
        z-index: 50;
        transform: translateX(-110%);
        transition: transform .22s ease;
      }

      .sidebar.open{
        transform: translateX(0);
      }

      .backdrop.show{
        display:block;
      }
    }

  </style>
</head>
<body>
  <div class="app">
    <div class="card sidebar">
      <div class="topbar">
        <div class="brand">
          <div class="logo"></div>
          <div style="min-width:0;">
            <h1>ehiniumChat</h1>
            <div class="me">{{ME_DISPLAY}} (@{{ME_USERNAME}})</div>
          </div>
        </div>
        <form method="post" action="/logout" style="margin:0;">
          <button class="btn" type="submit">Logout</button>
        </form>
      </div>

      <div class="glist" id="glist"></div>
    </div>

    <div class="card main">
      <div class="chatTop">
        <button class="btn" id="menuBtn" title="Menu">☰</button>
        <div class="chatTitle">
          <div class="name" id="chatName">Select a group</div>
          <div class="sub" id="chatSub">Your messages are stored on this server.</div>
        </div>
        <div style="display:flex; gap:10px; align-items:center;">
            <button class="btn" id="infoBtn" disabled>Group info</button>
        </div>

      </div>

      <div class="messages" id="messages">
        <div class="loadHint" id="loadHint">Scroll up to load older messages</div>
      </div>

      <div class="composer">
        <label class="iconBtn" title="Attach file">
          +
          <input id="file" type="file" />
        </label>
        <div class="composeBox">
          <textarea id="text" placeholder="Message..." disabled></textarea>
        </div>
        <button class="send" id="send" disabled>Send</button>
      </div>
    </div>
  </div>

  <div class="toast" id="toast"></div>
  <div class="backdrop" id="backdrop"></div>

  <div class="modalBack" id="modalBack">
    <div class="modal">
      <div class="modalTop">
        <div class="title" id="modalTitle">Group info</div>
        <div class="x" id="modalClose">x</div>
      </div>
      <div class="modalBody" id="modalBody"></div>
    </div>
  </div>

<script>
(function(){
  const state = {
    me: { username: "{{ME_USERNAME}}", display_name: "{{ME_DISPLAY}}" },
    groups: [],
    activeGroupId: null,
    activeGroupName: "",
    messages: [],
    hasMore: false,
    loadingOlder: false,
    ws: null,
    subscribed: new Set(),
    lastMessageIdByGroup: new Map(),
    lastReadSentByGroup: new Map(),
  };

  const glist = document.getElementById('glist');
  const chatName = document.getElementById('chatName');
  const chatSub = document.getElementById('chatSub');
  const messagesEl = document.getElementById('messages');
  const loadHint = document.getElementById('loadHint');
  const textEl = document.getElementById('text');
  const sendBtn = document.getElementById('send');
  const fileEl = document.getElementById('file');
  const toast = document.getElementById('toast');
  const infoBtn = document.getElementById('infoBtn');
  const menuBtn = document.getElementById('menuBtn');
  const backdrop = document.getElementById('backdrop');
  const sidebarEl = document.querySelector('.sidebar');

  const modalBack = document.getElementById('modalBack');
  const modalClose = document.getElementById('modalClose');
  const modalTitle = document.getElementById('modalTitle');
  const modalBody = document.getElementById('modalBody');

  function showToast(msg){
    toast.textContent = msg;
    toast.style.display = 'block';
    setTimeout(()=> toast.style.display = 'none', 2600);
  }
  
    function isMobile(){
    return window.matchMedia('(max-width: 920px)').matches;
  }

  function openMenu(){
    if(!sidebarEl) return;
    sidebarEl.classList.add('open');
    if(backdrop) backdrop.classList.add('show');
  }

  function closeMenu(){
    if(!sidebarEl) return;
    sidebarEl.classList.remove('open');
    if(backdrop) backdrop.classList.remove('show');
  }


  function fmtTime(ts){
    const d = new Date(ts * 1000);
    const hh = String(d.getHours()).padStart(2,'0');
    const mm = String(d.getMinutes()).padStart(2,'0');
    return hh + ":" + mm;
  }

  function humanSeen(secondsAgo){
    if(secondsAgo < 20) return "online";
    if(secondsAgo < 60) return secondsAgo + "s ago";
    const m = Math.floor(secondsAgo / 60);
    if(m < 60) return m + "m ago";
    const h = Math.floor(m / 60);
    if(h < 48) return h + "h ago";
    const d = Math.floor(h / 24);
    return d + "d ago";
  }

  function escapeHtml(s){
    return s.replace(/[&<>"']/g, (c)=>({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c]));
  }

  function linkify(text){
    const safe = escapeHtml(text);
    return safe.replace(/(https?:\/\/[^\s<]+)/g, (m)=>{
      const url = m;
      return '<a href="'+url+'" target="_blank" rel="noopener noreferrer">'+url+'</a>';
    });
  }

  async function apiGet(url){
    const r = await fetch(url, {credentials:'same-origin'});
    if(!r.ok) throw new Error("API error");
    return await r.json();
  }
  async function apiPost(url, data){
    const r = await fetch(url, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify(data),
      credentials:'same-origin'
    });
    const j = await r.json().catch(()=>({ok:false}));
    if(!r.ok) throw new Error(j.error || "API error");
    return j;
  }

  async function loadGroups(){
    const j = await apiGet('/api/groups');
    state.groups = j.groups || [];
    renderGroups();
  }

  function renderGroups(){
    glist.innerHTML = "";
    const items = state.groups;
    for(const g of items){
      const div = document.createElement('div');
      div.className = 'gitem' + (state.activeGroupId === g.id ? ' active':'');
      const initials = (g.name || "?").trim().slice(0,2).toUpperCase();

      const last = g.last_message;
      const preview = last ? (last.by + ": " + (last.text || "")) : "No messages yet";
      const time = last ? fmtTime(last.created_at) : "";

      div.innerHTML = `
        <div class="avatar">${escapeHtml(initials)}</div>
        <div class="gmeta">
          <div class="gtitle">
            <div class="gname">${escapeHtml(g.name)}</div>
            <div class="gtime">${escapeHtml(time)}</div>
          </div>
          <div class="gsub">
            <div class="gpreview">${escapeHtml(preview)}</div>
            <div class="badge">
              <div class="dot" style="display:${g.unread>0?'block':'none'}"></div>
              <div class="count" style="display:${g.unread>0?'flex':'none'}">${g.unread}</div>
            </div>
          </div>
        </div>
      `;
      div.addEventListener('click', ()=> selectGroup(g.id, g.name));
      glist.appendChild(div);
    }
  }

  function clearMessages(){
    state.messages = [];
    messagesEl.innerHTML = '<div class="loadHint" id="loadHint">Scroll up to load older messages</div>';
  }

  async function selectGroup(groupId, groupName){
    state.activeGroupId = groupId;
    state.activeGroupName = groupName;
    chatName.textContent = groupName;
    chatSub.textContent = "Loading...";
    textEl.disabled = false;
    sendBtn.disabled = false;
    infoBtn.disabled = false;

    clearMessages();

    await ensureSubscribed(groupId);
    await loadLatest(groupId);
    renderGroups();

    chatSub.textContent = "Scroll up to load older messages";
    scrollToBottom();

    // mark read after load
    markReadIfNeeded(true);
    if(isMobile()) closeMenu();
  }

  async function loadLatest(groupId){
    const j = await apiGet('/api/messages?group_id=' + groupId + '&limit=10');
    state.messages = j.messages || [];
    state.hasMore = !!j.has_more;
    renderMessages(true);
  }

  async function loadOlder(){
    if(state.loadingOlder) return;
    if(!state.activeGroupId) return;
    if(!state.hasMore) return;
    if(state.messages.length === 0) return;

    state.loadingOlder = true;
    const beforeId = state.messages[0].id;

    const prevScrollHeight = messagesEl.scrollHeight;
    const prevScrollTop = messagesEl.scrollTop;

    try{
      const j = await apiGet('/api/messages?group_id=' + state.activeGroupId + '&limit=10&before_id=' + beforeId);
      const older = j.messages || [];
      state.hasMore = !!j.has_more;
      state.messages = older.concat(state.messages);
      renderMessages(false);

      // keep visual position stable
      const newScrollHeight = messagesEl.scrollHeight;
      messagesEl.scrollTop = prevScrollTop + (newScrollHeight - prevScrollHeight);
    }catch(e){
      showToast("Failed to load older messages");
    }finally{
      state.loadingOlder = false;
    }
  }

  function renderMessages(fullReplace){
    const hint = document.createElement('div');
    hint.className = 'loadHint';
    hint.id = 'loadHint';
    hint.textContent = state.hasMore ? "Scroll up to load older messages" : "No more messages";
    hint.style.display = 'block';

    if(fullReplace){
      messagesEl.innerHTML = "";
      messagesEl.appendChild(hint);
    }else{
      // keep current DOM and prepend via full redraw for simplicity
      messagesEl.innerHTML = "";
      messagesEl.appendChild(hint);
    }

    for(const m of state.messages){
      const row = document.createElement('div');
      const isMe = (m.sender && m.sender.username === state.me.username);
      row.className = 'row' + (isMe ? ' me' : '');

      const time = fmtTime(m.created_at);
      const sender = m.sender ? m.sender.display_name : "Unknown";

      let attHtml = "";
      if(m.attachment){
        const isImg = (m.attachment.mime || "").startsWith("image/");
        if(isImg){
          attHtml = `
            <div class="att">
              <a href="${m.attachment.url}" target="_blank" rel="noopener noreferrer">
                <img src="${m.attachment.url}" alt="${escapeHtml(m.attachment.orig_name || 'image')}" />
              </a>
              <div class="file">
                <a href="${m.attachment.url}" target="_blank" rel="noopener noreferrer">${escapeHtml(m.attachment.orig_name || 'image')}</a>
                <div class="size">${formatBytes(m.attachment.size || 0)}</div>
              </div>
            </div>
          `;
        }else{
          attHtml = `
            <div class="att">
              <div class="file">
                <a href="${m.attachment.url}" target="_blank" rel="noopener noreferrer">${escapeHtml(m.attachment.orig_name || 'file')}</a>
                <div class="size">${formatBytes(m.attachment.size || 0)}</div>
              </div>
            </div>
          `;
        }
      }

      row.innerHTML = `
        <div class="bubble">
          <div class="metaLine">
            <div class="sender">${escapeHtml(sender)}</div>
            <div class="time">${escapeHtml(time)}</div>
          </div>
          <div class="text">${linkify(m.text || "")}</div>
          ${attHtml}
        </div>
      `;
      messagesEl.appendChild(row);
    }
  }

  function scrollToBottom(){
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  function formatBytes(b){
    if(b < 1024) return b + " B";
    const kb = b/1024;
    if(kb < 1024) return kb.toFixed(1) + " KB";
    const mb = kb/1024;
    if(mb < 1024) return mb.toFixed(1) + " MB";
    const gb = mb/1024;
    return gb.toFixed(2) + " GB";
  }

  async function sendMessage(text, attachmentId){
    if(!state.activeGroupId) return;
    const payload = {group_id: state.activeGroupId, text: text || "", attachment_id: attachmentId || 0};
    await apiPost('/api/send', payload);
  }

  function autoGrow(){
    textEl.style.height = 'auto';
    textEl.style.height = Math.min(textEl.scrollHeight, 110) + 'px';
  }

  async function uploadFile(file){
    const fd = new FormData();
    fd.append('file', file);

    const r = await fetch('/api/upload', {method:'POST', body: fd, credentials:'same-origin'});
    const j = await r.json().catch(()=>({ok:false}));
    if(!r.ok || !j.ok) throw new Error(j.error || "upload_failed");
    return j.attachment;
  }

  async function ensureWs(){
    if(state.ws && (state.ws.readyState === 0 || state.ws.readyState === 1)) return;

    const proto = (location.protocol === 'https:') ? 'wss' : 'ws';
    const wsUrl = proto + '://' + location.host + '/ws';

    const ws = new WebSocket(wsUrl);
    state.ws = ws;

    ws.onopen = () => {
      // re-subscribe active group
      for(const gid of state.subscribed){
        wsSend({type:'subscribe', group_id: gid});
      }
      showToast("Connected");
    };
    ws.onmessage = (ev) => {
      let data = null;
      try{ data = JSON.parse(ev.data); }catch(e){ return; }
      if(data.type === 'message'){
        onIncomingMessage(data.message);
      }
    };
    ws.onclose = () => {
      setTimeout(()=> ensureWs(), 1200);
    };
    ws.onerror = () => {};
  }

  function wsSend(obj){
    try{
      if(state.ws && state.ws.readyState === 1){
        state.ws.send(JSON.stringify(obj));
      }
    }catch(e){}
  }

  async function ensureSubscribed(groupId){
    await ensureWs();
    if(state.subscribed.has(groupId)) return;
    state.subscribed.add(groupId);
    wsSend({type:'subscribe', group_id: groupId});
  }

  function onIncomingMessage(m){
    // update group list preview and unread count UI by reloading groups (simple and consistent)
    // but avoid spamming: do a lightweight update + occasional refresh
    const gid = m.group_id;

    // If active group, append and mark read
    if(state.activeGroupId === gid){
      state.messages.push(m);
      renderMessages(false);
      scrollToBottom();
      markReadIfNeeded(true);
    }else{
      // not active: just refresh groups to show unread dot/count
      loadGroups().catch(()=>{});
      showToast("New message in: " + (findGroupName(gid) || "a group"));
    }
  }

  function findGroupName(gid){
    const g = state.groups.find(x => x.id === gid);
    return g ? g.name : "";
  }

  async function markReadIfNeeded(force){
    if(!state.activeGroupId) return;
    if(state.messages.length === 0) return;
    const lastId = state.messages[state.messages.length - 1].id;

    const prev = state.lastReadSentByGroup.get(state.activeGroupId) || 0;
    if(!force && lastId <= prev) return;

    state.lastReadSentByGroup.set(state.activeGroupId, lastId);
    try{
      await apiPost('/api/mark_read', {group_id: state.activeGroupId, last_id: lastId});
      // refresh groups so unread counts disappear
      loadGroups().catch(()=>{});
    }catch(e){}
  }

  async function openGroupInfo(){
    if(!state.activeGroupId) return;
    try{
      const j = await apiGet('/api/group_info?group_id=' + state.activeGroupId);
      if(!j.ok) throw new Error("bad");
      modalTitle.textContent = j.group.name + " members";
      modalBody.innerHTML = "";
      for(const m of j.group.members){
        const div = document.createElement('div');
        div.className = 'member';
        const seen = humanSeen(m.last_seen_ago);
        div.innerHTML = `
          <div class="left">
            <div class="name">${escapeHtml(m.display_name)}</div>
            <div class="user">@${escapeHtml(m.username)}</div>
          </div>
          <div class="seen">${escapeHtml(seen)}</div>
        `;
        modalBody.appendChild(div);
      }
      modalBack.style.display = 'flex';
    }catch(e){
      showToast("Failed to load group info");
    }
  }

  // Events
  messagesEl.addEventListener('scroll', () => {
    if(messagesEl.scrollTop < 80){
      loadOlder();
    }
  });

  textEl.addEventListener('input', autoGrow);
  textEl.addEventListener('keydown', (e) => {
    if(e.key === 'Enter' && !e.shiftKey){
      e.preventDefault();
      sendBtn.click();
    }
  });

  sendBtn.addEventListener('click', async () => {
    const text = (textEl.value || "").trim();
    if(!text && !fileEl.files.length) return;

    sendBtn.disabled = true;

    try{
      let attachmentId = 0;
      if(fileEl.files.length){
        const f = fileEl.files[0];
        const att = await uploadFile(f);
        attachmentId = att.id;
        fileEl.value = "";
      }
      await sendMessage(text, attachmentId);
      textEl.value = "";
      autoGrow();
    }catch(e){
      showToast("Send failed");
    }finally{
      sendBtn.disabled = false;
    }
  });

  fileEl.addEventListener('change', () => {
    if(fileEl.files.length){
      const f = fileEl.files[0];
      if(f.size > (25 * 1024 * 1024)){
        showToast("File too large (max 25MB)");
        fileEl.value = "";
        return;
      }
      showToast("Selected: " + f.name);
    }
  });
  
  if(menuBtn && sidebarEl){
    menuBtn.addEventListener('click', () => {
      if(sidebarEl.classList.contains('open')) closeMenu();
      else openMenu();
    });
  }

  if(backdrop){
    backdrop.addEventListener('click', closeMenu);
  }

  window.addEventListener('resize', () => {
    if(!isMobile()) closeMenu();
  });
  
  infoBtn.addEventListener('click', openGroupInfo);
  modalClose.addEventListener('click', () => modalBack.style.display = 'none');
  modalBack.addEventListener('click', (e) => {
    if(e.target === modalBack) modalBack.style.display = 'none';
  });

  // Init
  (async function init(){
    await loadGroups();
    renderGroups();
    ensureWs().catch(()=>{});

    // Auto-open menu on mobile when no group is selected
    if(isMobile() && !state.activeGroupId){
      openMenu();
    }

    setInterval(()=> {
      wsSend({type:'ping'});
      markReadIfNeeded(false);
    }, 12000);
  })();
})();
</script>
</body>
</html>
"""


def main():
    global SECRET
    SECRET = read_secret()

    init_db()
    seed_data()

    app = build_app()
    print(f"[{APP_NAME}] Starting on http://{HOST}:{PORT}")
    web.run_app(app, host=HOST, port=PORT)


if __name__ == "__main__":
    main()
