#!/usr/bin/env python3
import sys
import sqlite3
from pathlib import Path

DB = "/opt/ehiniumChat/ehiniumchat.db"

def conn():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def die(msg, code=1):
    print(msg)
    sys.exit(code)

def get_user_id(c, username):
    r = c.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    return r["id"] if r else None

def get_group_id(c, name):
    r = c.execute("SELECT id FROM groups WHERE name=?", (name,)).fetchone()
    return r["id"] if r else None

def cmd_list_users():
    with conn() as c:
        rows = c.execute("SELECT username, display_name, is_admin FROM users ORDER BY username").fetchall()
        for r in rows:
            tag = " (admin)" if r["is_admin"] else ""
            print(f'{r["username"]} -> {r["display_name"]}{tag}')

def cmd_list_groups():
    with conn() as c:
        rows = c.execute("SELECT id, name FROM groups ORDER BY name COLLATE NOCASE").fetchall()
        for r in rows:
            print(f'{r["id"]}: {r["name"]}')

def cmd_group_members(group_name):
    with conn() as c:
        gid = get_group_id(c, group_name)
        if not gid:
            die("Group not found")
        rows = c.execute("""
            SELECT u.username, u.display_name
            FROM users u
            JOIN memberships m ON m.user_id=u.id
            WHERE m.group_id=?
            ORDER BY u.username
        """, (gid,)).fetchall()
        for r in rows:
            print(f'{r["username"]} ({r["display_name"]})')

def cmd_add_user(username, password=None, display_name=None, admin=False):
    if not password:
        password = username + "123"
    if not display_name:
        display_name = username[:1].upper() + username[1:]
    with conn() as c:
        c.execute("""
            INSERT INTO users (username, display_name, password, is_admin, last_seen)
            VALUES (?, ?, ?, ?, strftime('%s','now'))
        """, (username, display_name, password, 1 if admin else 0))
        c.commit()
    print("OK user added")

def cmd_set_password(username, password):
    with conn() as c:
        if not get_user_id(c, username):
            die("User not found")
        c.execute("UPDATE users SET password=? WHERE username=?", (password, username))
        c.commit()
    print("OK password updated")

def cmd_add_group(group_name):
    with conn() as c:
        c.execute("INSERT INTO groups (name) VALUES (?)", (group_name,))
        gid = c.execute("SELECT id FROM groups WHERE name=?", (group_name,)).fetchone()["id"]
        c.commit()
    print(f"OK group added id={gid}")

def cmd_rename_group(old, new):
    with conn() as c:
        gid = get_group_id(c, old)
        if not gid:
            die("Group not found")
        c.execute("UPDATE groups SET name=? WHERE id=?", (new, gid))
        c.commit()
    print("OK group renamed")

def cmd_add_member(group_name, username):
    with conn() as c:
        gid = get_group_id(c, group_name)
        if not gid:
            die("Group not found")
        uid = get_user_id(c, username)
        if not uid:
            die("User not found")
        c.execute("INSERT OR IGNORE INTO memberships (user_id, group_id) VALUES (?, ?)", (uid, gid))
        c.execute("INSERT OR IGNORE INTO last_read (user_id, group_id, last_read_msg_id) VALUES (?, ?, 0)", (uid, gid))
        c.commit()
    print("OK member added")

def cmd_remove_member(group_name, username):
    with conn() as c:
        gid = get_group_id(c, group_name)
        if not gid:
            die("Group not found")
        uid = get_user_id(c, username)
        if not uid:
            die("User not found")
        c.execute("DELETE FROM memberships WHERE user_id=? AND group_id=?", (uid, gid))
        c.execute("DELETE FROM last_read WHERE user_id=? AND group_id=?", (uid, gid))
        c.commit()
    print("OK member removed")

def cmd_delete_group(group_name):
    with conn() as c:
        gid = get_group_id(c, group_name)
        if not gid:
            die("Group not found")
        # Delete messages + attachments rows (files stay on disk, you can clean later)
        c.execute("DELETE FROM messages WHERE group_id=?", (gid,))
        c.execute("DELETE FROM memberships WHERE group_id=?", (gid,))
        c.execute("DELETE FROM last_read WHERE group_id=?", (gid,))
        c.execute("DELETE FROM groups WHERE id=?", (gid,))
        c.commit()
    print("OK group deleted (messages removed)")

def cmd_delete_user(username):
    if username == "ehsan":
        die("Refusing to delete admin user ehsan")
    with conn() as c:
        uid = get_user_id(c, username)
        if not uid:
            die("User not found")
        c.execute("DELETE FROM messages WHERE user_id=?", (uid,))
        c.execute("DELETE FROM memberships WHERE user_id=?", (uid,))
        c.execute("DELETE FROM last_read WHERE user_id=?", (uid,))
        c.execute("DELETE FROM users WHERE id=?", (uid,))
        c.commit()
    print("OK user deleted (their messages removed)")

def usage():
    print("""ehiniumChat admin CLI

List:
  admin_cli.py list-users
  admin_cli.py list-groups
  admin_cli.py members "Group Name"

Users:
  admin_cli.py add-user username [password] [display_name]
  admin_cli.py set-pass username newpassword
  admin_cli.py del-user username

Groups:
  admin_cli.py add-group "Group Name"
  admin_cli.py rename-group "Old" "New"
  admin_cli.py del-group "Group Name"

Membership:
  admin_cli.py add-member "Group Name" username
  admin_cli.py del-member "Group Name" username
""")

def main():
    if not Path(DB).exists():
        die("DB not found at " + DB)

    if len(sys.argv) < 2:
        usage()
        return

    cmd = sys.argv[1]

    if cmd == "list-users":
        cmd_list_users()
    elif cmd == "list-groups":
        cmd_list_groups()
    elif cmd == "members":
        if len(sys.argv) < 3: die("Missing group name")
        cmd_group_members(sys.argv[2])
    elif cmd == "add-user":
        if len(sys.argv) < 3: die("Missing username")
        username = sys.argv[2]
        password = sys.argv[3] if len(sys.argv) >= 4 else None
        display = sys.argv[4] if len(sys.argv) >= 5 else None
        cmd_add_user(username, password, display, admin=False)
    elif cmd == "set-pass":
        if len(sys.argv) < 4: die("Usage: set-pass username newpassword")
        cmd_set_password(sys.argv[2], sys.argv[3])
    elif cmd == "del-user":
        if len(sys.argv) < 3: die("Missing username")
        cmd_delete_user(sys.argv[2])
    elif cmd == "add-group":
        if len(sys.argv) < 3: die("Missing group name")
        cmd_add_group(sys.argv[2])
    elif cmd == "rename-group":
        if len(sys.argv) < 4: die("Usage: rename-group Old New")
        cmd_rename_group(sys.argv[2], sys.argv[3])
    elif cmd == "del-group":
        if len(sys.argv) < 3: die("Missing group name")
        cmd_delete_group(sys.argv[2])
    elif cmd == "add-member":
        if len(sys.argv) < 4: die("Usage: add-member Group username")
        cmd_add_member(sys.argv[2], sys.argv[3])
    elif cmd == "del-member":
        if len(sys.argv) < 4: die("Usage: del-member Group username")
        cmd_remove_member(sys.argv[2], sys.argv[3])
    else:
        usage()

if __name__ == "__main__":
    main()
