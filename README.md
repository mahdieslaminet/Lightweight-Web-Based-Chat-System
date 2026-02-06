# ehiniumChat

**ehiniumChat** is a lightweight, private group chat system designed for Linux servers. 
It uses only system packages, stores data in SQLite, and provides a clean Telegram-like UI with realtime messaging.

This project is intentionally simple, auditable, and self-hosted.

## Features

- Private login (no public signup)
- User-defined groups and memberships
- Realtime messaging via WebSocket
- Message pagination (loads latest 10, loads older on scroll)
- Unread message dots and counters
- Group info panel (members + last seen)
- File upload with image preview
- Mobile responsive UI
- SQLite database (single file)
- No external services, no pip, no npm

## Requirements

- **Linux server (Ubuntu recommended, any version)**
- Root or sudo access
- Ability to install packages using `apt`
- Optional: domain + CDN (for HTTPS on client side)

Used system packages only:
- `python3`
- `python3-aiohttp`

## Important note for Iran access servers

If your server is **Iran-access (زمان قطعی اینترنت)**:

### 1) DNS resolution
Public resolvers like **8.8.8.8** or **1.1.1.1** usually do **not work**.

Make sure your server:
- Uses datacenter-provided DNS, or
- Uses Iranian DNS resolvers

### 2) Use Iranian apt mirrors
Default Ubuntu mirrors may fail.  
Recommended tools to switch mirrors automatically:

https://github.com/mexenon/syshelper  
https://github.com/GeeDook/mirava

After fixing mirrors:
```bash
sudo apt update
```

### Download project without GitHub access
If GitHub is blocked, download the packaged file from this mirror:  
```bash
https://uploadkon.ir/uploads/3cfb13_26ehiniumChat-tar.gz
```

## Installation

### 1) Install dependencies
```bash
sudo apt update
sudo apt install -y python3 python3-aiohttp
```

### 2) Create application directory
```bash
sudo mkdir -p /opt/ehiniumChat/uploads
```

### 3) Get the code
Option A: using GitHub:
```bash
git clone https://github.com/ehinium/ehiniumChat.git
sudo mkdir -p /opt/ehiniumChat
sudo cp -a ehiniumChat/* /opt/ehiniumChat/
```

Option B: using the Iranian mirror:
```bash
wget https://uploadkon.ir/uploads/3cfb13_26ehiniumChat-tar.gz
sudo tar -xzf ehiniumChat-tar.gz -C /
```

Ensure files exist:
```bash
ls /opt/ehiniumChat
```

Make executable:
```bash
sudo chmod +x /opt/ehiniumChat/app.py
sudo chmod +x /opt/ehiniumChat/admin_cli.py || true
```

### 4) Create secret key (required)
This key signs login cookies.

Generate:
```bash
python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
```

Create file:
```bash
sudo nano /opt/ehiniumChat/secret.key
```
Paste the generated hex string and save.

### 5) First run (manual test)
```bash
sudo python3 /opt/ehiniumChat/app.py
```

App starts on:  
`http://0.0.0.0:8080`

Open in browser:  
`http://SERVER_IP:8080`

Stop with Ctrl+C after confirming it works.

## Run as a system service (recommended)

### 1) Create systemd service
```bash
sudo nano /etc/systemd/system/ehiniumchat.service
```

Paste:
```bash
[Unit]
Description=ehiniumChat (aiohttp + sqlite)
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/ehiniumChat
ExecStart=/usr/bin/python3 /opt/ehiniumChat/app.py
Restart=always
RestartSec=2
User=root
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

### 2) Enable and start
```bash
sudo systemctl daemon-reload
sudo systemctl enable ehiniumchat
sudo systemctl restart ehiniumchat
sudo systemctl status ehiniumchat --no-pager
```

Logs:
```bash
sudo journalctl -u ehiniumchat -n 200 --no-pager
```

## CDN / HTTPS setup (optional)
Common setup:  
Browser to CDN is HTTPS, CDN to server is HTTP.

Requirements:  
- CDN must support WebSocket proxying
- Paths:
  - UI: /chat
  - WebSocket: /ws
  - Uploads: /uploads/

If CDN terminates HTTPS, browser uses wss automatically.

## Admin management (users, groups, members)
If admin_cli.py is present:

List users:
```bash
sudo /opt/ehiniumChat/admin_cli.py list-users
```

Add user (default password = username123):
```bash
sudo /opt/ehiniumChat/admin_cli.py add-user ali
```

Set password:
```bash
sudo /opt/ehiniumChat/admin_cli.py set-pass ali NewPassword
```

Add group:
```bash
sudo /opt/ehiniumChat/admin_cli.py add-group "My Group"
```

Add member to group:
```bash
sudo /opt/ehiniumChat/admin_cli.py add-member "My Group" ali
```

Rename group:
```bash
sudo /opt/ehiniumChat/admin_cli.py rename-group "Old Name" "New Name"
```

## Backup and migration

### Move to another server (keep data)
On old server:
```bash
sudo systemctl stop ehiniumchat
sudo tar -czf /root/ehiniumChat_backup.tgz -C /opt ehiniumChat
```

Copy archive to new server and extract:
```bash
sudo tar -xzf ehiniumChat_backup.tgz -C /
```
Reinstall packages and start service.

### Share with someone else (code only)
To give the software without your users/messages:
```bash
sudo tar -czf ehiniumChat_clean.tgz \
  /opt/ehiniumChat/app.py \
  /opt/ehiniumChat/admin_cli.py
```

**Do not share:**
- ehiniumchat.db
- uploads/
- secret.key

Recipient must create their own secret.key.

## Security notes (important)
- ISP cannot read messages if client to CDN is HTTPS
- CDN can read messages if origin is HTTP
- Datacenter network can read messages if origin is HTTP
- Messages are stored in plaintext in SQLite
- Passwords are stored in plaintext (by design)

This system is suitable for private groups and internal teams.

**It is not end-to-end encrypted.**
