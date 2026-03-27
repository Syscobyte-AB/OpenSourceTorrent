# TorrentVault

Advanced self-hosted torrent downloader. FastAPI + libtorrent backend with JWT auth, rate limiting, WebSocket live updates, per-torrent speed/file controls, SQLite/PostgreSQL database with full audit logging.

## Stack
- **Backend:** Python 3.11+ / FastAPI + libtorrent 2.0
- **Database:** SQLite (dev) / PostgreSQL (prod) via SQLAlchemy async
- **Auth:** JWT (HS256) + bcrypt passwords
- **Security:** Rate limiting, trusted hosts, security headers, CSP
- **Real-time:** WebSocket push (1s interval)
- **Frontend:** Single-page dark-themed dashboard

## Features
| Feature | Details |
|---|---|
| Dashboard | Live stats, user counts, recent activity |
| Magnet URI | Validated input |
| .torrent file upload | 10 MB limit, extension check |
| File selection | Per-file priority (0=skip, 7=high) |
| Speed limits | Per-torrent up/down |
| Pause / Resume | Per-torrent control |
| Delete + remove files | Optional file cleanup |
| Peer list | Up to 20 peers per torrent |
| Tracker list | Full tracker info |
| Piece map | First 500 pieces visualized |
| DHT / LSD / UPnP | Enabled by default |
| Sequential download | Optional per-torrent |
| JWT auth | 24h tokens, admin/user roles |
| User management | Create, update, disable, delete users (admin) |
| Audit log | Every action logged with timestamp, user, IP |
| Torrent history | Persistent records survive restarts |
| Rate limiting | slowapi (10 logins/min, 30 adds/min) |
| Security headers | CSP, X-Frame, nosniff, etc. |
| WebSocket live stats | /ws/torrents |
| Docker | Non-root, cap_drop ALL |

## Quick Start

### 1. Generate a secure secret key
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### 2. Generate a bcrypt password hash
```bash
python3 -c "import bcrypt; print(bcrypt.hashpw(b'yourpassword', bcrypt.gensalt()).decode())"
```

### 3. Create .env
```env
SECRET_KEY=your_generated_key_here
ADMIN_PASSWORD_HASH=your_bcrypt_hash_here
DOWNLOAD_DIR=/path/to/downloads
DOMAIN=yourdomain.com
DATABASE_URL=sqlite+aiosqlite:///./data/torrentvault.db
```

### 4. Run with Docker
```bash
docker-compose up -d
```

### 5. Run without Docker (dev)
```bash
# Install libtorrent (macOS)
brew install libtorrent-rasterbar

# Create venv with system-site-packages (required for libtorrent bindings)
/opt/homebrew/bin/python3 -m venv --system-site-packages venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Create data directory for SQLite
mkdir -p data

# Start the server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Open **http://localhost:8000** in your browser.

Default credentials: `admin` / `changeme`

## Database Setup

TorrentVault uses SQLite by default. Tables are **auto-created on first startup** and the default admin user is **auto-seeded**.

### Switch to PostgreSQL (production)
```env
# In .env
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/torrentvault
```
Install the async driver:
```bash
pip install asyncpg
```

### Database Tables
| Table | Purpose |
|---|---|
| `users` | User accounts with bcrypt hashes, roles, status |
| `torrent_records` | Persistent torrent history (survives restarts) |
| `audit_log` | Immutable log of every user action |

### Direct SQLite Queries
```bash
# List all tables
sqlite3 data/torrentvault.db ".tables"

# List all users
sqlite3 data/torrentvault.db "SELECT id, username, is_admin, is_active, created_at, last_login FROM users;"

# View recent audit log
sqlite3 data/torrentvault.db "SELECT id, timestamp, username, action, target, ip_address FROM audit_log ORDER BY id DESC LIMIT 20;"

# View torrent history
sqlite3 data/torrentvault.db "SELECT id, info_hash, name, source, added_by, status, created_at FROM torrent_records ORDER BY id DESC;"
```

## User Management

### Auto-seeded admin
On first startup, an `admin` user is created automatically using the `ADMIN_PASSWORD_HASH` from your `.env` file (or the default `changeme` password).

### Create users via API
```bash
# 1. Login as admin to get a token
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# 2. Create a regular user
curl -X POST http://localhost:8000/api/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"john","password":"secret123","is_admin":false}'

# 3. Create another admin user
curl -X POST http://localhost:8000/api/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin2","password":"secret456","is_admin":true}'

# 4. List all users
curl -s http://localhost:8000/api/users \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# 5. Disable a user
curl -X PUT http://localhost:8000/api/users/john \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"is_active":false}'

# 6. Change a user's password
curl -X PUT http://localhost:8000/api/users/john \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"password":"newpassword"}'

# 7. Delete a user
curl -X DELETE http://localhost:8000/api/users/john \
  -H "Authorization: Bearer $TOKEN"
```

### Create users via direct SQL
```bash
# Generate a bcrypt hash first
HASH=$(python3 -c "import bcrypt; print(bcrypt.hashpw(b'mypassword', bcrypt.gensalt()).decode())")

# Insert a regular user
sqlite3 data/torrentvault.db "INSERT INTO users (username, password_hash, is_admin, is_active) VALUES ('john', '$HASH', 0, 1);"

# Insert an admin user
sqlite3 data/torrentvault.db "INSERT INTO users (username, password_hash, is_admin, is_active) VALUES ('admin2', '$HASH', 1, 1);"

# Verify
sqlite3 data/torrentvault.db "SELECT id, username, is_admin, is_active FROM users;"
```

### Create users via the Web UI
1. Open http://localhost:8000
2. Login as admin
3. Click the **Users** tab
4. Fill in username, password, check Admin if needed
5. Click **Create User**

## API Reference

### Auth
```
POST /api/auth/login
Body: {"username": "admin", "password": "yourpassword"}
Returns: {"access_token": "...", "token_type": "bearer"}
```

### Dashboard
```
GET /api/dashboard
Header: Authorization: Bearer <token>
Returns: aggregated stats (libtorrent, users, torrents, audit)
```

### Add Magnet
```
POST /api/torrents/add/magnet
Header: Authorization: Bearer <token>
Body: {"magnet_uri": "magnet:?xt=...", "sequential": false}
```

### Add .torrent File
```
POST /api/torrents/add/file
Header: Authorization: Bearer <token>
Form: file=<torrent file>
```

### List Torrents
```
GET /api/torrents
Header: Authorization: Bearer <token>
```

### Torrent Detail
```
GET /api/torrents/{info_hash}
Header: Authorization: Bearer <token>
```

### Pause / Resume / Delete
```
POST /api/torrents/{info_hash}/pause
POST /api/torrents/{info_hash}/resume
DELETE /api/torrents/{info_hash}?delete_files=true
Header: Authorization: Bearer <token>
```

### Speed Limits
```
PUT /api/torrents/speed
Header: Authorization: Bearer <token>
Body: {"info_hash": "...", "download_kbps": 500, "upload_kbps": 100}
```

### File Selection
```
PUT /api/torrents/files
Header: Authorization: Bearer <token>
Body: {"info_hash": "...", "file_indices": [0, 2, 5]}
```

### Priority
```
PUT /api/torrents/priority
Header: Authorization: Bearer <token>
Body: {"info_hash": "...", "priority": 7}
```

### User Management (admin only)
```
GET    /api/users                  — List all users
POST   /api/users                  — Create user
PUT    /api/users/{username}       — Update user
DELETE /api/users/{username}       — Delete user
```

### Audit Log (admin only)
```
GET /api/audit?limit=100&offset=0&action=login&username=admin
Header: Authorization: Bearer <token>
```
Supported action filters: `login`, `login_failed`, `add_magnet`, `add_file`, `pause`, `resume`, `delete`, `set_speed`, `set_priority`, `set_files`, `user_create`, `user_update`, `user_delete`

### Torrent History (admin only)
```
GET /api/torrents/history?limit=50&offset=0&status=active
Header: Authorization: Bearer <token>
```

### WebSocket (live updates)
```
ws://localhost:8000/ws/torrents?token=<jwt>
```
Receives JSON every second with all torrent states + global stats.

### Health Check
```
GET /api/health
Returns: {"status": "ok", "version": "1.1.0"}
```

## Security Notes
- Change the default `admin`/`changeme` credentials immediately
- Run behind Nginx with TLS — never expose port 8000 directly
- Add your server IP to `ALLOWED_HOSTS`
- Consider `anonymous_mode = True` in `session_manager.py` for privacy
- The Docker container runs as UID 1000 with `cap_drop: ALL`
- All user actions are logged in the audit trail
- Failed login attempts are tracked with IP addresses

## Production Nginx Config (snippet)
```nginx
server {
    listen 443 ssl;
    server_name yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /ws/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
    }
}
```

## File Structure
```
torrentvault/
├── app/
│   ├── main.py             ← FastAPI app, routes, auth, middleware
│   ├── session_manager.py  ← libtorrent wrapper (core engine)
│   ├── config.py           ← Settings (env-driven, Pydantic v2)
│   ├── database.py         ← SQLAlchemy async engine + session
│   ├── models.py           ← User, TorrentRecord, AuditLog models
│   ├── audit.py            ← Audit logging helper
│   └── static/
│       └── index.html      ← Single-page web UI
├── data/
│   └── torrentvault.db     ← SQLite database (auto-created)
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env                    ← Environment config (not committed)
└── README.md
```

## Environment Variables
| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | random | JWT signing key |
| `ADMIN_PASSWORD_HASH` | hash of "changeme" | Bcrypt hash for initial admin |
| `DATABASE_URL` | `sqlite+aiosqlite:///./data/torrentvault.db` | Database connection string |
| `DOWNLOAD_DIR` | `~/Downloads` | Where to save downloaded files |
| `DOMAIN` | `localhost` | Server domain |
| `ALLOWED_ORIGINS` | `http://localhost:3000,http://localhost:8000` | CORS origins |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1` | Trusted host headers |
| `LISTEN_PORT_MIN` | `6881` | BitTorrent listen port start |
| `LISTEN_PORT_MAX` | `6891` | BitTorrent listen port end |
