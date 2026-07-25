import asyncio
import json
import os
import sys
import hashlib

# Ensure the app directory is on the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import secrets
import time
import aiofiles
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from urllib.parse import quote
from collections import deque, defaultdict
import base64
import io
import logging

from shared import USER_CONNECTIONS, USER_CONNECTIONS_LOCK

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("Spider-Gateway")

try:
    import qrcode
    from PIL import Image
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False
    logger.warning("qrcode/PIL not installed -- QR endpoints will return 501")

from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx

IRAN_TZ = ZoneInfo("Asia/Tehran")

app = FastAPI(title="Spider Gateway", docs_url=None, redoc_url=None)

CONFIG = {
    "port": int(os.environ.get("PORT", 8080)),
    "secret": os.environ.get("SECRET_KEY", "spider-panel-secret-key-v2"),
    "host": os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost"),
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Persistence ───────────────────────────────────────────────────────────────
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
DATA_FILE = DATA_DIR / "spider_state.json"
SAVE_LOCK = asyncio.Lock()

async def load_state():
    global LINKS, AUTH, SUBS, USERS, SETTINGS, GROUPS, IP_POOL, IP_BLACKLIST, INBOUNDS
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if DATA_FILE.exists():
            async with aiofiles.open(DATA_FILE, "r", encoding="utf-8") as f:
                raw = await f.read()
            data = json.loads(raw)
            LINKS.update(data.get("links", {}))
            SUBS.update(data.get("subs", {}))
            USERS.update(data.get("users", {}))
            # Always load saved password hash (no secret-key guard — causes password reset bugs)
            if "password_hash" in data:
                AUTH["password_hash"] = data["password_hash"]
            # Also store saved_secret so future saves remain consistent
            if "saved_secret" in data:
                CONFIG["secret"] = data["saved_secret"]
            if "settings" in data:
                SETTINGS.update(data["settings"])
            GROUPS.update(data.get("groups", {}))
            INBOUNDS.update(data.get("inbounds", {}))
            IP_POOL.clear()
            IP_POOL.extend(data.get("ip_pool", []))
            IP_BLACKLIST.clear()
            IP_BLACKLIST.update(data.get("ip_blacklist", []))
            logger.info(f"State loaded: {len(LINKS)} links, {len(SUBS)} subs, {len(USERS)} users, {len(GROUPS)} groups, {len(IP_POOL)} ips, {len(INBOUNDS)} inbounds")
            # Restore user connection tracking
            if "user_connections" in data:
                USER_CONNECTIONS.clear()
                for uid, conns in data["user_connections"].items():
                    USER_CONNECTIONS[uid] = set(conns)
    except Exception as e:
        logger.warning(f"Could not load state: {e}")
    # Connections are transient — always start fresh on load
    USER_CONNECTIONS.clear()
    # Rebuild path index from all users and links
    _rebuild_path_index()
    # Migrate: auto-create links for users that have config_uuid but no link
    _migrate_user_links()


def _migrate_user_links():
    """Ensure every user with a config_uuid has a corresponding link in LINKS."""
    created = 0
    for uid, u in USERS.items():
        cuuid = u.get("config_uuid")
        if not cuuid:
            continue
        if cuuid in LINKS:
            continue
        LINKS[cuuid] = {
            "label": u.get("username", uid),
            "limit_bytes": u.get("traffic_limit_bytes", 0),
            "used_bytes": u.get("traffic_used_bytes", 0),
            "created_at": u.get("created_at", datetime.now().isoformat()),
            "active": (u.get("status", "active") == "active"),
            "expires_at": u.get("expire_at"),
            "note": f"لینک کاربر {u.get('username', uid)}",
            "is_default": False,
            "sub_id": None,
            "protocol": u.get("protocol", "vless"),
            "path": (u.get("path") or "").strip().lstrip("/"),
            "user_id": uid,
        }
        created += 1
    if created:
        logger.info(f"_migrate_user_links: created {created} missing links for existing users")


def _rebuild_path_index():
    """Rebuild PATH_INDEX from all USERS and LINKS with stored paths."""
    PATH_INDEX.clear()
    # From users — store clean path (no /ws/ prefix)
    for uid, u in USERS.items():
        path = (u.get("path") or "").strip().lstrip("/")
        # Strip any old /ws/ prefix from stored paths
        if path.startswith("ws/"):
            path = path[3:]
        config_uuid = u.get("config_uuid") or uid
        if path:
            PATH_INDEX[path] = config_uuid
    # From legacy links
    for lid, link in LINKS.items():
        link_path = (link.get("path") or "").strip().lstrip("/")
        if link_path.startswith("ws/"):
            link_path = link_path[3:]
        if link_path:
            PATH_INDEX[link_path] = lid
    # Backward compat: index by config_uuid for old /ws/{uuid} clients
    for uid, u in USERS.items():
        config_uuid = u.get("config_uuid") or uid
        PATH_INDEX[config_uuid] = config_uuid
    logger.info(f"PATH_INDEX rebuilt: {len(PATH_INDEX)} entries")

async def save_state():
    async with SAVE_LOCK:
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            data = {
                "links": dict(LINKS),
                "users": dict(USERS),
                "subs": dict(SUBS),
                "settings": dict(SETTINGS),
                "groups": dict(GROUPS),
                "inbounds": dict(INBOUNDS),
                "ip_pool": list(IP_POOL),
                "ip_blacklist": list(IP_BLACKLIST),
                "password_hash": AUTH["password_hash"],
                "saved_secret": CONFIG["secret"],
                "saved_at": datetime.now().isoformat(),
                "user_connections": {k: list(v) for k, v in USER_CONNECTIONS.items()},  # Save user connection tracking for IP limit compliance
            }
            tmp = DATA_FILE.with_suffix(".tmp")
            async with aiofiles.open(tmp, "w", encoding="utf-8") as f:
                await f.write(json.dumps(data, ensure_ascii=False, indent=2))
            tmp.replace(DATA_FILE)
        except Exception as e:
            logger.warning(f"Could not save state: {e}")

# ── In-memory state ───────────────────────────────────────────────────────────
connections: dict = {}
stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}
error_logs: deque = deque(maxlen=50)
activity_logs: deque = deque(maxlen=200)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None
LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()
PATH_INDEX: dict = {}          # random_path -> uuid
PATH_INDEX_LOCK = asyncio.Lock()
SUBS: dict = {}
SUBS_LOCK = asyncio.Lock()
USERS: dict = {}
USERS_LOCK = asyncio.Lock()

# ── Settings ──────────────────────────────────────────────────────────────
SETTINGS = {
    "websocket_mode": True,
    "xhttp_mode": True,
    "default_connection_mode": "ws",  # ws, xhttp, tcp
    "max_ip_per_user": 3,
    "bandwidth_limit_mbps": 100,
    "live_monitoring": True,
    "auto_ip_rotation": False,
    "security_token": secrets.token_urlsafe(16),
    # Custom backgrounds (uploaded by admin)
    "bg_login": "",
    "bg_dashboard": "",
    "bg_sub": "",
    # Panel audio (uploaded by admin)
    "panel_audio": "",
    "panel_audio_enabled": False,
    # Reality defaults (3x-ui style)
    "reality": {
        "port": 1234,
        "dest": "is1-ssl.mzstatic.com:443",
        "sni": "is1-ssl.mzstatic.com",
        "public_key": "",
        "private_key": "",
        "short_id": "5a3ff5a13d",
        "spiderx": "/",
        "fingerprint": "chrome",
        "external_domain": "",
        "external_port": 443,
    },
    # XHTTP settings (3x-ui style)
    "xhttp": {
        "path": "/",
        "host": "",
        "mode": "auto",
        "xPaddingBytes": "100-1000",
        "scMaxEachPostBytes": "1000000",
        "scMaxBufferedPosts": 30,
        "scStreamUpServerSecs": "20-80",
    },
}
SETTINGS_LOCK = asyncio.Lock()

# ── Inbounds (for user config generation) ────────────────────────────────
INBOUNDS: dict = {}  # inbound_id → {name, protocol, port, network, security, domain, sni, external_port, fingerprint, reality_settings, xhttp_settings, created_at}
INBOUNDS_LOCK = asyncio.Lock()

# ── Groups ─────────────────────────────────────────────────────────────────
GROUPS: dict = {}  # group_id → {name, description, user_ids, ip_pool, rules, created_at}
GROUPS_LOCK = asyncio.Lock()

# ── IP Pool & Blacklist ────────────────────────────────────────────────────
IP_POOL: list = []  # list of {ip, status, latency_ms, location, assigned_user, last_check}
IP_POOL_LOCK = asyncio.Lock()
IP_BLACKLIST: set = set()
IP_BLACKLIST_LOCK = asyncio.Lock()

# ── IP per user tracking ───────────────────────────────────────────────────
USER_IP_MAP: dict = defaultdict(set)  # user_id → set of IPs used
USER_IP_MAP_LOCK = asyncio.Lock()

# پروتکل‌های پشتیبانی‌شده برای هر کانفیگ
PROTOCOLS = ("vless-ws", "xhttp-packet-up", "xhttp-stream-up", "xhttp-stream-one")

USER_PROTOCOLS = ("vless", "vmess", "trojan", "shadowsocks", "reality")
DEFAULT_PROTOCOL = "vless-ws"

def log_activity(kind: str, message: str, level: str = "info"):
    """ثبت یک رخداد در لاگ فعالیت‌ها (ساخت/حذف/ویرایش کانفیگ، ورود، و...)."""
    activity_logs.append({
        "kind": kind,
        "level": level,
        "message": message,
        "time": datetime.now().isoformat(),
    })

# ── Auth ──────────────────────────────────────────────────────────────────────
SESSION_COOKIE = "spider_session"
SESSION_TTL = 60 * 60 * 24 * 7

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

AUTH = {"password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "admin"))}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token: str | None) -> bool:
    if not token:
        return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None:
            return False
        if exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def destroy_session(token: str | None):
    if not token:
        return
    async with SESSIONS_LOCK:
        SESSIONS.pop(token, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

# ── Startup / Shutdown ────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global http_client
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(
        limits=limits, timeout=timeout, follow_redirects=True,
    )
    await load_state()
    # Auto-create default inbound if none exist
    async with INBOUNDS_LOCK:
        if not INBOUNDS:
            INBOUNDS["default"] = {
                "name": "VLESS+WS پیش‌فرض",
                "protocol": "vless",
                "port": 443,
                "network": "ws",
                "security": "tls",
                "domain": SETTINGS.get("domain", get_host()),
                "sni": "",
                "external_port": 443,
                "fingerprint": "chrome",
                "reality_settings": {},
                "xhttp_settings": {},
                "created_at": datetime.now().isoformat(),
            }
            asyncio.create_task(save_state())
            log_activity("inbound", "اینباند پیش‌فرض VLESS+WS ساخته شد", "ok")
    log_activity("system", "سرور راه‌اندازی شد", "ok")
    logger.info(f"Spider Gateway v9.2 started on port {CONFIG['port']}")

@app.on_event("shutdown")
async def shutdown():
    await save_state()
    if http_client:
        await http_client.aclose()

# ── Helpers ───────────────────────────────────────────────────────────────────
def get_host() -> str:
    return os.environ.get("RAILWAY_PUBLIC_DOMAIN", CONFIG["host"])

def generate_uuid() -> str:
    """Generate a 32-char hex identifier (no dashes) — compatible with Xray/VLESS configs."""
    return secrets.token_hex(16)


def generate_random_path(prefix: str = "", length: int = 6) -> str:
    """Generate a URL-safe random path segment once per user.

    Returns a path like /a83d91c5, /api-f7a29c, /cdn-91ad3b2f.
    Called ONCE at user creation time then stored permanently.
    """
    if prefix:
        return f"/{prefix}-{secrets.token_hex(length)}"
    return f"/{secrets.token_hex(length)}"


def now_ir() -> datetime:
    return datetime.now(IRAN_TZ)

def generate_vless_link(uuid: str, host: str, remark: str = "Spider", protocol: str = DEFAULT_PROTOCOL) -> str:
    """می‌سازد VLESS share-link متناسب با پروتکل انتخاب‌شده (WS کلاسیک یا یکی از مدهای XHTTP)."""
    if protocol == "vless-ws":
        path = f"/ws/{uuid}"
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "ws",
            "host": host,
            "path": path,
            "sni": host,
            "fp": "chrome",
            "alpn": "http/1.1",
        }
    else:
        # xhttp-packet-up / xhttp-stream-up / xhttp-stream-one
        mode = protocol.replace("xhttp-", "")  # packet-up | stream-up | stream-one
        path = f"/xhttp-siz10/{mode}/{uuid}"
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "xhttp",
            "mode": mode,
            "host": host,
            "path": path,
            "sni": host,
            "fp": "chrome",
            "alpn": "h2,http/1.1",
        }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{host}:443?{query}#{quote(remark)}"

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def uptime_secs():
    return max(time.time() - stats["start_time"], 1)

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 ** 3)
    if unit == "MB": return int(value * 1024 ** 2)
    if unit == "KB": return int(value * 1024)
    return int(value)

def is_link_expired(link: dict) -> bool:
    exp = link.get("expires_at")
    if not exp:
        return False
    try:
        return datetime.now() > datetime.fromisoformat(exp)
    except Exception:
        return False

def is_link_allowed(link: dict | None) -> bool:
    if link is None:
        return False
    if not link.get("active", True):
        return False
    if is_link_expired(link):
        return False
    lb = link.get("limit_bytes", 0)
    if lb > 0 and link.get("used_bytes", 0) >= lb:
        return False
    return True

def fmt_bytes(b: int) -> str:
    if b < 1024: return f"{b} B"
    if b < 1024**2: return f"{b/1024:.1f} KB"
    if b < 1024**3: return f"{b/1024**2:.2f} MB"
    return f"{b/1024**3:.2f} GB"

def client_ip(request: Request) -> str:
    """آی‌پی واقعی کلاینت رو با احتساب هدرهای پراکسی (Railway/Cloudflare) برمی‌گردونه."""
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "نامشخص"


# ── User helper functions ────────────────────────────────────────────────────
def is_user_allowed(user: dict | None) -> bool:
    """Check if a user is active and not expired."""
    if user is None:
        return False
    if user.get("status") == "disabled":
        return False
    if user.get("status") == "expired":
        return False
    exp = user.get("expire_at")
    if exp:
        try:
            if datetime.now() > datetime.fromisoformat(exp):
                user["status"] = "expired"
                return False
        except Exception:
            pass
    lb = user.get("traffic_limit_bytes", 0)
    if lb > 0 and user.get("traffic_used_bytes", 0) >= lb:
        return False
    return True

def auto_check_user_expiry(user: dict):
    """Auto-mark user as expired if past expire_at."""
    if not user:
        return
    exp = user.get("expire_at")
    if not exp:
        return
    try:
        if datetime.now() > datetime.fromisoformat(exp):
            if user.get("status") not in ("expired", "disabled"):
                user["status"] = "expired"
    except Exception:
        pass

def generate_short_id() -> str:
    """Generate a shorter ID for user management."""
    return secrets.token_hex(6)

def generate_user_config(user_id: str, user: dict, inbound_id: str = None) -> str:
    """Generate a connection config string for a user based on their protocol."""
    # Get settings from inbound if specified
    inbound = None
    if inbound_id:
        inbound = INBOUNDS.get(inbound_id)
    # Determine proper host for config generation
    # Priority: inbound external_domain > inbound domain > SETTINGS domain > get_host()
    host = (inbound.get("external_domain") if inbound else None) or (inbound.get("domain") if inbound else None) or SETTINGS.get("domain") or get_host()
    # Never use 0.0.0.0 or localhost in public configs
    if host in ("0.0.0.0", "127.0.0.1", "localhost", ""):
        host = CONFIG.get("host", "") or "SERVER_IP"
    # Protocol from user FIRST, then inbound, then default
    protocol = user.get("protocol") or (inbound.get("protocol") if inbound else None) or "vless"
    config_uuid = user.get("config_uuid", "")
    username = user.get("username", user_id)
    remark = quote(f"Spider-{username}")
    sni = user.get("sni") or (inbound.get("sni") if inbound else None) or host
    # Transport from user FIRST, then inbound, then default
    transport_type = user.get("transport_type") or (inbound.get("network") if inbound else None) or "ws"

    # ── Path: READ-ONLY, from user storage (generated once at creation) ──
    # Priority: inbound ws_settings/xhttp_settings > user stored path > generate+store (legacy)
    stored_path = (user.get("path") or "").strip()
    # Inbound override takes priority
    if inbound:
        ib_ws = inbound.get("ws_settings", {})
        if ib_ws and ib_ws.get("path"):
            stored_path = ib_ws["path"]
        ib_xh = inbound.get("xhttp_settings", {})
        if ib_xh and ib_xh.get("path"):
            stored_path = ib_xh["path"]
        ib_grpc = inbound.get("grpc_settings", {})
        if ib_grpc and ib_grpc.get("serviceName"):
            stored_path = ib_grpc["serviceName"]
    # Legacy users without path: generate once, store, persist
    if not stored_path:
        stored_path = generate_random_path()
        user["path"] = stored_path
        USERS[user_id] = user
        asyncio.create_task(save_state())

    # ── Reality Protocol ──
    if protocol == "reality":
        rs = inbound.get("reality_settings", {}) if inbound else SETTINGS.get("reality", {})
        xs = inbound.get("xhttp_settings", {}) if inbound else SETTINGS.get("xhttp", {})
        # Fallback to global if inbound settings are empty
        if not rs:
            rs = SETTINGS.get("reality", {})
        if not xs:
            xs = SETTINGS.get("xhttp", {})
        reality_pbk = rs.get("public_key", "")
        reality_sid = rs.get("short_id", "5a3ff5a13d")
        reality_spx = rs.get("spiderx", "/")
        reality_fp = (inbound.get("fingerprint") if inbound else None) or rs.get("fingerprint", "chrome")
        sni_reality = sni if sni and sni != host else rs.get("sni", "is1-ssl.mzstatic.com")
        ext_domain = (inbound.get("external_domain") if inbound else None) or (inbound.get("domain") if inbound else None) or rs.get("external_domain") or host
        ext_port = (inbound.get("external_port") if inbound else None) or rs.get("external_port", 443) or 443
        if not reality_pbk or not reality_sid:
            return f"vless://{config_uuid}@{ext_domain}:{ext_port}?encryption=none&security=reality&sni={quote(sni_reality)}&fp={reality_fp}&pbk=MISSING_PBK&sid=MISSING_SID&type=tcp#{remark}"
        rpath = stored_path if stored_path else xs.get("path", "/")
        rt = user.get("transport_type") or (inbound.get("network") if inbound else None) or "xhttp"
        if rt == "xhttp":
            xpb = xs.get("xPaddingBytes", "100-1000")
            xmod = xs.get("mode", "auto")
            xsc = xs.get("scMaxEachPostBytes", "1000000")
            extra_raw = '{{"xPaddingBytes":"{}","mode":"{}","scMaxEachPostBytes":"{}"}}'.format(xpb, xmod, xsc)
            extra = quote(extra_raw, safe='')
            params = (f"encryption=none&security=reality"
                      f"&sni={quote(sni_reality)}&fp={reality_fp}"
                      f"&pbk={reality_pbk}&sid={reality_sid}&spx={quote(reality_spx, safe='')}"
                      f"&type=xhttp&path={rpath}&mode={xmod}&extra={extra}")
        else:
            params = (f"encryption=none&security=reality&type=tcp"
                      f"&sni={quote(sni_reality)}&fp={reality_fp}&alpn=h2,http/1.1"
                      f"&pbk={reality_pbk}&sid={reality_sid}&spx={quote(reality_spx, safe='')}")
        return f"vless://{config_uuid}@{ext_domain}:{ext_port}?{params}#{remark}"

    # ── VLESS ──
    if protocol == "vless":
        vless_host = (inbound.get("external_domain") if inbound else None) or (inbound.get("domain") if inbound else None) or host
        vless_port = (inbound.get("external_port") if inbound else None) or (inbound.get("port") if inbound else None) or 443
        if transport_type == "grpc":
            params = f"encryption=none&security=tls&type=grpc&serviceName={quote(stored_path, safe='')}&host={quote(vless_host)}&sni={quote(sni)}&fp=chrome&alpn=h2"
            return f"vless://{config_uuid}@{vless_host}:{vless_port}?{params}#{remark}"
        elif transport_type == "tcp":
            params = f"encryption=none&security=tls&type=tcp&host={quote(vless_host)}&sni={quote(sni)}&fp=chrome&alpn=h2,http/1.1"
            return f"vless://{config_uuid}@{vless_host}:{vless_port}?{params}#{remark}"
        elif transport_type == "xhttp":
            # Read xhttp settings from user's link in LINKS (sync access ok — single-thread)
            xh = {}
            lk = LINKS.get(config_uuid)
            if lk:
                xh = lk.get("xhttp_settings", {})
            xpad = xh.get("xPaddingBytes", "100-1000")
            xmode = xh.get("mode", "auto")
            xsc = xh.get("scMaxEachPostBytes", "1000000")
            extra_raw = '{{"xPaddingBytes":"{}","mode":"{}","scMaxEachPostBytes":"{}"}}'.format(xpad, xmode, xsc)
            extra = quote(extra_raw, safe='')
            params = f"encryption=none&security=tls&type=xhttp&host={quote(vless_host)}&path={quote(stored_path, safe='')}&sni={quote(sni)}&fp=chrome&alpn=h2,http/1.1&mode={xmode}&extra={extra}"
            return f"vless://{config_uuid}@{vless_host}:{vless_port}?{params}#{remark}"
        else:  # ws — config_uuid IS the path (same as reference RVG-main)
            ws_host = (inbound.get("domain") if inbound else None) or SETTINGS.get("domain") or host
            ws_sni = sni if sni and sni != host else ws_host
            ws_path = f"/ws/{config_uuid}"
            params = "&".join([
                "encryption=none",
                "security=tls",
                f"type=ws",
                f"host={quote(ws_host)}",
                f"path={quote(ws_path, safe='')}",
                f"sni={quote(ws_sni)}",
                "fp=chrome",
                "alpn=http/1.1",
            ])
            vless_host = (inbound.get("external_domain") if inbound else None) or (inbound.get("domain") if inbound else None) or ws_host
            vless_port = (inbound.get("external_port") if inbound else None) or (inbound.get("port") if inbound else None) or 443
            return f"vless://{config_uuid}@{vless_host}:{vless_port}?{params}#{remark}"

    # ── VMess ──
    elif protocol == "vmess":
        vmess_net = transport_type if transport_type != "xhttp" else "ws"
        vmess_config = {
            "v": "2",
            "ps": username,
            "add": host,
            "port": "443",
            "id": config_uuid,
            "aid": "0",
            "scy": "auto",
            "net": vmess_net,
            "type": "none",
            "host": sni,
            "path": stored_path if transport_type != "grpc" else "",
            "tls": "tls",
            "sni": sni,
        }
        if transport_type == "grpc":
            vmess_config["type"] = "gun"
            vmess_config["path"] = stored_path
        encoded = base64.b64encode(json.dumps(vmess_config).encode()).decode()
        return f"vmess://{encoded}"

    # ── Trojan ──
    elif protocol == "trojan":
        if transport_type == "grpc":
            params_t = f"security=tls&type=grpc&serviceName={stored_path}&host={sni}&sni={sni}"
        elif transport_type == "xhttp":
            params_t = f"security=tls&type=xhttp&host={sni}&path={stored_path}&sni={sni}"
        elif transport_type == "tcp":
            params_t = f"security=tls&type=tcp&host={sni}&sni={sni}"
        else:
            params_t = f"security=tls&type=ws&host={sni}&path={stored_path}&sni={sni}"
        return f"trojan://{quote(config_uuid)}@{host}:443?{params_t}#{remark}"

    # ── Shadowsocks ──
    elif protocol == "shadowsocks":
        method = "aes-256-gcm"
        ss_encoded = base64.b64encode(f"{method}:{config_uuid}".encode()).decode()
        return f"ss://{ss_encoded}@{host}:8443#{remark}"

    return ""


# ── Default link ──────────────────────────────────────────────────────────────
_default_link_created = False

async def ensure_default_link():
    global _default_link_created
    if _default_link_created:
        return
    async with LINKS_LOCK:
        if not any(l.get("is_default") for l in LINKS.values()):
            uid = hashlib.sha256(f"default{CONFIG['secret']}".encode()).hexdigest()
            uid = f"{uid[:8]}-{uid[8:12]}-{uid[12:16]}-{uid[16:20]}-{uid[20:32]}"
            if uid not in LINKS:
                LINKS[uid] = {
                    "label": "لینک پیش‌فرض",
                    "limit_bytes": 0,
                    "used_bytes": 0,
                    "created_at": datetime.now().isoformat(),
                    "active": True,
                    "expires_at": None,
                    "note": "",
                    "is_default": True,
                    "sub_id": None,
                    "protocol": DEFAULT_PROTOCOL,
                }
                asyncio.create_task(save_state())
        _default_link_created = True

# ── Basic endpoints ───────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"service": "Spider Gateway", "version": "9.2", "status": "active", "channel": "https://t.me/SpiderPanel"}

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

# ── Subscription ping (must be before /sub/{{identifier}}) ──────────────────
@app.get("/sub/{identifier}/ping")
async def sub_ping_handler(identifier: str):
    """Ping endpoint for subscription page — returns a simple response."""
    # Check user first
    async with USERS_LOCK:
        for u in USERS.values():
            if u.get("username") == identifier and u.get("status") == "active":
                return {"ok": True, "ping": "pong", "username": identifier}
    # Fallback: check if it's a link
    async with LINKS_LOCK:
        link = LINKS.get(identifier)
    if link and is_link_allowed(link):
        return {"ok": True, "ping": "pong", "uuid": identifier}
    raise HTTPException(status_code=404, detail="User not found")


# ── Subscription (single link / user sub page) ──────────────────────────────
@app.get("/sub/{identifier}")
async def subscription_handler(identifier: str, request: Request):
    """Smart handler: checks users first, then links by UUID."""
    # 1) Check if it's a user (serve HTML sub page)
    async with USERS_LOCK:
        for uid, u in USERS.items():
            if u.get("username") == identifier:
                return FileResponse(_os.path.join(_STATIC_DIR, "sub.html"))

    # 2) Check if it's a link UUID (return base64 config)
    import base64
    async with LINKS_LOCK:
        link = LINKS.get(identifier)
    if link and is_link_allowed(link):
        host = SETTINGS.get("domain") or get_host()
        proto = link.get("protocol", DEFAULT_PROTOCOL)
        vless = generate_vless_link(identifier, host, remark=f"Spider-{link['label']}", protocol=proto)
        content = base64.b64encode(vless.encode()).decode()
        return Response(content=content, media_type="text/plain",
                        headers={"profile-title": quote(link["label"]), "support-url": "https://t.me/Spiderـvpn1"})

    raise HTTPException(status_code=404, detail="not found")

@app.get("/sub-all")
async def subscription_all(_=Depends(require_auth)):
    import base64
    host = SETTINGS.get("domain") or get_host()
    async with LINKS_LOCK:
        lines = [
            generate_vless_link(uid, host, remark=f"Spider-{d['label']}", protocol=d.get("protocol", DEFAULT_PROTOCOL))
            for uid, d in LINKS.items()
            if is_link_allowed(d)
        ]
    content = base64.b64encode("\n".join(lines).encode()).decode()
    return Response(content=content, media_type="text/plain")

# ══════════════════════════════════════════════════════════════════════════════
# SUB GROUP endpoints
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/subs")
async def create_sub(request: Request, _=Depends(require_auth)):
    body = await request.json()
    name = (body.get("name") or "گروه جدید").strip()[:60]
    desc = (body.get("desc") or body.get("description") or "").strip()[:200]
    password = (body.get("password") or "").strip()
    sub_id = generate_uuid()
    uuid_key = secrets.token_urlsafe(16)
    async with SUBS_LOCK:
        SUBS[sub_id] = {
            "name": name,
            "desc": desc,
            "password_hash": hash_password(password) if password else None,
            "uuid_key": uuid_key,
            "created_at": datetime.now().isoformat(),
            "link_ids": [],
        }
    asyncio.create_task(save_state())
    log_activity("sub", f"گروه «{name}» ساخته شد", "ok")
    host = SETTINGS.get("domain") or get_host()
    return {
        "sub_id": sub_id,
        **SUBS[sub_id],
        "public_url": f"https://{host}/p/{uuid_key}",
        "sub_url": f"https://{host}/sub-group/{uuid_key}",
    }

@app.get("/api/subs")
async def list_subs(_=Depends(require_auth)):
    host = SETTINGS.get("domain") or get_host()
    async with SUBS_LOCK:
        snap_subs = dict(SUBS)
    async with LINKS_LOCK:
        snap_links = dict(LINKS)
    result = []
    for sid, s in snap_subs.items():
        link_ids = s.get("link_ids", [])
        active_count = sum(1 for lid in link_ids if is_link_allowed(snap_links.get(lid)))
        total_used = sum(snap_links[lid].get("used_bytes", 0) for lid in link_ids if lid in snap_links)
        result.append({
            "sub_id": sid,
            **s,
            "password_hash": None,
            "has_password": s.get("password_hash") is not None,
            "links_count": len(link_ids),
            "active_count": active_count,
            "total_used_bytes": total_used,
            "total_used_fmt": fmt_bytes(total_used),
            "public_url": f"https://{host}/p/{s['uuid_key']}",
            "sub_url": f"https://{host}/sub-group/{s['uuid_key']}",
        })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"subs": result}

@app.patch("/api/subs/{sub_id}")
async def update_sub(sub_id: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="sub not found")
        s = SUBS[sub_id]
        if "name" in body:
            s["name"] = str(body["name"])[:60]
        if "desc" in body:
            s["desc"] = str(body["desc"])[:200]
        if "password" in body:
            pw = str(body["password"]).strip()
            s["password_hash"] = hash_password(pw) if pw else None
        if "link_ids" in body:
            s["link_ids"] = list(body["link_ids"])
    asyncio.create_task(save_state())
    return {"ok": True}

@app.delete("/api/subs/{sub_id}")
async def delete_sub(sub_id: str, _=Depends(require_auth)):
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="sub not found")
        name = SUBS[sub_id].get("name", sub_id)
        del SUBS[sub_id]
    async with LINKS_LOCK:
        for link in LINKS.values():
            if link.get("sub_id") == sub_id:
                link["sub_id"] = None
    asyncio.create_task(save_state())
    log_activity("sub", f"گروه «{name}» حذف شد", "warn")
    return {"ok": True, "deleted": sub_id}

@app.post("/api/subs/{sub_id}/links")
async def assign_link_to_sub(sub_id: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    link_id = str(body.get("link_id", ""))
    action = str(body.get("action", "add"))
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="sub not found")
        s = SUBS[sub_id]
        ids = s.setdefault("link_ids", [])
        if action == "add":
            if link_id not in ids:
                ids.append(link_id)
        else:
            if link_id in ids:
                ids.remove(link_id)
    async with LINKS_LOCK:
        if link_id in LINKS:
            LINKS[link_id]["sub_id"] = sub_id if action == "add" else None
    asyncio.create_task(save_state())
    return {"ok": True}

# ── Public sub-group subscription file ───────────────────────────────────────
@app.get("/sub-group/{uuid_key}")
async def sub_group_subscription(uuid_key: str, request: Request):
    import base64
    async with SUBS_LOCK:
        sub = next((s for s in SUBS.values() if s.get("uuid_key") == uuid_key), None)
    if not sub:
        raise HTTPException(status_code=404, detail="not found")

    if sub.get("password_hash"):
        pw = request.query_params.get("pw", "")
        if hash_password(pw) != sub["password_hash"]:
            raise HTTPException(status_code=403, detail="wrong password")

    host = SETTINGS.get("domain") or get_host()
    link_ids = sub.get("link_ids", [])
    async with LINKS_LOCK:
        lines = []
        for lid in link_ids:
            link = LINKS.get(lid)
            if link and is_link_allowed(link):
                lines.append(generate_vless_link(lid, host, remark=f"Spider-{link['label']}", protocol=link.get("protocol", DEFAULT_PROTOCOL)))

    content = base64.b64encode("\n".join(lines).encode()).decode()
    return Response(
        content=content,
        media_type="text/plain",
        headers={
            "profile-title": quote(sub["name"]),
            "support-url": "https://t.me/SpiderPanel",
            "profile-update-interval": "12",
        }
    )

# ── Auth endpoints ────────────────────────────────────────────────────────────
@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    ip = client_ip(request)
    if hash_password(str(body.get("password", ""))) != AUTH["password_hash"]:
        log_activity("auth", f"تلاش ورود ناموفق از {ip}", "err")
        raise HTTPException(status_code=401, detail="رمز عبور اشتباه است")
    token = await create_session()
    log_activity("auth", f"ورود موفق به پنل از {ip}", "ok")
    resp = JSONResponse({"ok": True})
    resp.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    await destroy_session(request.cookies.get(SESSION_COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    return {"authenticated": await is_valid_session(request.cookies.get(SESSION_COOKIE))}

@app.post("/api/change-password")
async def api_change_password(request: Request, token=Depends(require_auth)):
    body = await request.json()
    if hash_password(str(body.get("current_password", ""))) != AUTH["password_hash"]:
        raise HTTPException(status_code=400, detail="رمز فعلی اشتباه است")
    new = str(body.get("new_password", ""))
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="رمز جدید باید حداقل ۴ کاراکتر باشد")
    AUTH["password_hash"] = hash_password(new)
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        SESSIONS[token] = time.time() + SESSION_TTL
    await save_state()
    log_activity("auth", "رمز عبور پنل تغییر کرد", "ok")
    return {"ok": True}

# ── Stats ─────────────────────────────────────────────────────────────────────
@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    async with LINKS_LOCK:
        snap = dict(LINKS)
    async with USERS_LOCK:
        snap_users = dict(USERS)
    async with SUBS_LOCK:
        snap_subs = dict(SUBS)

    # Auto-check user expiry
    for user in snap_users.values():
        auto_check_user_expiry(user)

    # Count active users
    active_users = sum(1 for u in snap_users.values() if u.get("status") == "active")
    total_users = len(snap_users)

    # Traffic across all links
    total_bytes = stats["total_bytes"]
    traffic_usage_gb = round(total_bytes / (1024 ** 3), 3)

    # Connection-based health simulation
    conn_count = len(connections)
    if conn_count > 400:
        server_status = "down"
    elif conn_count > 200:
        server_status = "degraded"
    else:
        server_status = "healthy"

    # Simulated system metrics
    cpu_percent = round(min(conn_count * 0.3 + 5, 95), 1)
    ram_percent = round(min(45 + (total_users * 0.5) + (conn_count * 0.1), 95), 1)
    disk_percent = round(min(25 + (len(snap) * 0.02) + (total_users * 0.1), 90), 1)
    uptime_secs = max(time.time() - stats["start_time"], 1)
    network_mbps = round(total_bytes / uptime_secs * 8 / 1000000, 2)

    return {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 ** 2), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "hourly": dict(hourly_traffic),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(snap),
        "active_links": sum(1 for l in snap.values() if is_link_allowed(l)),
        "expired_links": sum(1 for l in snap.values() if is_link_expired(l)),
        "subs_count": len(SUBS),
        # Enhanced stats
        "active_users": active_users,
        "total_configs": len(snap),
        "total_users": total_users,
        "traffic_usage_gb": traffic_usage_gb,
        "server_status": server_status,
        "cpu_percent": cpu_percent,
        "ram_percent": ram_percent,
        "disk_percent": disk_percent,
        "network_mbps": network_mbps,
        "recent_activity": list(activity_logs)[-10:],
    }

# ── Activity Logs ─────────────────────────────────────────────────────────────
@app.get("/api/activity")
async def get_activity(_=Depends(require_auth)):
    return {"logs": list(activity_logs)[-150:]}

# ── Live connections (with IP) ────────────────────────────────────────────────
@app.get("/api/connections")
async def get_connections(_=Depends(require_auth)):
    """
    خروجی این endpoint حالا بر اساس IP گروه‌بندی شده:
    هر آی‌پی فقط یک آیتم نمایش داده می‌شود، با جمع بایت‌های تمام سشن‌های
    باز روی همان آی‌پی و تعداد سشن‌های فعال آن آی‌پی.
    raw_count همچنان تعداد واقعی اتصالات باز (سشن‌های خام، مثلاً ۴۰ تا
    اتصال هم‌زمان یک موبایل) را برمی‌گرداند.
    """
    async with LINKS_LOCK:
        snap = dict(LINKS)

    grouped: dict[str, dict] = {}
    for conn_id, c in connections.items():
        ip = c.get("ip", "نامشخص")
        link = snap.get(c.get("uuid"))
        label = link.get("label") if link else "نامشخص"
        g = grouped.get(ip)
        if g is None:
            g = {
                "ip": ip,
                "sessions": 0,
                "bytes": 0,
                "labels": set(),
                "transports": set(),
                "first_connected_at": c.get("connected_at"),
                "last_connected_at": c.get("connected_at"),
            }
            grouped[ip] = g
        g["sessions"] += 1
        g["bytes"] += c.get("bytes", 0)
        g["labels"].add(label)
        g["transports"].add(c.get("transport", "vless-ws"))
        ca = c.get("connected_at")
        if ca:
            if not g["first_connected_at"] or ca < g["first_connected_at"]:
                g["first_connected_at"] = ca
            if not g["last_connected_at"] or ca > g["last_connected_at"]:
                g["last_connected_at"] = ca

    result = []
    for ip, g in grouped.items():
        result.append({
            "ip": ip,
            "sessions": g["sessions"],
            "labels": sorted(g["labels"]),
            "label": " · ".join(sorted(g["labels"])) if g["labels"] else "نامشخص",
            "transports": sorted(g["transports"]),
            "bytes": g["bytes"],
            "bytes_fmt": fmt_bytes(g["bytes"]),
            "connected_at": g["first_connected_at"],
            "last_connected_at": g["last_connected_at"],
        })
    result.sort(key=lambda x: x.get("last_connected_at") or "", reverse=True)

    return {
        "connections": result,
        "count": len(result),          # تعداد آی‌پی‌های یکتا
        "raw_count": len(connections), # تعداد کل اتصالات باز (بدون گروه‌بندی)
    }

# ── Link Management ───────────────────────────────────────────────────────────
@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "لینک جدید").strip()[:60]
    lv = float(body.get("limit_value") or 0)
    lu = body.get("limit_unit") or "GB"
    limit_bytes = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
    exp_days = int(body.get("expires_days") or 0)
    expires_at = (datetime.now() + timedelta(days=exp_days)).isoformat() if exp_days > 0 else None
    note = (body.get("note") or "").strip()[:200]
    sub_id = body.get("sub_id") or None
    protocol = body.get("protocol") or DEFAULT_PROTOCOL
    if protocol not in PROTOCOLS:
        protocol = DEFAULT_PROTOCOL

    uid = generate_uuid()
    async with LINKS_LOCK:
        LINKS[uid] = {
            "label": label,
            "limit_bytes": limit_bytes,
            "used_bytes": 0,
            "created_at": datetime.now().isoformat(),
            "active": True,
            "expires_at": expires_at,
            "note": note,
            "is_default": False,
            "sub_id": sub_id,
            "protocol": protocol,
        }

    if sub_id:
        async with SUBS_LOCK:
            if sub_id in SUBS:
                ids = SUBS[sub_id].setdefault("link_ids", [])
                if uid not in ids:
                    ids.append(uid)

    asyncio.create_task(save_state())
    log_activity("link", f"کانفیگ «{label}» ساخته شد", "ok")
    host = SETTINGS.get("domain") or get_host()
    return {
        "uuid": uid,
        **LINKS[uid],
        "expired": False,
        "vless_link": generate_vless_link(uid, host, remark=f"Spider-{label}", protocol=protocol),
        "sub_url": f"https://{host}/sub/{uid}",
    }

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    host = SETTINGS.get("domain") or get_host()
    async with LINKS_LOCK:
        snap = dict(LINKS)
    result = []
    for uid, d in snap.items():
        proto = d.get("protocol", DEFAULT_PROTOCOL)
        result.append({
            "uuid": uid,
            **d,
            "protocol": proto,
            "expired": is_link_expired(d),
            "vless_link": generate_vless_link(uid, host, remark=f"Spider-{d['label']}", protocol=proto),
            "sub_url": f"https://{host}/sub/{uid}",
        })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.patch("/api/links/{uid}")
async def update_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        link = LINKS[uid]
        old_sub = link.get("sub_id")
        label = link.get("label")
        if "active" in body:
            link["active"] = bool(body["active"])
            log_activity("link", f"کانفیگ «{label}» {'فعال' if link['active'] else 'غیرفعال'} شد", "ok" if link["active"] else "warn")
        if "label" in body:
            link["label"] = str(body["label"])[:60]
        if "note" in body:
            link["note"] = str(body["note"])[:200]
        if "reset_usage" in body and body["reset_usage"]:
            link["used_bytes"] = 0
            log_activity("link", f"مصرف کانفیگ «{label}» ریست شد", "info")
        if "limit_value" in body:
            lv = float(body.get("limit_value") or 0)
            lu = body.get("limit_unit") or "GB"
            link["limit_bytes"] = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
        if "expires_days" in body:
            ed = int(body["expires_days"] or 0)
            link["expires_at"] = (datetime.now() + timedelta(days=ed)).isoformat() if ed > 0 else None
        if any(k in body for k in ("label", "note", "limit_value", "expires_days")):
            log_activity("link", f"کانفیگ «{link['label']}» ویرایش شد", "info")
        new_sub = body.get("sub_id", "UNCHANGED")
        if new_sub != "UNCHANGED":
            link["sub_id"] = new_sub or None

    if new_sub != "UNCHANGED":
        async with SUBS_LOCK:
            if old_sub and old_sub in SUBS:
                ids = SUBS[old_sub].get("link_ids", [])
                if uid in ids:
                    ids.remove(uid)
            if new_sub and new_sub in SUBS:
                ids = SUBS[new_sub].setdefault("link_ids", [])
                if uid not in ids:
                    ids.append(uid)

    asyncio.create_task(save_state())
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        label = LINKS[uid].get("label", uid)
        sub_id = LINKS[uid].get("sub_id")
        del LINKS[uid]
    if sub_id:
        async with SUBS_LOCK:
            if sub_id in SUBS:
                ids = SUBS[sub_id].get("link_ids", [])
                if uid in ids:
                    ids.remove(uid)
    asyncio.create_task(save_state())
    log_activity("link", f"کانفیگ «{label}» حذف شد", "err")
    return {"ok": True, "deleted": uid}

# ══════════════════════════════════════════════════════════════════════════════
# VLESS Relay — optional module
# ══════════════════════════════════════════════════════════════════════════════

try:
    from relay_vless import (
        RELAY_BUF,
        parse_vless_header,
        check_and_use,
        relay_ws_to_tcp,
        relay_tcp_to_ws,
        websocket_tunnel,
    )
    # WebSocket route: /ws/{uuid} — config_uuid IS the path
    # Uses the same approach as reference RVG-main project
    @app.websocket("/ws/{uuid}")
    async def ws_uuid_handler(ws: WebSocket, uuid: str):
        # /ws/live is registered later — handle it here since param route matches first
        if uuid == "live":
            await websocket_live_stats(ws)
            return
        await websocket_tunnel(ws, uuid)

    logger.info("VLESS Relay module loaded (WS: /ws/{uuid})")
except Exception as e:
    logger.warning(f"VLESS Relay module not available: {e}")

# XHTTP — optional transport module
# ══════════════════════════════════════════════════════════════════════════════
try:
    from xhttp_siz10 import router as xhttp_router
    app.include_router(xhttp_router)
    logger.info("XHTTP module loaded")
except (ImportError, ModuleNotFoundError) as e:
    logger.warning(f"XHTTP module not available: {e}")

# ══════════════════════════════════════════════════════════════════════════════
# ── HTTP Proxy ────────────────────────────────────────────────────────────────
_HOP = {"connection","keep-alive","proxy-authenticate","proxy-authorization",
        "te","trailers","transfer-encoding","upgrade","content-encoding","content-length"}

@app.api_route("/proxy/{target_url:path}", methods=["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"])
async def http_proxy(target_url: str, request: Request):
    if not target_url.startswith("http"):
        target_url = "https://" + target_url
    try:
        body = await request.body()
        headers = {k: v for k, v in request.headers.items() if k.lower() not in _HOP and k.lower() != "host"}
        resp = await http_client.request(method=request.method, url=target_url, headers=headers, content=body)
        stats["total_bytes"] += len(resp.content)
        stats["total_requests"] += 1
        hourly_traffic[now_ir().strftime("%H:00")] += len(resp.content)
        return Response(content=resp.content, status_code=resp.status_code,
                        headers={k: v for k, v in resp.headers.items() if k.lower() not in _HOP})
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "url": target_url, "time": datetime.now().isoformat()})
        raise HTTPException(status_code=502, detail=f"Proxy error: {exc}")


# ══════════════════════════════════════════════════════════════════════════════
# INBOUNDS MANAGEMENT endpoints
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/inbounds")
async def list_inbounds(_=Depends(require_auth)):
    """List all inbounds."""
    async with INBOUNDS_LOCK:
        snap = dict(INBOUNDS)
    result = []
    for iid, ib in snap.items():
        result.append({
            "inbound_id": iid,
            **ib,
            "users_count": sum(1 for u in USERS.values() if u.get("inbound_id") == iid),
        })
    result.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return {"inbounds": result}


@app.post("/api/inbounds")
async def create_inbound(request: Request, _=Depends(require_auth)):
    """Create a new inbound."""
    body = await request.json()
    name = (body.get("name") or "اینباند جدید").strip()[:60]
    protocol = str(body.get("protocol") or "vless").lower()
    if protocol not in ("vless", "vmess", "trojan", "reality"):
        raise HTTPException(status_code=400, detail="Invalid protocol")
    network = str(body.get("network") or "ws").lower()
    security = str(body.get("security") or "tls").lower()
    domain = str(body.get("domain") or "").strip()
    external_domain = str(body.get("external_domain") or "").strip()
    sni = str(body.get("sni") or "").strip()
    port = int(body.get("port") or 443)
    external_port = int(body.get("external_port") or 443)
    fingerprint = str(body.get("fingerprint") or "chrome").strip()
    reality_settings = body.get("reality_settings", {}) if isinstance(body.get("reality_settings"), dict) else {}
    xhttp_settings = body.get("xhttp_settings", {}) if isinstance(body.get("xhttp_settings"), dict) else {}
    ws_settings = body.get("ws_settings", {}) if isinstance(body.get("ws_settings"), dict) else {}
    grpc_settings = body.get("grpc_settings", {}) if isinstance(body.get("grpc_settings"), dict) else {}

    # Auto-generate Reality key pair + short_id if protocol is reality
    if protocol == "reality":
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        if not reality_settings.get("private_key") or not reality_settings.get("public_key"):
            priv = X25519PrivateKey.generate()
            priv_bytes = priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            pub_bytes = priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            reality_settings["private_key"] = base64.b64encode(priv_bytes).decode()
            reality_settings["public_key"] = base64.b64encode(pub_bytes).decode()
            logger.info("Auto-generated Reality x25519 key pair for inbound")
        if not reality_settings.get("short_id"):
            reality_settings["short_id"] = secrets.token_hex(5)[:10]  # 10-char hex like 3x-ui
        reality_settings.setdefault("dest", "is1-ssl.mzstatic.com:443")
        reality_settings.setdefault("spiderx", "/")
        # Set security to "reality" for Reality protocol
        security = "reality"
        # If no external_domain provided, use domain or host
        if not external_domain:
            external_domain = domain or CONFIG.get("host", "")
        # Network defaults to tcp for Reality (can also be xhttp)
        if network not in ("tcp", "xhttp", "grpc"):
            network = "tcp"

    inbound_id = generate_short_id()
    async with INBOUNDS_LOCK:
        if any(ib.get("name") == name for ib in INBOUNDS.values()):
            raise HTTPException(status_code=409, detail="Inbound name already exists")
        INBOUNDS[inbound_id] = {
            "name": name,
            "protocol": protocol,
            "port": port,
            "network": network,
            "security": security,
            "domain": domain,
            "external_domain": external_domain,
            "sni": sni,
            "external_port": external_port,
            "fingerprint": fingerprint,
            "reality_settings": reality_settings,
            "xhttp_settings": xhttp_settings,
            "ws_settings": ws_settings,
            "grpc_settings": grpc_settings,
            "created_at": datetime.now().isoformat(),
        }
    await save_state()
    log_activity("inbound", f"اینباند «{name}» با پروتکل {protocol.upper()} ساخته شد", "ok")
    return {"ok": True, "inbound_id": inbound_id, **INBOUNDS[inbound_id]}


@app.patch("/api/inbounds/{inbound_id}")
async def update_inbound(inbound_id: str, request: Request, _=Depends(require_auth)):
    """Update an existing inbound."""
    body = await request.json()
    async with INBOUNDS_LOCK:
        ib = INBOUNDS.get(inbound_id)
        if not ib:
            raise HTTPException(status_code=404, detail="inbound not found")
        if "name" in body:
            ib["name"] = str(body["name"]).strip()[:60]
        if "protocol" in body:
            p = str(body["protocol"]).lower()
            if p in ("vless", "vmess", "trojan", "reality"):
                ib["protocol"] = p
        if "port" in body:
            ib["port"] = int(body["port"])
        if "network" in body:
            ib["network"] = str(body["network"]).lower()
        if "security" in body:
            ib["security"] = str(body["security"]).lower()
        # Reality protocol must always use security="reality"
        if ib.get("protocol") == "reality":
            ib["security"] = "reality"
            # Auto-update reality_settings with short_id/spiderx if not present
            rs = ib.setdefault("reality_settings", {})
            if not rs.get("short_id"):
                rs["short_id"] = secrets.token_hex(5)[:10]
            rs.setdefault("spiderx", "/")
            rs.setdefault("dest", "is1-ssl.mzstatic.com:443")
            if ib.get("network") not in ("tcp", "xhttp", "grpc"):
                ib["network"] = "tcp"
        if "domain" in body:
            ib["domain"] = str(body["domain"]).strip()
        if "external_domain" in body:
            ib["external_domain"] = str(body["external_domain"]).strip()
        if "sni" in body:
            ib["sni"] = str(body["sni"]).strip()
        if "external_port" in body:
            ib["external_port"] = int(body["external_port"])
        if "fingerprint" in body:
            ib["fingerprint"] = str(body["fingerprint"]).strip()
        if "reality_settings" in body and isinstance(body["reality_settings"], dict):
            ib["reality_settings"] = body["reality_settings"]
        if "xhttp_settings" in body and isinstance(body["xhttp_settings"], dict):
            ib["xhttp_settings"] = body["xhttp_settings"]
        if "ws_settings" in body and isinstance(body["ws_settings"], dict):
            ib["ws_settings"] = body["ws_settings"]
        if "grpc_settings" in body and isinstance(body["grpc_settings"], dict):
            ib["grpc_settings"] = body["grpc_settings"]
    await save_state()
    log_activity("inbound", f"اینباند «{ib.get('name', inbound_id)}» ویرایش شد", "info")
    return {"ok": True}


@app.post("/api/inbounds/{inbound_id}/generate-reality-keys")
async def generate_inbound_reality_keys(inbound_id: str, _=Depends(require_auth)):
    """Generate Reality x25519 key pair + short_id + spiderx for an inbound."""
    async with INBOUNDS_LOCK:
        ib = INBOUNDS.get(inbound_id)
        if not ib:
            raise HTTPException(status_code=404, detail="inbound not found")
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            from cryptography.hazmat.primitives import serialization
            priv = X25519PrivateKey.generate()
            priv_bytes = priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            pub_bytes = priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            import base64 as b64
            rs = ib.setdefault("reality_settings", {})
            rs["private_key"] = b64.b64encode(priv_bytes).decode()
            rs["public_key"] = b64.b64encode(pub_bytes).decode()
            rs["short_id"] = secrets.token_hex(5)[:10]
            rs.setdefault("spiderx", "/")
            rs.setdefault("dest", "is1-ssl.mzstatic.com:443")
            ib["security"] = "reality"
            ib["protocol"] = "reality"
            if ib.get("network") not in ("tcp", "xhttp", "grpc"):
                ib["network"] = "tcp"
        except ImportError:
            return {"error": True, "note": "cryptography not installed: pip install cryptography"}
    await save_state()
    return {
        "ok": True,
        "public_key": rs["public_key"],
        "private_key": rs["private_key"],
        "short_id": rs["short_id"],
        "spiderx": rs.get("spiderx", "/"),
    }


@app.post("/api/inbounds/{inbound_id}/generate-short-id")
async def generate_inbound_short_id(inbound_id: str, _=Depends(require_auth)):
    """Generate only a new short_id for a Reality inbound (no key regeneration)."""
    async with INBOUNDS_LOCK:
        ib = INBOUNDS.get(inbound_id)
        if not ib:
            raise HTTPException(status_code=404, detail="inbound not found")
        if ib.get("protocol") != "reality":
            raise HTTPException(status_code=400, detail="inbound is not Reality protocol")
        rs = ib.setdefault("reality_settings", {})
        rs["short_id"] = secrets.token_hex(5)[:10]
    await save_state()
    return {"ok": True, "short_id": rs["short_id"]}


@app.delete("/api/inbounds/{inbound_id}")
async def delete_inbound(inbound_id: str, _=Depends(require_auth)):
    """Delete an inbound."""
    async with INBOUNDS_LOCK:
        ib = INBOUNDS.pop(inbound_id, None)
        if not ib:
            raise HTTPException(status_code=404, detail="inbound not found")
        name = ib.get("name", inbound_id)
    asyncio.create_task(save_state())
    log_activity("inbound", f"اینباند «{name}» حذف شد", "err")
    return {"ok": True, "deleted": inbound_id}


# ══════════════════════════════════════════════════════════════════════════════
# USER MANAGEMENT endpoints
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/users")
async def list_users(_=Depends(require_auth)):
    """List all users with traffic stats and status."""
    host = SETTINGS.get("domain") or get_host()
    async with USERS_LOCK:
        snap = dict(USERS)

    result = []
    for uid, u in snap.items():
        auto_check_user_expiry(u)
        protocol = u.get("protocol", "vless")
        result.append({
            "user_id": uid,
            "username": u.get("username"),
            "protocol": protocol,
            "transport_type": u.get("transport_type", "ws"),
            "path": u.get("path", ""),
            "traffic_limit_bytes": u.get("traffic_limit_bytes", 0),
            "traffic_limit_fmt": "∞" if u.get("traffic_limit_bytes", 0) == 0 else fmt_bytes(u["traffic_limit_bytes"]),
            "traffic_used_bytes": u.get("traffic_used_bytes", 0),
            "traffic_used_fmt": fmt_bytes(u.get("traffic_used_bytes", 0)),
            "traffic_percent": round(u.get("traffic_used_bytes", 0) / max(u.get("traffic_limit_bytes", 1), 1) * 100, 1) if u.get("traffic_limit_bytes", 0) > 0 else 0,
            "expire_at": u.get("expire_at"),
            "concurrent_connections": u.get("concurrent_connections", 3),
            "created_at": u.get("created_at"),
            "status": u.get("status", "active"),
            "server": u.get("server", ""),
            "config_uuid": u.get("config_uuid"),
            "subscription_uuid": u.get("subscription_uuid"),
            "inbound_id": u.get("inbound_id"),
            "inbound_name": INBOUNDS.get(u.get("inbound_id", ""), {}).get("name", "") if u.get("inbound_id") else "",
            "config_url": f"https://{host}/api/users/{uid}/config",
            "qr_url": f"https://{host}/api/users/{uid}/qr",
            "subscription_url": f"https://{host}/api/users/{uid}/subscription",
            "connections": sum(1 for c in connections.values() if c.get("uuid") == u.get("config_uuid")),
        })
    result.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return {"users": result}

@app.post("/api/users")
async def create_user(request: Request, _=Depends(require_auth)):
    """Create a new user with protocol config, traffic limit, and expiry."""
    body = await request.json()
    username = (body.get("username") or "user").strip()[:40]
    password = str(body.get("password") or secrets.token_urlsafe(12))
    traffic_limit_gb = float(body.get("traffic_limit_gb") or 0)
    expire_days = int(body.get("expire_days") or 0)
    protocol = str(body.get("protocol") or "vless").lower()
    concurrent_connections = int(body.get("concurrent_connections") or 3)
    server = (body.get("server") or "IR-Tehran-01").strip()[:40]
    sni = str(body.get("sni") or "").strip()
    path_custom = str(body.get("path") or "").strip()
    transport_type = str(body.get("transport_type") or "ws").strip().lower()
    inbound_id = str(body.get("inbound_id") or "").strip() or None

    if transport_type not in ("ws", "grpc", "tcp", "xhttp", "reality"):
        transport_type = "ws"

    if protocol not in USER_PROTOCOLS:
        raise HTTPException(status_code=400, detail=f"Invalid protocol. Must be one of: {', '.join(USER_PROTOCOLS)}")
    if len(username) < 1:
        raise HTTPException(status_code=400, detail="Username is required")
    if len(password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    if concurrent_connections < 1:
        concurrent_connections = 1

    user_id = generate_short_id()
    config_uuid = generate_uuid()
    subscription_uuid = secrets.token_urlsafe(16)
    traffic_limit_bytes = int(traffic_limit_gb * 1024 ** 3) if traffic_limit_gb > 0 else 0
    expire_at = (datetime.now() + timedelta(days=expire_days)).isoformat() if expire_days > 0 else None

    # Auto-generate Reality key pair if protocol is reality and no key exists
    if protocol == "reality":
        async with SETTINGS_LOCK:
            reality = SETTINGS.get("reality", {})
            if not reality.get("public_key"):
                try:
                    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
                    priv = X25519PrivateKey.generate()
                    priv_bytes = priv.private_bytes_raw()
                    pub_bytes = priv.public_key().public_bytes_raw()
                    import base64 as b64
                    reality["private_key"] = b64.b64encode(priv_bytes).decode()
                    reality["public_key"] = b64.b64encode(pub_bytes).decode()
                    reality.setdefault("short_id", secrets.token_hex(4)[:10])
                    reality.setdefault("dest", "is1-ssl.mzstatic.com:443")
                    reality.setdefault("sni", "is1-ssl.mzstatic.com")
                    reality.setdefault("spiderx", "/")
                    reality.setdefault("fingerprint", "chrome")
                    reality.setdefault("external_port", 443)
                    SETTINGS["reality"] = reality
                    asyncio.create_task(save_state())
                    log_activity("settings", "کلیدهای Reality خودکار ساخته شد", "ok")
                except ImportError:
                    pass

    async with USERS_LOCK:
        # Check for duplicate username
        for existing in USERS.values():
            if existing.get("username") == username:
                raise HTTPException(status_code=409, detail="Username already exists")

        USERS[user_id] = {
            "username": username,
            "password_hash": hash_password(password),
            "protocol": protocol,
            "traffic_limit_bytes": traffic_limit_bytes,
            "traffic_used_bytes": 0,
            "expire_at": expire_at,
            "concurrent_connections": concurrent_connections,
            "created_at": datetime.now().isoformat(),
            "status": "active",
            "server": server,
            "config_uuid": config_uuid,
            "subscription_uuid": subscription_uuid,
            "sni": sni,
            "path": path_custom if path_custom else (
                f"/xhttp-siz10/stream-up/{config_uuid}" if transport_type == "xhttp" else
                f"/ws/{config_uuid}"
            ),
            "transport_type": transport_type,
            "inbound_id": inbound_id,
        }
        _path = USERS[user_id].get("path", "").strip().lstrip("/")

    # Auto-create matching link so relay can find it
    async with LINKS_LOCK:
        link_xhttp = {}
        if transport_type == "xhttp":
            link_xhttp = {
                "xPaddingBytes": "100-1000",
                "mode": "auto",
                "scMaxEachPostBytes": "1000000",
            }
        LINKS[config_uuid] = {
            "label": username,
            "limit_bytes": traffic_limit_bytes,
            "used_bytes": 0,
            "created_at": datetime.now().isoformat(),
            "active": True,
            "expires_at": expire_at,
            "note": f"لینک کاربر {username}",
            "is_default": False,
            "sub_id": None,
            "protocol": protocol,
            "transport_type": transport_type,
            "xhttp_settings": link_xhttp,
            "path": _path,
            "user_id": user_id,
        }
        # Register uuid in PATH_INDEX for backward compat (old random-path clients)
        # config_uuid IS the path under /ws/{config_uuid}
        PATH_INDEX[config_uuid] = config_uuid
        if _path:
            PATH_INDEX[_path.lstrip("/")] = config_uuid

    asyncio.create_task(save_state())
    log_activity("user", f"کاربر «{username}» با پروتکل {protocol} ساخته شد", "ok")
    host = SETTINGS.get("domain") or get_host()
    return {
        "user_id": user_id,
        **USERS[user_id],
        "password_hash": None,
        "config_url": f"https://{host}/api/users/{user_id}/config",
        "qr_url": f"https://{host}/api/users/{user_id}/qr",
        "subscription_url": f"https://{host}/api/users/{user_id}/subscription",
        "config": generate_user_config(user_id, USERS[user_id], inbound_id),
    }

@app.patch("/api/users/{user_id}/toggle")
async def toggle_user(user_id: str, _=Depends(require_auth)):
    """Enable or disable a user."""
    async with USERS_LOCK:
        u = USERS.get(user_id)
        if not u:
            raise HTTPException(status_code=404, detail="user not found")
        old = u.get("status", "active")
        if old == "disabled":
            u["status"] = "active"
        else:
            u["status"] = "disabled"
        new_status = u["status"]

    # Sync link active state
    config_uuid = u.get("config_uuid")
    if config_uuid:
        async with LINKS_LOCK:
            if config_uuid in LINKS:
                LINKS[config_uuid]["active"] = (new_status == "active")

    asyncio.create_task(save_state())
    log_activity("user", f"کاربر «{u['username']}» {'غیرفعال' if new_status == 'disabled' else 'فعال'} شد", "ok" if new_status == "active" else "warn")
    return {"ok": True, "user_id": user_id, "status": new_status}

@app.patch("/api/users/{user_id}/reset")
async def reset_user_traffic(user_id: str, _=Depends(require_auth)):
    """Reset a user's traffic usage to zero."""
    async with USERS_LOCK:
        u = USERS.get(user_id)
        if not u:
            raise HTTPException(status_code=404, detail="user not found")
        u["traffic_used_bytes"] = 0
        username = u.get("username", user_id)
    asyncio.create_task(save_state())
    log_activity("user", f"مصرف کاربر «{username}» ریست شد", "info")
    return {"ok": True, "user_id": user_id, "traffic_used_bytes": 0}

@app.delete("/api/users/{user_id}")
@app.patch("/api/users/{user_id}")
async def edit_user(user_id: str, request: Request, _=Depends(require_auth)):
    """Edit an existing user."""
    body = await request.json()
    async with USERS_LOCK:
        if user_id not in USERS:
            raise HTTPException(status_code=404, detail="user not found")
        u = USERS[user_id]
        if "username" in body:
            u["username"] = str(body["username"]).strip()[:40]
        if "traffic_limit_gb" in body:
            gb = float(body["traffic_limit_gb"])
            u["traffic_limit_bytes"] = int(gb * 1024**3) if gb > 0 else 0
        if "expire_days" in body:
            days = int(body["expire_days"])
            u["expire_at"] = (datetime.now() + timedelta(days=days)).isoformat() if days > 0 else None
        if "protocol" in body:
            p = str(body["protocol"]).lower()
            if p in USER_PROTOCOLS:
                u["protocol"] = p
        if "status" in body:
            u["status"] = str(body["status"])
        if "sni" in body:
            u["sni"] = str(body["sni"]).strip()
        if "path" in body:
            # Update PATH_INDEX when path changes
            old_path = (u.get("path") or "").strip().lstrip("/")
            new_path = str(body["path"]).strip().lstrip("/")
            u["path"] = new_path
            if old_path:
                PATH_INDEX.pop(old_path, None)
            if new_path:
                PATH_INDEX[new_path] = u.get("config_uuid", user_id)
        if "transport_type" in body:
            u["transport_type"] = str(body["transport_type"]).strip().lower()
        if "concurrent_connections" in body:
            u["concurrent_connections"] = max(1, int(body["concurrent_connections"]))
        if "reset_traffic" in body and body["reset_traffic"]:
            u["traffic_used_bytes"] = 0
    asyncio.create_task(save_state())
    return {"ok": True, "user_id": user_id}

@app.get("/api/users/{user_id}")
async def get_user(user_id: str, _=Depends(require_auth)):
    """Get single user details."""
    async with USERS_LOCK:
        if user_id not in USERS:
            raise HTTPException(status_code=404, detail="user not found")
        u = dict(USERS[user_id])
        u["user_id"] = user_id
        u["password_hash"] = None
        return u


async def delete_user(user_id: str, _=Depends(require_auth)):
    """Delete a user permanently."""
    async with USERS_LOCK:
        u = USERS.get(user_id)
        if not u:
            raise HTTPException(status_code=404, detail="user not found")
        username = u.get("username", user_id)
        # Clean up PATH_INDEX and synced link
        old_path = (u.get("path") or "").strip().lstrip("/")
        if old_path:
            PATH_INDEX.pop(old_path, None)
        config_uuid = u.get("config_uuid")
        if config_uuid:
            PATH_INDEX.pop(config_uuid, None)
        USERS.pop(user_id, None)
    # Delete matching link
    if config_uuid:
        async with LINKS_LOCK:
            LINKS.pop(config_uuid, None)
    asyncio.create_task(save_state())
    log_activity("user", f"کاربر «{username}» حذف شد", "err")
    return {"ok": True, "deleted": user_id}

@app.get("/api/users/{user_id}")
async def get_single_user(user_id: str, _=Depends(require_auth)):
    """Get full details for a single user."""
    async with USERS_LOCK:
        u = USERS.get(user_id)
        if not u:
            raise HTTPException(status_code=404, detail="user not found")
        user = dict(u)
        user["user_id"] = user_id
        user["password_hash"] = None  # Never expose hash
    auto_check_user_expiry(user)
    host = SETTINGS.get("domain") or get_host()
    return {
        **user,
        "config": generate_user_config(user_id, user, user.get("inbound_id")),
        "config_url": f"https://{host}/api/users/{user_id}/config",
        "qr_url": f"https://{host}/api/users/{user_id}/qr",
        "subscription_url": f"https://{host}/api/users/{user_id}/subscription",
        "traffic_used_fmt": fmt_bytes(user.get("traffic_used_bytes", 0)),
        "traffic_limit_fmt": "∞" if user.get("traffic_limit_bytes", 0) == 0 else fmt_bytes(user.get("traffic_limit_bytes", 0)),
    }

@app.patch("/api/users/{user_id}")
async def edit_user(user_id: str, request: Request, _=Depends(require_auth)):
    """Edit an existing user's fields."""
    body = await request.json()
    async with USERS_LOCK:
        u = USERS.get(user_id)
        if not u:
            raise HTTPException(status_code=404, detail="user not found")
        old_username = u.get("username")

        if "username" in body:
            new_name = str(body["username"]).strip()[:40]
            # Check duplicate
            for oid, ou in USERS.items():
                if oid != user_id and ou.get("username") == new_name:
                    raise HTTPException(status_code=409, detail="Username already exists")
            if new_name:
                u["username"] = new_name

        if "traffic_limit_gb" in body:
            gb = float(body["traffic_limit_gb"] or 0)
            u["traffic_limit_bytes"] = int(gb * 1024 ** 3) if gb > 0 else 0

        if "expire_days" in body:
            days = int(body["expire_days"] or 0)
            u["expire_at"] = (datetime.now() + timedelta(days=days)).isoformat() if days > 0 else None

        if "protocol" in body:
            proto = str(body["protocol"]).lower()
            if proto in USER_PROTOCOLS:
                u["protocol"] = proto

        if "sni" in body:
            u["sni"] = str(body["sni"]).strip()

        if "path" in body:
            u["path"] = str(body["path"]).strip()

        if "transport_type" in body:
            tt = str(body["transport_type"]).strip().lower()
            if tt in ("ws", "grpc", "tcp", "xhttp", "reality"):
                u["transport_type"] = tt

        if "status" in body:
            st = str(body["status"]).lower()
            if st in ("active", "disabled", "expired"):
                u["status"] = st

        if "concurrent_connections" in body:
            cc = int(body["concurrent_connections"] or 3)
            u["concurrent_connections"] = max(1, cc)

    asyncio.create_task(save_state())
    log_activity("user", f"کاربر «{old_username}» ویرایش شد", "info")
    return {"ok": True, "user_id": user_id, "username": u.get("username")}

@app.get("/api/users/{user_id}/config")
async def get_user_config(user_id: str, _=Depends(require_auth)):
    """Return the protocol config string for a user."""
    async with USERS_LOCK:
        u = USERS.get(user_id)
        if not u:
            raise HTTPException(status_code=404, detail="user not found")
        config = generate_user_config(user_id, u, u.get("inbound_id"))
        username = u.get("username")
        protocol = u.get("protocol")
    host = SETTINGS.get("domain") or get_host()
    return {
        "user_id": user_id,
        "username": username,
        "protocol": protocol,
        "config": config,
        "config_url": f"https://{host}/api/users/{user_id}/config",
        "qr_url": f"https://{host}/api/users/{user_id}/qr",
        "subscription_url": f"https://{host}/api/users/{user_id}/subscription",
    }

@app.get("/api/users/{user_id}/qr")
async def get_user_qr(user_id: str, _=Depends(require_auth)):
    """Return a QR code PNG image for the user's config."""
    if not QR_AVAILABLE:
        raise HTTPException(status_code=501, detail="QR code generation not available (install qrcode and Pillow)")

    async with USERS_LOCK:
        u = USERS.get(user_id)
        if not u:
            raise HTTPException(status_code=404, detail="user not found")
        config = generate_user_config(user_id, u, u.get("inbound_id"))

    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=4, error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(config)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return Response(content=buf.getvalue(), media_type="image/png",
                    headers={"Content-Disposition": f"inline; filename={user_id}.png"})

@app.get("/api/users/{user_id}/subscription")
async def get_user_subscription(user_id: str, _=Depends(require_auth)):
    """Return the subscription URL for a user."""
    host = SETTINGS.get("domain") or get_host()
    async with USERS_LOCK:
        u = USERS.get(user_id)
        if not u:
            raise HTTPException(status_code=404, detail="user not found")
        sub_uuid = u.get("subscription_uuid")
        username = u.get("username")

    if not sub_uuid:
        raise HTTPException(status_code=404, detail="no subscription configured")

    config = generate_user_config(user_id, u, u.get("inbound_id"))
    content = base64.b64encode(config.encode()).decode()

    return {
        "user_id": user_id,
        "username": username,
        "subscription_uuid": sub_uuid,
        "subscription_url": f"https://{host}/sub/{sub_uuid}",
        "encoded_config": content,
    }


# ── Public sub page ───────────────────────────────────────────────────────────
@app.get("/p/{uuid_key}", response_class=HTMLResponse)
async def public_sub_page(uuid_key: str, request: Request):
    from pages import get_public_page_html
    async with SUBS_LOCK:
        sub = next(({"sub_id": sid, **s} for sid, s in SUBS.items() if s.get("uuid_key") == uuid_key), None)
    if not sub:
        return HTMLResponse("<h2 style='font-family:sans-serif;padding:40px'>گروه پیدا نشد</h2>", status_code=404)
    return HTMLResponse(content=get_public_page_html(uuid_key))

@app.get("/api/public/sub/{uuid_key}")
async def public_sub_data(uuid_key: str, request: Request):
    async with SUBS_LOCK:
        sub_entry = next(((sid, s) for sid, s in SUBS.items() if s.get("uuid_key") == uuid_key), None)
    if not sub_entry:
        raise HTTPException(status_code=404, detail="not found")
    sub_id, sub = sub_entry

    has_pw = sub.get("password_hash") is not None
    if has_pw:
        pw = request.query_params.get("pw", "")
        if hash_password(pw) != sub["password_hash"]:
            return JSONResponse({"locked": True, "name": sub["name"]})

    host = SETTINGS.get("domain") or get_host()
    link_ids = sub.get("link_ids", [])
    async with LINKS_LOCK:
        snap = dict(LINKS)

    links_out = []
    active_conns = 0
    for lid in link_ids:
        link = snap.get(lid)
        if not link:
            continue
        allowed = is_link_allowed(link)
        conn_count = sum(1 for c in connections.values() if c.get("uuid") == lid)
        active_conns += conn_count
        proto = link.get("protocol", DEFAULT_PROTOCOL)
        links_out.append({
            "uuid": lid,
            "label": link["label"],
            "active": allowed,
            "protocol": proto,
            "used_bytes": link.get("used_bytes", 0),
            "used_fmt": fmt_bytes(link.get("used_bytes", 0)),
            "limit_bytes": link.get("limit_bytes", 0),
            "limit_fmt": "∞" if link.get("limit_bytes", 0) == 0 else fmt_bytes(link["limit_bytes"]),
            "expires_at": link.get("expires_at"),
            "vless_link": generate_vless_link(lid, host, remark=f"Spider-{link['label']}", protocol=proto),
            "sub_url": f"https://{host}/sub/{lid}",
            "connections": conn_count,
        })

    total_used = sum(l["used_bytes"] for l in links_out)
    return {
        "locked": False,
        "name": sub["name"],
        "desc": sub.get("desc", ""),
        "sub_url": f"https://{host}/sub-group/{uuid_key}",
        "active_connections": active_conns,
        "total_used_fmt": fmt_bytes(total_used),
        "links": links_out,
    }

# ── HTML Pages (SPA) ───────────────────────────────────────────────────────
import os as _os
_STATIC_DIR = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "static")
_os.makedirs(_STATIC_DIR, exist_ok=True)

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/spider")
    return FileResponse(_os.path.join(_STATIC_DIR, "index.html"))

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_redirect(request: Request):
    return RedirectResponse(url="/spider")

@app.get("/spider", response_class=HTMLResponse)
async def spider_panel(request: Request):
    if not await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/login")
    await ensure_default_link()
    return FileResponse(_os.path.join(_STATIC_DIR, "index.html"))

@app.get("/test-ws", response_class=HTMLResponse)
async def test_ws_redirect():
    return HTMLResponse(content="<script>location.href='/spider'</script>")


# ══════════════════════════════════════════════════════════════════════════════
# USER SUBSCRIPTION DATA API (Public)
# Note: /sub/{identifier} above now handles both user HTML pages and link configs.
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/sub/{username}")
async def api_user_sub(username: str):
    """Return subscription data for a user (works for both active and inactive users)."""
    async with USERS_LOCK:
        user = None
        for uid, u in USERS.items():
            if u.get("username") == username:
                user = dict(u)
                user["user_id"] = uid
                break
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Even inactive users get their sub page (just show status)
    status = user.get("status", "active")

    auto_check_user_expiry(user)

    # Calculate expiry info
    expire_days = None
    expire_at_ts = None
    if user.get("expire_at"):
        try:
            exp = datetime.fromisoformat(user["expire_at"])
            expire_at_ts = int(exp.timestamp())
            expire_days = max(0, (exp - datetime.now()).days)
        except Exception:
            pass

    # Calculate created_at timestamp
    created_at_ts = None
    if user.get("created_at"):
        try:
            created_at_ts = int(datetime.fromisoformat(user["created_at"]).timestamp())
        except Exception:
            pass

    status = user.get("status", "active")
    is_active = is_user_allowed(user)
    if not is_active and status == "active":
        status = "expired" if user.get("status") != "disabled" else "disabled"

    # Calculate traffic percent
    used = user.get("traffic_used_bytes", 0)
    limit = user.get("traffic_limit_bytes", 0)
    traffic_pct = round(used / max(limit, 1) * 100, 1) if limit > 0 else 0

    config = generate_user_config(user.get("user_id"), user, user.get("inbound_id"))

    return {
        "username": user.get("username"),
        "protocol": user.get("protocol", "vless"),
        "traffic_used_bytes": used,
        "traffic_used_fmt": fmt_bytes(used),
        "traffic_limit_bytes": limit,
        "traffic_limit_fmt": "∞" if limit == 0 else fmt_bytes(limit),
        "traffic_percent": traffic_pct,
        "expire_days": expire_days,
        "expire_at": user.get("expire_at"),
        "expire_at_ts": expire_at_ts,
        "created_at": user.get("created_at"),
        "created_at_ts": created_at_ts,
        "status": status,
        "is_active": is_active,
        "vless_link": config,
        "config": config,
        "sni": user.get("sni", ""),
        "path": user.get("path", ""),
        "transport_type": user.get("transport_type", "ws"),
        "concurrent_connections": user.get("concurrent_connections", 3),
        "server": user.get("server", ""),
    }


# ══════════════════════════════════════════════════════════════════════════════
# TOOLS - Reality Settings
# ══════════════════════════════════════════════════════════════════════════════


@app.post("/api/tools/generate-reality-keys")
async def generate_reality_keys(_=Depends(require_auth)):
    """Generate a Reality key pair (x25519)."""
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        priv = X25519PrivateKey.generate()
        priv_bytes = priv.private_bytes_raw()
        pub_bytes = priv.public_key().public_bytes_raw()
        import base64 as b64
        return {"private_key": b64.b64encode(priv_bytes).decode(), "public_key": b64.b64encode(pub_bytes).decode()}
    except ImportError:
        # cryptography not installed - return error
        return {"error": True, "private_key": "", "public_key": "", "note": "cryptography not installed: pip install cryptography"}

@app.get("/api/tools/reality-settings")
async def get_reality_settings(_=Depends(require_auth)):
    """Get Reality settings from global SETTINGS."""
    async with SETTINGS_LOCK:
        reality = SETTINGS.get("reality", {})
    host = get_host()
    return {
        "port": reality.get("port", 1234),
        "dest": reality.get("dest", "google.com:443"),
        "sni": reality.get("sni", host),
        "public_key": reality.get("public_key", ""),
        "short_id": reality.get("short_id", "6ba85179e30d4fc2"),
        "spiderx": reality.get("spiderx", "/"),
        "fingerprint": reality.get("fingerprint", "chrome"),
        "dest": reality.get("dest", "is1-ssl.mzstatic.com:443"),
        "external_domain": reality.get("external_domain", host),
        "external_port": reality.get("external_port", 443),
        "domain": reality.get("domain", host),
        "domain_history": reality.get("domain_history", []),
    }

@app.post("/api/tools/reality-settings")
async def set_reality_settings(request: Request, _=Depends(require_auth)):
    """Save Reality settings globally."""
    body = await request.json()
    async with SETTINGS_LOCK:
        reality = SETTINGS.get("reality", {})
        if "port" in body:
            reality["port"] = int(body.get("port", 1234))
        if "dest" in body:
            reality["dest"] = str(body.get("dest", "google.com:443"))
        if "sni" in body:
            reality["sni"] = str(body.get("sni", get_host()))
        if "public_key" in body:
            reality["public_key"] = str(body.get("public_key", ""))
        if "short_id" in body:
            reality["short_id"] = str(body.get("short_id", "6ba85179e30d4fc2"))
        if "spiderx" in body:
            reality["spiderx"] = str(body.get("spiderx", "/"))
        if "external_domain" in body:
            reality["external_domain"] = str(body.get("external_domain", get_host()))
        if "external_port" in body:
            reality["external_port"] = int(body.get("external_port", 443))
        if "domain" in body:
            domain_val = str(body.get("domain", "")).strip()
            if domain_val:
                reality["domain"] = domain_val
                # manage domain history (keep last 20, unique)
                history = reality.get("domain_history", [])
                if domain_val in history:
                    history.remove(domain_val)
                history.insert(0, domain_val)
                reality["domain_history"] = history[:20]
        SETTINGS["reality"] = reality
    asyncio.create_task(save_state())
    log_activity("settings", "تنظیمات Reality ذخیره شد", "ok")
    return {"ok": True, "reality": reality}

@app.get("/api/tools/settings")
async def get_global_settings(_=Depends(require_auth)):
    """Get global panel settings."""
    host = get_host()
    async with SETTINGS_LOCK:
        reality = SETTINGS.get("reality", {})
    return {
        "domain": SETTINGS.get("domain", host),
        "default_path": SETTINGS.get("default_path", "/"),
        "default_transport": SETTINGS.get("default_transport", "ws"),
        "enabled_protocols": SETTINGS.get("enabled_protocols", ["vless", "vmess", "trojan", "reality"]),
        "reality": reality,
        "domain_history": reality.get("domain_history", []),
        "xhttp_mode": SETTINGS.get("xhttp_mode", True),
        "websocket_mode": SETTINGS.get("websocket_mode", True),
        "default_connection_mode": SETTINGS.get("default_connection_mode", "ws"),
        "bg_login": SETTINGS.get("bg_login", ""),
        "bg_dashboard": SETTINGS.get("bg_dashboard", ""),
        "bg_sub": SETTINGS.get("bg_sub", ""),
        "panel_audio": SETTINGS.get("panel_audio", ""),
        "panel_audio_enabled": SETTINGS.get("panel_audio_enabled", False),
    }

@app.post("/api/tools/settings")
async def set_global_settings(request: Request, _=Depends(require_auth)):
    """Save global panel settings."""
    body = await request.json()
    async with SETTINGS_LOCK:
        if "domain" in body:
            domain_val = str(body["domain"]).strip()
            if domain_val:
                SETTINGS["domain"] = domain_val
                # update domain history in reality too
                reality = SETTINGS.get("reality", {})
                history = reality.get("domain_history", [])
                if domain_val in history:
                    history.remove(domain_val)
                history.insert(0, domain_val)
                reality["domain_history"] = history[:20]
                SETTINGS["reality"] = reality
        if "default_path" in body:
            SETTINGS["default_path"] = str(body["default_path"]).strip()
        if "default_transport" in body:
            val = str(body["default_transport"]).strip()
            if val in ("ws", "xhttp", "tcp"):
                SETTINGS["default_transport"] = val
        if "enabled_protocols" in body:
            SETTINGS["enabled_protocols"] = body["enabled_protocols"]
        if "xhttp_mode" in body:
            SETTINGS["xhttp_mode"] = bool(body["xhttp_mode"])
        if "websocket_mode" in body:
            SETTINGS["websocket_mode"] = bool(body["websocket_mode"])
        if "default_connection_mode" in body:
            val = str(body["default_connection_mode"]).strip()
            if val in ("ws", "xhttp", "tcp"):
                SETTINGS["default_connection_mode"] = val
    asyncio.create_task(save_state())
    log_activity("settings", "تنظیمات کلی ذخیره شد", "ok")
    return {"ok": True}


# ══════════════════════════════════════════════════════════════════════════════
# SUB-SYNC endpoints (Flask-style sub config serving)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/sub-sync/data")
async def subsync_get_data():
    """Return all sub data as JSON."""
    async with SUBS_LOCK:
        snap = dict(SUBS)
    async with LINKS_LOCK:
        snap_links = dict(LINKS)
    host = SETTINGS.get("domain") or get_host()
    result = []
    for sid, s in snap.items():
        link_ids = s.get("link_ids", [])
        configs = []
        for lid in link_ids:
            link = snap_links.get(lid)
            if link and is_link_allowed(link):
                proto = link.get("protocol", DEFAULT_PROTOCOL)
                configs.append(generate_vless_link(lid, host, remark=f"Spider-{link['label']}", protocol=proto))
        result.append({"name": s["name"], "desc": s.get("desc", ""), "configs": configs, "uuid_key": s.get("uuid_key", ""), "sub_id": sid})
    return {"subs": result}

@app.post("/sub-sync/sync")
async def subsync_sync_data(request: Request):
    """Sync sub data (for external tools)."""
    body = await request.json()
    if not body or "subs" not in body:
        raise HTTPException(status_code=400, detail="Invalid data")
    # This is a read-only mirror — we just echo back
    return {"ok": True, "message": "Data received", "count": len(body["subs"])}

@app.get("/sub-sync/sub/{name}")
async def subsync_get_sub(name: str):
    """Get configs for a specific sub by name or username."""
    configs = []
    host = SETTINGS.get("domain") or get_host()
    
    # First check SUBS (subscription groups)
    async with SUBS_LOCK:
        sub = next((s for s in SUBS.values() if s.get("name") == name), None)
    if sub:
        link_ids = sub.get("link_ids", [])
        async with LINKS_LOCK:
            snap = dict(LINKS)
        for lid in link_ids:
            link = snap.get(lid)
            if link and is_link_allowed(link):
                proto = link.get("protocol", DEFAULT_PROTOCOL)
                configs.append(generate_vless_link(lid, host, remark=f"Spider-{link['label']}", protocol=proto))
    
    # Also check USERS — serve user config directly
    if not configs:
        async with USERS_LOCK:
            user = next(((uid, u) for uid, u in USERS.items() if u.get("username") == name), None)
        if user:
            uid, u = user
            cfg = generate_user_config(uid, u, u.get("inbound_id"))
            if cfg:
                configs.append(cfg)
    
    if not configs:
        raise HTTPException(status_code=404, detail=f"No configs found for '{name}'")
    return Response(content="\n".join(configs), media_type="text/plain; charset=utf-8")


# ══════════════════════════════════════════════════════════════════════════════
# ADVANCED SETTINGS SYSTEM
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/settings")
async def get_settings(_=Depends(require_auth)):
    """Return all settings, masking the security token."""
    async with SETTINGS_LOCK:
        s = dict(SETTINGS)
        s["security_token"] = s["security_token"][:8] + "********" if s.get("security_token") else ""
    return s


@app.post("/api/settings")
async def update_settings(request: Request, _=Depends(require_auth)):
    """Update settings from any subset of fields."""
    body = await request.json()
    allowed_keys = {
        "websocket_mode", "xhttp_mode", "default_connection_mode",
        "max_ip_per_user", "bandwidth_limit_mbps", "live_monitoring",
        "auto_ip_rotation",
    }
    async with SETTINGS_LOCK:
        for k, v in body.items():
            if k in allowed_keys:
                if k == "max_ip_per_user" and isinstance(v, (int, float)):
                    SETTINGS[k] = int(v)
                elif k == "bandwidth_limit_mbps" and isinstance(v, (int, float)):
                    SETTINGS[k] = int(v)
                elif k == "default_connection_mode" and isinstance(v, str):
                    if v in ("ws", "xhttp", "tcp"):
                        SETTINGS[k] = v
                elif isinstance(v, bool):
                    SETTINGS[k] = v
    asyncio.create_task(save_state())
    log_activity("settings", "تنظیمات پیشرفته به‌روزرسانی شد", "info")
    async with SETTINGS_LOCK:
        s = dict(SETTINGS)
        s["security_token"] = s["security_token"][:8] + "********" if s.get("security_token") else ""
    return {"ok": True, "settings": s}


@app.post("/api/settings/security-token/rotate")
async def rotate_security_token(_=Depends(require_auth)):
    """Generate a new security token."""
    async with SETTINGS_LOCK:
        SETTINGS["security_token"] = secrets.token_urlsafe(16)
    asyncio.create_task(save_state())
    log_activity("settings", "توکن امنیتی جدید تولید شد", "ok")
    return {"ok": True, "security_token": SETTINGS["security_token"]}





# ══════════════════════════════════════════════════════════════════════════════
# GROUP MANAGEMENT SYSTEM
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/groups")
async def list_groups(_=Depends(require_auth)):
    """List all groups with user count."""
    async with GROUPS_LOCK:
        snap = dict(GROUPS)
    result = []
    for gid, g in snap.items():
        user_ids = g.get("user_ids", [])
        result.append({
            "group_id": gid,
            "name": g.get("name"),
            "description": g.get("description", ""),
            "user_count": len(user_ids),
            "user_ids": user_ids,
            "speed_limit": g.get("speed_limit", 0),
            "traffic_limit": g.get("traffic_limit", 0),
            "expire_days": g.get("expire_days", 0),
            "ip_pool": g.get("ip_pool", []),
            "rules": g.get("rules", {}),
            "created_at": g.get("created_at"),
        })
    result.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return {"groups": result}


@app.post("/api/groups")
async def create_group(request: Request, _=Depends(require_auth)):
    """Create a new group."""
    body = await request.json()
    name = (body.get("name") or "گروه جدید").strip()[:60]
    description = (body.get("description") or "").strip()[:200]
    speed_limit = int(body.get("speed_limit") or 0)
    traffic_limit = int(body.get("traffic_limit") or 0)
    expire_days = int(body.get("expire_days") or 0)

    group_id = generate_short_id()
    async with GROUPS_LOCK:
        GROUPS[group_id] = {
            "name": name,
            "description": description,
            "user_ids": [],
            "ip_pool": body.get("ip_pool", []),
            "rules": body.get("rules", {}),
            "speed_limit": speed_limit,
            "traffic_limit": traffic_limit,
            "expire_days": expire_days,
            "created_at": datetime.now().isoformat(),
        }
    asyncio.create_task(save_state())
    log_activity("group", f"گروه «{name}» ساخته شد", "ok")
    return {"ok": True, "group_id": group_id, **GROUPS[group_id]}


@app.patch("/api/groups/{group_id}")
async def update_group(group_id: str, request: Request, _=Depends(require_auth)):
    """Update an existing group."""
    body = await request.json()
    async with GROUPS_LOCK:
        g = GROUPS.get(group_id)
        if not g:
            raise HTTPException(status_code=404, detail="group not found")
        if "name" in body:
            g["name"] = str(body["name"])[:60]
        if "description" in body:
            g["description"] = str(body["description"])[:200]
        if "speed_limit" in body:
            g["speed_limit"] = int(body["speed_limit"])
        if "traffic_limit" in body:
            g["traffic_limit"] = int(body["traffic_limit"])
        if "expire_days" in body:
            g["expire_days"] = int(body["expire_days"])
        if "ip_pool" in body:
            g["ip_pool"] = list(body["ip_pool"])
        if "rules" in body:
            g["rules"] = dict(body["rules"])
    asyncio.create_task(save_state())
    log_activity("group", f"گروه «{g.get('name', group_id)}» ویرایش شد", "info")
    return {"ok": True}


@app.delete("/api/groups/{group_id}")
async def delete_group(group_id: str, _=Depends(require_auth)):
    """Delete a group and unlink all users from it."""
    async with GROUPS_LOCK:
        g = GROUPS.pop(group_id, None)
        if not g:
            raise HTTPException(status_code=404, detail="group not found")
        name = g.get("name", group_id)
        user_ids = g.get("user_ids", [])
    asyncio.create_task(save_state())
    log_activity("group", f"گروه «{name}» حذف شد", "warn")
    return {"ok": True, "deleted": group_id, "unlinked_users": len(user_ids)}


@app.post("/api/groups/{group_id}/users")
async def add_user_to_group(group_id: str, request: Request, _=Depends(require_auth)):
    """Add a user to a group."""
    body = await request.json()
    user_id = str(body.get("user_id", ""))
    if not user_id:
        raise HTTPException(status_code=400, detail="user_id is required")

    async with USERS_LOCK:
        if user_id not in USERS:
            raise HTTPException(status_code=404, detail="user not found")

    async with GROUPS_LOCK:
        g = GROUPS.get(group_id)
        if not g:
            raise HTTPException(status_code=404, detail="group not found")
        ids = g.setdefault("user_ids", [])
        if user_id not in ids:
            ids.append(user_id)
    asyncio.create_task(save_state())
    log_activity("group", f"کاربر «{user_id}» به گروه «{g.get('name', group_id)}» اضافه شد", "info")
    return {"ok": True}


@app.delete("/api/groups/{group_id}/users/{user_id}")
async def remove_user_from_group(group_id: str, user_id: str, _=Depends(require_auth)):
    """Remove a user from a group."""
    async with GROUPS_LOCK:
        g = GROUPS.get(group_id)
        if not g:
            raise HTTPException(status_code=404, detail="group not found")
        ids = g.get("user_ids", [])
        if user_id in ids:
            ids.remove(user_id)
        else:
            raise HTTPException(status_code=404, detail="user not in group")
    asyncio.create_task(save_state())
    log_activity("group", f"کاربر «{user_id}» از گروه «{g.get('name', group_id)}» حذف شد", "info")
    return {"ok": True}


@app.get("/api/groups/{group_id}/subscription")
async def group_subscription(group_id: str, _=Depends(require_auth)):
    """Generate subscription link for a group — base64-encoded configs of all active users."""
    async with GROUPS_LOCK:
        g = GROUPS.get(group_id)
        if not g:
            raise HTTPException(status_code=404, detail="group not found")
        user_ids = list(g.get("user_ids", []))

    async with USERS_LOCK:
        snap = dict(USERS)

    configs = []
    for uid in user_ids:
        u = snap.get(uid)
        if u and is_user_allowed(u):
            cfg = generate_user_config(uid, u, u.get("inbound_id"))
            if cfg:
                configs.append(cfg)

    if not configs:
        raise HTTPException(status_code=404, detail="no active users in group")

    content = base64.b64encode("\n".join(configs).encode()).decode()
    host = SETTINGS.get("domain") or get_host()
    return {
        "group_id": group_id,
        "group_name": g.get("name"),
        "active_users": len(configs),
        "total_users": len(user_ids),
        "subscription_url": f"https://{host}/api/groups/{group_id}/subscription",
        "encoded_config": content,
    }


# ══════════════════════════════════════════════════════════════════════════════
# IP POOL MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/ips")
async def list_ips(_=Depends(require_auth)):
    """List all IPs in the pool with status."""
    async with IP_POOL_LOCK:
        ips = list(IP_POOL)
    async with IP_BLACKLIST_LOCK:
        bl = set(IP_BLACKLIST)
    for entry in ips:
        entry["blacklisted"] = entry["ip"] in bl
    return {"ips": ips, "total": len(ips), "blacklisted_count": len(bl)}


@app.post("/api/ips")
async def add_ip(request: Request, _=Depends(require_auth)):
    """Add an IP to the pool."""
    body = await request.json()
    ip_addr = (body.get("ip") or "").strip()
    if not ip_addr:
        raise HTTPException(status_code=400, detail="ip is required")
    async with IP_POOL_LOCK:
        if any(e["ip"] == ip_addr for e in IP_POOL):
            raise HTTPException(status_code=409, detail="ip already in pool")
        entry = {
            "ip": ip_addr,
            "status": body.get("status", "active"),
            "latency_ms": body.get("latency_ms", 0),
            "location": body.get("location", "Unknown"),
            "assigned_user": body.get("assigned_user"),
            "last_check": datetime.now().isoformat(),
        }
        IP_POOL.append(entry)
    asyncio.create_task(save_state())
    log_activity("ip", f"IP «{ip_addr}» به مخزن اضافه شد", "info")
    return {"ok": True, "ip": entry}


@app.delete("/api/ips")
async def remove_ip(request: Request, _=Depends(require_auth)):
    """Remove an IP from the pool."""
    body = await request.json()
    ip_addr = (body.get("ip") or "").strip()
    if not ip_addr:
        raise HTTPException(status_code=400, detail="ip is required")
    async with IP_POOL_LOCK:
        before = len(IP_POOL)
        IP_POOL[:] = [e for e in IP_POOL if e["ip"] != ip_addr]
        if len(IP_POOL) == before:
            raise HTTPException(status_code=404, detail="ip not found in pool")
    asyncio.create_task(save_state())
    log_activity("ip", f"IP «{ip_addr}» از مخزن حذف شد", "warn")
    return {"ok": True, "deleted": ip_addr}


@app.post("/api/ips/blacklist")
async def blacklist_ip(request: Request, _=Depends(require_auth)):
    """Add an IP to the blacklist."""
    body = await request.json()
    ip_addr = (body.get("ip") or "").strip()
    if not ip_addr:
        raise HTTPException(status_code=400, detail="ip is required")
    async with IP_BLACKLIST_LOCK:
        IP_BLACKLIST.add(ip_addr)
    asyncio.create_task(save_state())
    log_activity("ip", f"IP «{ip_addr}» به لیست سیاه اضافه شد", "warn")
    return {"ok": True, "blacklisted": ip_addr}


@app.delete("/api/ips/blacklist")
async def unblacklist_ip(request: Request, _=Depends(require_auth)):
    """Remove an IP from the blacklist."""
    body = await request.json()
    ip_addr = (body.get("ip") or "").strip()
    if not ip_addr:
        raise HTTPException(status_code=400, detail="ip is required")
    async with IP_BLACKLIST_LOCK:
        if ip_addr not in IP_BLACKLIST:
            raise HTTPException(status_code=404, detail="ip not in blacklist")
        IP_BLACKLIST.discard(ip_addr)
    asyncio.create_task(save_state())
    log_activity("ip", f"IP «{ip_addr}» از لیست سیاه خارج شد", "info")
    return {"ok": True, "removed": ip_addr}


@app.post("/api/ips/assign")
async def assign_ip_to_user(request: Request, _=Depends(require_auth)):
    """Assign an IP from the pool to a user."""
    body = await request.json()
    user_id = str(body.get("user_id", ""))
    ip_addr = str(body.get("ip", ""))
    if not user_id or not ip_addr:
        raise HTTPException(status_code=400, detail="user_id and ip are required")

    async with USERS_LOCK:
        if user_id not in USERS:
            raise HTTPException(status_code=404, detail="user not found")

    async with IP_POOL_LOCK:
        entry = next((e for e in IP_POOL if e["ip"] == ip_addr), None)
        if not entry:
            raise HTTPException(status_code=404, detail="ip not found in pool")
        entry["assigned_user"] = user_id
        entry["status"] = "assigned"

    async with USER_IP_MAP_LOCK:
        USER_IP_MAP[user_id].add(ip_addr)

    asyncio.create_task(save_state())
    log_activity("ip", f"IP «{ip_addr}» به کاربر «{user_id}» اختصاص یافت", "info")
    return {"ok": True, "user_id": user_id, "ip": ip_addr}


@app.get("/api/ips/test")
async def test_ips(_=Depends(require_auth)):
    """Return simulated ping results for pool IPs."""
    import random
    async with IP_POOL_LOCK:
        ips = list(IP_POOL)
    results = []
    for entry in ips:
        latency = random.randint(20, 350)
        status = "ok" if latency < 300 else "timeout"
        results.append({
            "ip": entry["ip"],
            "latency_ms": latency,
            "status": status,
            "location": entry.get("location", "Unknown"),
            "assigned_user": entry.get("assigned_user"),
            "tested_at": datetime.now().isoformat(),
        })
    results.sort(key=lambda x: x["latency_ms"])
    return {"results": results, "tested_at": datetime.now().isoformat()}


@app.get("/api/ips/check")
async def check_ip(request: Request, _=Depends(require_auth)):
    """Check if an IP is in the blacklist."""
    ip_addr = request.query_params.get("ip", "").strip()
    if not ip_addr:
        raise HTTPException(status_code=400, detail="ip query param is required")
    async with IP_BLACKLIST_LOCK:
        blacklisted = ip_addr in IP_BLACKLIST
    return {"ip": ip_addr, "blacklisted": blacklisted}


# ══════════════════════════════════════════════════════════════════════════════
# LIVE SERVER STATS — Helpers & WebSocket
# ══════════════════════════════════════════════════════════════════════════════

ws_client_count = 0
WS_LIVE_CLIENTS: set = set()

def get_live_stats() -> dict:
    """Get real server stats using psutil with fallback."""
    conn_count = len(connections)
    try:
        import psutil as _ps
        cpu_pct = round(_ps.cpu_percent(interval=0.3), 1)
        mem = _ps.virtual_memory()
        ram_pct = round(mem.percent, 1)
        ram_used_gb = round(mem.used / (1024**3), 2)
        ram_total_gb = round(mem.total / (1024**3), 2)
        disk = _ps.disk_usage('/')
        disk_pct = round(disk.percent, 1)
        disk_used_gb = round(disk.used / (1024**3), 2)
        disk_total_gb = round(disk.total / (1024**3), 2)
        net = _ps.net_io_counters()
        net_sent_mb = round(net.bytes_sent / (1024**2), 2)
        net_recv_mb = round(net.bytes_recv / (1024**2), 2)
        network_mbps = round(max((net.bytes_sent + net.bytes_recv) / (1024**2) / max(uptime_secs(), 1) * 8, 0.5), 2)
    except Exception:
        cpu_pct = round(min(conn_count * 0.3 + 5, 95), 1)
        ram_pct = round(min(45 + len(USERS) * 0.5 + conn_count * 0.1, 95), 1)
        ram_used_gb = round(ram_pct / 100 * 8, 2)
        ram_total_gb = 8
        disk_pct = round(min(25 + len(LINKS) * 0.02 + len(USERS) * 0.1, 90), 1)
        disk_used_gb = round(disk_pct / 100 * 50, 2)
        disk_total_gb = 50
        net_sent_mb = 0
        net_recv_mb = 0
        network_mbps = 2.5
    # Calculate total traffic from all users
    total_used = sum(u.get("traffic_used_bytes", 0) for u in USERS.values())
    total_limit = sum(u.get("traffic_limit_bytes", 0) for u in USERS.values())
    return {
        "cpu_percent": max(0, cpu_pct),
        "ram_percent": max(0, ram_pct),
        "ram_used_gb": ram_used_gb,
        "ram_total_gb": ram_total_gb,
        "disk_percent": max(0, disk_pct),
        "disk_used_gb": disk_used_gb,
        "disk_total_gb": disk_total_gb,
        "network_mbps": network_mbps,
        "net_sent_mb": net_sent_mb,
        "net_recv_mb": net_recv_mb,
        "active_connections": conn_count,
        "ws_connections": ws_client_count,
        "total_users": len(USERS),
        "total_traffic_used_tb": round(total_used / (1024**4), 3),
        "total_traffic_limit_tb": round(total_limit / (1024**4), 3) if total_limit > 0 else 0,
        "uptime": uptime(),
        "uptime_seconds": uptime_secs(),
        "timestamp": datetime.now().isoformat(),
    }


@app.websocket("/ws/live")
async def websocket_live_stats(websocket: WebSocket):
    global ws_client_count
    await websocket.accept()
    ws_client_count += 1
    WS_LIVE_CLIENTS.add(websocket)
    try:
        while True:
            try:
                stats_data = get_live_stats()
                await websocket.send_json(stats_data)
                await asyncio.sleep(2)
            except WebSocketDisconnect:
                break
            except Exception:
                break
    finally:
        ws_client_count = max(0, ws_client_count - 1)
        WS_LIVE_CLIENTS.discard(websocket)


# ══════════════════════════════════════════════════════════════════════════════
# IP LIMIT ENFORCEMENT
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/users/{user_id}/ip-check")
async def check_user_ip_limit(user_id: str, _=Depends(require_auth)):
    """Check if a user is within their IP limit."""
    async with USERS_LOCK:
        u = USERS.get(user_id)
        if not u:
            raise HTTPException(status_code=404, detail="user not found")
        username = u.get("username")

    async with USER_IP_MAP_LOCK:
        ip_count = len(USER_IP_MAP.get(user_id, set()))

    async with SETTINGS_LOCK:
        max_ip = SETTINGS.get("max_ip_per_user", 3)

    within_limit = ip_count < max_ip
    return {
        "user_id": user_id,
        "username": username,
        "current_ip_count": ip_count,
        "max_ip_per_user": max_ip,
        "within_limit": within_limit,
        "ips": list(USER_IP_MAP.get(user_id, set())),
    }


# ══════════════════════════════════════════════════════════════════════════════
# ADMIN TOOLS
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/tools/config-generator")
async def config_generator(request: Request, _=Depends(require_auth)):
    """Generate a connection config string for given parameters."""
    body = await request.json()
    protocol = str(body.get("protocol", "vless")).lower()
    host = str(body.get("host", get_host())).strip()
    config_uuid = str(body.get("uuid") or generate_uuid())
    remark = str(body.get("remark", "Generated"))

    if protocol not in USER_PROTOCOLS:
        raise HTTPException(status_code=400, detail=f"Invalid protocol. Must be one of: {', '.join(USER_PROTOCOLS)}")

    # Build a temporary user-like dict for generate_user_config
    temp_user = {
        "protocol": protocol,
        "config_uuid": config_uuid,
        "username": remark,
    }
    # Override host temporarily
    original_host = CONFIG.get("host")
    CONFIG["host"] = host
    config = generate_user_config("temp", temp_user)
    if original_host:
        CONFIG["host"] = original_host

    return {
        "protocol": protocol,
        "host": host,
        "uuid": config_uuid,
        "remark": remark,
        "config": config,
        "generated_at": datetime.now().isoformat(),
    }


@app.post("/api/tools/ip-test")
async def ip_test(request: Request, _=Depends(require_auth)):
    """Simulated ping test for a given IP."""
    import random
    body = await request.json()
    ip_addr = str(body.get("ip", "")).strip()
    if not ip_addr:
        raise HTTPException(status_code=400, detail="ip is required")

    # Simple IP format check
    parts = ip_addr.split(".")
    valid_format = len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    if not valid_format:
        raise HTTPException(status_code=400, detail="invalid ip format")

    latency = random.randint(10, 400)
    status = "reachable" if latency < 350 else "unreachable"

    # Check blacklist
    async with IP_BLACKLIST_LOCK:
        blacklisted = ip_addr in IP_BLACKLIST

    return {
        "ip": ip_addr,
        "latency_ms": latency,
        "status": status,
        "blacklisted": blacklisted,
        "tested_at": datetime.now().isoformat(),
    }


@app.get("/api/tools/stress-test")
async def stress_test(_=Depends(require_auth)):
    """Simulated server load stats."""
    import random
    conn_count = len(connections)
    load_factor = min(conn_count / 500, 1.0) * 100
    return {
        "timestamp": datetime.now().isoformat(),
        "load_percent": round(load_factor, 1),
        "active_connections": conn_count,
        "max_theoretical_connections": 500,
        "cpu_percent": round(min(conn_count * 0.35 + random.uniform(2, 8), 95), 1),
        "ram_percent": round(min(50 + conn_count * 0.08 + random.uniform(1, 5), 95), 1),
        "disk_iops": random.randint(100, 2000),
        "network_mbps": round(random.uniform(2, 80), 2),
        "requests_per_second": stats.get("total_requests", 0) / max(time.time() - stats["start_time"], 1),
        "status": "healthy" if load_factor < 70 else ("degraded" if load_factor < 90 else "critical"),
    }


@app.post("/api/tools/bulk-create")
async def bulk_create_users(request: Request, _=Depends(require_auth)):
    """Create multiple users at once based on a template."""
    body = await request.json()
    count = int(body.get("count", 1))
    if count < 1:
        raise HTTPException(status_code=400, detail="count must be at least 1")
    if count > 100:
        raise HTTPException(status_code=400, detail="count cannot exceed 100")

    template = body.get("template", {})
    base_username = str(template.get("username_prefix", "bulk")).strip()[:20]
    protocol = str(template.get("protocol", "vless")).lower()
    traffic_limit_gb = float(template.get("traffic_limit_gb") or 0)
    expire_days = int(template.get("expire_days") or 0)
    concurrent = int(template.get("concurrent_connections") or 3)
    server = str(template.get("server", "IR-Tehran-01")).strip()[:40]

    if protocol not in USER_PROTOCOLS:
        raise HTTPException(status_code=400, detail=f"Invalid protocol: {protocol}")

    created = []
    async with USERS_LOCK:
        for i in range(count):
            user_id = generate_short_id()
            username = f"{base_username}{i + 1}"
            # Avoid duplicates: append random suffix if needed
            if any(u.get("username") == username for u in USERS.values()):
                username = f"{base_username}{i + 1}_{secrets.token_hex(3)}"
            config_uuid = generate_uuid()
            traffic_limit_bytes = int(traffic_limit_gb * 1024 ** 3) if traffic_limit_gb > 0 else 0
            expire_at = (datetime.now() + timedelta(days=expire_days)).isoformat() if expire_days > 0 else None
            USERS[user_id] = {
                "username": username,
                "password_hash": hash_password(secrets.token_urlsafe(8)),
                "protocol": protocol,
                "traffic_limit_bytes": traffic_limit_bytes,
                "traffic_used_bytes": 0,
                "expire_at": expire_at,
                "concurrent_connections": concurrent,
                "created_at": datetime.now().isoformat(),
                "status": "active",
                "server": server,
                "config_uuid": config_uuid,
                "subscription_uuid": secrets.token_urlsafe(16),
            }
            created.append({"user_id": user_id, "username": username})

    asyncio.create_task(save_state())
    log_activity("user", f"{count} کاربر به‌صورت انبوه ساخته شد", "ok")
    return {"ok": True, "created_count": len(created), "users": created}


# ══════════════════════════════════════════════════════════════════════════════
# SERVER RESOURCES (neon bars)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/server/resources")
async def server_resources(_=Depends(require_auth)):
    """Return live CPU, RAM, Disk, uptime for neon status bars."""
    try:
        import psutil
        return {
            "cpu_percent": psutil.cpu_percent(interval=0.3),
            "cpu_count": psutil.cpu_count(),
            "ram_percent": psutil.virtual_memory().percent,
            "ram_total_gb": round(psutil.virtual_memory().total / 1024**3, 1),
            "ram_used_gb": round(psutil.virtual_memory().used / 1024**3, 1),
            "disk_percent": psutil.disk_usage("/").percent,
            "disk_total_gb": round(psutil.disk_usage("/").total / 1024**3, 1),
            "net_sent_mb": round(psutil.net_io_counters().bytes_sent / 1024**2, 1),
            "net_recv_mb": round(psutil.net_io_counters().bytes_recv / 1024**2, 1),
            "uptime_seconds": int(time.time() - stats.get("start_time", time.time())),
        }
    except ImportError:
        return {"error": "psutil not installed", "cpu_percent": 0, "ram_percent": 0, "disk_percent": 0}


# ══════════════════════════════════════════════════════════════════════════════
# XRAY CORE CONFIG GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

def generate_xray_server_config(inbound_id: str = None) -> dict:
    """
    Generate a complete Xray-core server config.json based on inbound settings.
    Returns a dict that can be saved as config.json for Xray core.
    """
    inbound = None
    if inbound_id:
        inbound = INBOUNDS.get(inbound_id)
    
    host = SETTINGS.get("domain") or get_host()
    xray_config = {
        "log": {"loglevel": "warning"},
        "inbounds": [],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": []
        }
    }
    
    if not inbound:
        # Generate for all inbounds
        for iid, ib in INBOUNDS.items():
            _add_inbound_to_xray(xray_config, ib, iid, host)
    else:
        _add_inbound_to_xray(xray_config, inbound, inbound_id, host)
    
    return xray_config


def _add_inbound_to_xray(cfg: dict, ib: dict, iid: str, host: str):
    """Add a single inbound to an Xray config dict."""
    protocol = ib.get("protocol", "vless")
    port = int(ib.get("port", 443))
    network = ib.get("network", "ws")
    security = ib.get("security", "tls")
    domain = ib.get("domain", host)
    sni_val = ib.get("sni", domain)
    fingerprint = ib.get("fingerprint", "chrome")
    rs = ib.get("reality_settings", {}) if protocol == "reality" else {}
    ws_settings = ib.get("ws_settings", {})
    xh_settings = ib.get("xhttp_settings", {})
    grpc_settings = ib.get("grpc_settings", {})
    
    inbound_obj = {
        "tag": f"inbound-{iid}",
        "port": port,
        "protocol": protocol,
        "settings": {"clients": [], "decryption": "none"},
        "streamSettings": {}
    }
    
    # Protocol-specific client settings
    if protocol in ("vless", "vmess", "trojan"):
        # Generate some default client entries
        client_count = 10
        clients = []
        for i in range(client_count):
            uid = generate_uuid()
            client = {"id": uid}
            if protocol == "vless":
                client["flow"] = ""
            elif protocol == "vmess":
                client["alterId"] = 0
            elif protocol == "trojan":
                client["password"] = secrets.token_urlsafe(16)
            clients.append(client)
        inbound_obj["settings"]["clients"] = clients
    
    # Transport / Stream settings
    if protocol == "reality":
        inbound_obj["streamSettings"] = {
            "network": network if network in ("tcp", "xhttp", "grpc") else "tcp",
            "security": "reality",
            "realitySettings": {
                "show": False,
                "dest": rs.get("dest", "is1-ssl.mzstatic.com:443"),
                "xver": 0,
                "serverNames": [rs.get("sni", "is1-ssl.mzstatic.com")],
                "privateKey": rs.get("private_key", ""),
                "shortIds": [rs.get("short_id", "5a3ff5a13d")],
                "spiderX": rs.get("spiderx", "/"),
            }
        }
        if network == "xhttp":
            inbound_obj["streamSettings"]["xhttpSettings"] = {
                "path": xh_settings.get("path", "/"),
                "host": xh_settings.get("host", domain),
                "mode": xh_settings.get("mode", "auto"),
                "xPaddingBytes": xh_settings.get("xPaddingBytes", "100-1000"),
                "scMaxEachPostBytes": xh_settings.get("scMaxEachPostBytes", "1000000"),
                "scMaxBufferedPosts": xh_settings.get("scMaxBufferedPosts", 30),
                "scStreamUpServerSecs": xh_settings.get("scStreamUpServerSecs", "20-80"),
            }
    elif security == "tls":
        inbound_obj["streamSettings"] = {
            "network": network,
            "security": "tls",
            "tlsSettings": {
                "certificates": [{
                    "certificateFile": "/etc/xray/cert.pem",
                    "keyFile": "/etc/xray/key.pem"
                }]
            }
        }
        if network == "ws":
            inbound_obj["streamSettings"]["wsSettings"] = {
                "path": ws_settings.get("path", "/"),
                "headers": {"Host": ws_settings.get("host", domain)}
            }
        elif network == "grpc":
            inbound_obj["streamSettings"]["grpcSettings"] = {
                "serviceName": grpc_settings.get("serviceName", "")
            }
        elif network == "xhttp":
            inbound_obj["streamSettings"]["xhttpSettings"] = {
                "path": xh_settings.get("path", "/"),
                "host": xh_settings.get("host", domain),
                "mode": xh_settings.get("mode", "auto"),
                "xPaddingBytes": xh_settings.get("xPaddingBytes", "100-1000"),
                "scMaxEachPostBytes": xh_settings.get("scMaxEachPostBytes", "1000000"),
            }
    else:
        # No TLS (raw)
        inbound_obj["streamSettings"] = {"network": network}
        if network == "ws":
            inbound_obj["streamSettings"]["wsSettings"] = {"path": ws_settings.get("path", "/")}
    
    # Add sniffing
    inbound_obj["sniffing"] = {
        "enabled": True,
        "destOverride": ["http", "tls", "quic"]
    }
    
    cfg["inbounds"].append(inbound_obj)


@app.post("/api/tools/generate-xray-config")
async def gen_xray_server_config(request: Request, _=Depends(require_auth)):
    """Generate a complete Xray-core server config.json for all or specific inbounds."""
    body = await request.json()
    inbound_id = body.get("inbound_id") or None
    
    try:
        config = generate_xray_server_config(inbound_id)
        return {
            "ok": True,
            "config": config,
            "config_json": json.dumps(config, indent=2, ensure_ascii=False),
            "inbounds_count": len(config["inbounds"]),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/tools/generate-xray-keys")
async def gen_xray_keys(_=Depends(require_auth)):
    """Generate all Xray-related keys: Reality x25519 keypair, UUID, shortId."""
    result = {
        "uuid": generate_uuid(),
        "short_id": secrets.token_hex(5)[:10],
    }
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        priv = X25519PrivateKey.generate()
        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        import base64 as b64
        result["private_key"] = b64.b64encode(priv_bytes).decode()
        result["public_key"] = b64.b64encode(pub_bytes).decode()
    except ImportError:
        result["private_key"] = ""
        result["public_key"] = ""
        result["note"] = "cryptography not installed"
    return result


# ══════════════════════════════════════════════════════════════════════════════
# SERVER STATS (HTTP polling)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/server/stats")
async def server_stats_http(_=Depends(require_auth)):
    """One-shot HTTP response with live server stats (for polling clients)."""
    return get_live_stats()


# ── Static files mount (MUST be after all routes) ──
# ── Static files mount (MUST be after all routes) ──


# ══════════════════════════════════════════════════════════════════════════════
# FILE UPLOADS - Backgrounds, Audio, Custom Assets
# ══════════════════════════════════════════════════════════════════════════════

UPLOAD_DIR = _os.path.join(_STATIC_DIR, "uploads")
_os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/jpg", "image/webp", "image/gif"}
ALLOWED_AUDIO_TYPES = {"audio/mpeg", "audio/mp3", "audio/wav", "audio/ogg", "audio/webm"}


@app.post("/api/upload/background")
async def upload_background(request: Request, _=Depends(require_auth)):
    """Upload a custom background image for login, dashboard, or sub page."""
    form = await request.form()
    file = form.get("file")
    bg_type = str(form.get("type") or "login").lower()  # login, dashboard, sub
    
    if not file:
        raise HTTPException(status_code=400, detail="No file uploaded")
    
    content_type = file.content_type or ""
    if content_type not in ALLOWED_IMAGE_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid file type: {content_type}. Allowed: jpg, png, webp, gif")
    
    # Save file
    ext = file.filename.split(".")[-1] if "." in (file.filename or "") else "jpg"
    safe_name = f"bg_{bg_type}.{ext}"
    file_path = _os.path.join(UPLOAD_DIR, safe_name)
    
    content = await file.read()
    if len(content) > 10 * 1024 * 1024:  # 10MB max
        raise HTTPException(status_code=400, detail="File too large (max 10MB)")
    
    _os.makedirs(_os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "wb") as f:
        f.write(content)
    
    # Update settings
    bg_key = f"bg_{bg_type}"
    async with SETTINGS_LOCK:
        SETTINGS[bg_key] = f"/static/uploads/{safe_name}?t={int(time.time())}"
    
    await save_state()
    log_activity("settings", f"Background {bg_type} uploaded", "ok")
    return {"ok": True, "url": SETTINGS[bg_key], "type": bg_type}


@app.post("/api/upload/audio")
async def upload_audio(request: Request, _=Depends(require_auth)):
    """Upload a custom audio/music file for the panel."""
    form = await request.form()
    file = form.get("file")
    
    if not file:
        raise HTTPException(status_code=400, detail="No file uploaded")
    
    content_type = file.content_type or ""
    if content_type not in ALLOWED_AUDIO_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid file type: {content_type}. Allowed: mp3, wav, ogg")
    
    ext = file.filename.split(".")[-1] if "." in (file.filename or "") else "mp3"
    safe_name = f"panel_audio.{ext}"
    file_path = _os.path.join(UPLOAD_DIR, safe_name)
    
    content = await file.read()
    if len(content) > 50 * 1024 * 1024:  # 50MB max
        raise HTTPException(status_code=400, detail="File too large (max 50MB)")
    
    _os.makedirs(_os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "wb") as f:
        f.write(content)
    
    # Update settings
    async with SETTINGS_LOCK:
        SETTINGS["panel_audio"] = f"/static/uploads/{safe_name}?t={int(time.time())}"
        SETTINGS["panel_audio_enabled"] = True
    
    await save_state()
    log_activity("settings", "Panel audio uploaded", "ok")
    return {"ok": True, "url": SETTINGS["panel_audio"]}


@app.post("/api/settings/background/remove")
async def remove_background(request: Request, _=Depends(require_auth)):
    """Remove a custom background."""
    body = await request.json()
    bg_type = str(body.get("type") or "login").lower()
    bg_key = f"bg_{bg_type}"
    async with SETTINGS_LOCK:
        SETTINGS.pop(bg_key, None)
    await save_state()
    return {"ok": True, "removed": bg_type}


@app.post("/api/settings/audio/remove")
async def remove_audio(_=Depends(require_auth)):
    """Remove panel audio."""
    async with SETTINGS_LOCK:
        SETTINGS["panel_audio"] = ""
        SETTINGS["panel_audio_enabled"] = False
    await save_state()
    return {"ok": True}


# ══════════════════════════════════════════════════════════════════════════════
# IP SCANNER - Railway IPs, Ping Tests, Current IP
# ══════════════════════════════════════════════════════════════════════════════

RAILWAY_REGIONS = [
    {"name": "us-west1 (Oregon)", "host": "us-west1.railway.app"},
    {"name": "us-east4 (Virginia)", "host": "us-east4.railway.app"},
    {"name": "us-central1 (Iowa)", "host": "us-central1.railway.app"},
    {"name": "europe-west4 (Netherlands)", "host": "europe-west4.railway.app"},
    {"name": "europe-west1 (Belgium)", "host": "europe-west1.railway.app"},
    {"name": "asia-southeast1 (Singapore)", "host": "asia-southeast1.railway.app"},
    {"name": "asia-east1 (Taiwan)", "host": "asia-east1.railway.app"},
    {"name": "asia-northeast1 (Tokyo)", "host": "asia-northeast1.railway.app"},
    {"name": "australia-southeast1 (Sydney)", "host": "australia-southeast1.railway.app"},
    {"name": "southamerica-east1 (Sao Paulo)", "host": "southamerica-east1.railway.app"},
]

FAMOUS_SITES = [
    {"name": "Google", "host": "google.com"},
    {"name": "Cloudflare", "host": "cloudflare.com"},
    {"name": "GitHub", "host": "github.com"},
    {"name": "YouTube", "host": "youtube.com"},
    {"name": "Amazon", "host": "amazon.com"},
    {"name": "Wikipedia", "host": "wikipedia.org"},
    {"name": "Microsoft", "host": "microsoft.com"},
    {"name": "Twitter/X", "host": "twitter.com"},
    {"name": "Instagram", "host": "instagram.com"},
    {"name": "Telegram", "host": "telegram.org"},
]


import subprocess
import platform


@app.get("/api/tools/my-ip")
async def get_my_ip(_=Depends(require_auth)):
    """Get the server's current public IP."""
    ips = {}
    # Try multiple services
    for service, url in [
        ("ipify", "https://api.ipify.org?format=json"),
        ("icanhazip", "https://icanhazip.com"),
        ("ipinfo", "https://ipinfo.io/json"),
    ]:
        try:
            async with http_client as client:
                resp = await client.get(url, timeout=5)
                if resp.status_code == 200:
                    body = resp.text.strip()
                    ips[service] = body
        except Exception:
            ips[service] = None
    
    # Try Railway metadata
    railway_ip = None
    try:
        if os.environ.get("RAILWAY_STATIC_URL"):
            railway_ip = os.environ.get("RAILWAY_STATIC_URL")
    except Exception:
        pass
    
    return {
        "ips": ips,
        "railway_url": railway_ip,
        "local_hostname": platform.node(),
    }


@app.get("/api/tools/ping-sites")
async def ping_famous_sites(_=Depends(require_auth)):
    """Ping famous websites and return latency results."""
    results = []
    for site in FAMOUS_SITES:
        latency = None
        status = "error"
        try:
            system = platform.system().lower()
            if system == "windows":
                cmd = ["ping", "-n", "1", "-w", "3000", site["host"]]
            else:
                cmd = ["ping", "-c", "1", "-W", "3", site["host"]]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
            
            if proc.returncode == 0:
                output = stdout.decode(errors="ignore")
                # Extract time from ping output
                import re as _re
                if system == "windows":
                    match = _re.search(r"time[=<](\d+)ms", output)
                else:
                    match = _re.search(r"time=(\d+\.?\d*)\s*ms", output)
                if match:
                    latency = float(match.group(1))
                    status = "ok" if latency < 200 else ("slow" if latency < 500 else "very-slow")
                else:
                    status = "no-response"
            else:
                status = "unreachable"
        except asyncio.TimeoutError:
            status = "timeout"
        except Exception:
            status = "error"
        
        results.append({
            "name": site["name"],
            "host": site["host"],
            "latency_ms": latency,
            "status": status,
        })
    return {"sites": results}


@app.get("/api/tools/scan-railway-ips")
async def scan_railway_ips(_=Depends(require_auth)):
    """Ping Railway region endpoints (NOT Cloudflare) to test connectivity."""
    results = []
    for region in RAILWAY_REGIONS:
        latency = None
        status = "error"
        try:
            system = platform.system().lower()
            if system == "windows":
                cmd = ["ping", "-n", "1", "-w", "3000", region["host"]]
            else:
                cmd = ["ping", "-c", "1", "-W", "3", region["host"]]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
            
            if proc.returncode == 0:
                output = stdout.decode(errors="ignore")
                import re as _re
                if system == "windows":
                    match = _re.search(r"time[=<](\d+)ms", output)
                else:
                    match = _re.search(r"time=(\d+\.?\d*)\s*ms", output)
                if match:
                    latency = float(match.group(1))
                    status = "ok" if latency < 200 else ("slow" if latency < 500 else "very-slow")
                else:
                    status = "no-response"
            else:
                status = "unreachable"
        except asyncio.TimeoutError:
            status = "timeout"
        except Exception:
            status = "error"
        
        results.append({
            "region": region["name"],
            "host": region["host"],
            "latency_ms": latency,
            "status": status,
        })
    return {"regions": results}


app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

# Lazy XHTTP import (after all symbols defined)
try:
    from xhttp_siz10 import router as xhttp_router
    app.include_router(xhttp_router)
except Exception:
    pass  # XHTTP optional

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=CONFIG["port"], log_level="info", workers=1)
