import asyncio
import json
import os
import hashlib
import secrets
import time
import re
from datetime import datetime, timedelta
from urllib.parse import quote
from collections import deque, defaultdict

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging
import psutil

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("AMIR-VPN")

app = FastAPI(title="AMIR VPN", docs_url=None, redoc_url=None)

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": os.environ.get("SECRET_KEY", "ren-default-secret-key"),
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

connections: dict = {}
connection_sockets: dict = {}
link_ip_map: dict = defaultdict(set)
stats = {"total_bytes": 0, "total_requests": 0, "total_errors": 0, "start_time": time.time()}
error_logs: deque = deque(maxlen=50)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None

LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()

CUSTOM_ADDRESSES: list = ["www.speedtest.net"]
CUSTOM_ADDRESSES_LOCK = asyncio.Lock()

CUSTOM_DOMAIN: str = ""
CUSTOM_DOMAIN_LOCK = asyncio.Lock()

SESSION_COOKIE = "ren_session"
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
        if exp is None or exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def destroy_session(token: str | None):
    if token:
        async with SESSIONS_LOCK:
            SESSIONS.pop(token, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

async def keep_alive():
    while True:
        await asyncio.sleep(600)
        try:
            domain = get_domain()
            if domain and domain != "localhost":
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.get(f"https://{domain}/health")
                logger.info("Keep-alive ping sent")
        except Exception:
            pass

@app.on_event("startup")
async def startup():
    global http_client
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True)
    logger.info(f"AMIR VPN started on port {CONFIG['port']}")
    asyncio.create_task(keep_alive())

@app.on_event("shutdown")
async def shutdown():
    if http_client:
        await http_client.aclose()

def get_domain() -> str:
    return os.environ.get("RENDER_EXTERNAL_URL", os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost")).replace("https://", "").replace("http://", "")

def generate_uuid(seed: str | None = None) -> str:
    if seed is None:
        return str(secrets.token_hex(16))[:8] + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(6)
    h = hashlib.sha256(f"{seed}{CONFIG['secret']}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def generate_vless_link(uuid: str, remark: str = "AMIR VPN", address: str = None) -> str:
    domain = CUSTOM_DOMAIN if CUSTOM_DOMAIN else get_domain()
    addr = address if address else domain
    path = f"/ws/{uuid}"
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "host": domain,
        "path": path,
        "sni": domain,
        "fp": "chrome",
        "alpn": "http/1.1",
    }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{addr}:443?{query}#{quote(remark)}"

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 * 1024 * 1024)
    if unit == "MB": return int(value * 1024 * 1024)
    if unit == "KB": return int(value * 1024)
    return int(value)

def compute_expiry(expiry_days) -> str:
    """Turn a number of days into an absolute ISO expiry timestamp. 0/empty = no expiry."""
    try:
        days = float(expiry_days or 0)
    except (TypeError, ValueError):
        days = 0
    if days <= 0:
        return ""
    return (datetime.now() + timedelta(days=days)).isoformat()

def is_expired(link) -> bool:
    """True if the link has an expiry date that is in the past."""
    exp = link.get("expiry") if isinstance(link, dict) else None
    if not exp:
        return False
    try:
        return datetime.now() >= datetime.fromisoformat(exp)
    except (TypeError, ValueError):
        return False

def expiry_epoch(link) -> int:
    """Expiry as a unix timestamp for the subscription-userinfo header (0 = never)."""
    exp = link.get("expiry") if isinstance(link, dict) else None
    if not exp:
        return 0
    try:
        return int(datetime.fromisoformat(exp).timestamp())
    except (TypeError, ValueError):
        return 0

async def ensure_default_link():
    async with LINKS_LOCK:
        if not LINKS:
            LINKS["Default"] = {"label": "Default", "limit_bytes": 0, "used_bytes": 0, "max_connections": 0, "created_at": datetime.now().isoformat(), "active": True, "expiry": ""}

def get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if websocket.client:
        return websocket.client.host
    return "unknown"

def count_connections_for_link(uid: str) -> int:
    return len(link_ip_map.get(uid, set()))

def remove_ip_from_link(uid: str, ip: str):
    if uid in link_ip_map:
        link_ip_map[uid].discard(ip)
        if not link_ip_map[uid]:
            link_ip_map.pop(uid, None)

async def close_connections_for_link(uid: str):
    to_close = [cid for cid, info in connections.items() if info.get("uuid") == uid]
    for cid in to_close:
        ws = connection_sockets.get(cid)
        if ws:
            try:
                await ws.close(code=1000, reason="link deleted")
            except Exception:
                pass
        connections.pop(cid, None)
        connection_sockets.pop(cid, None)
    link_ip_map.pop(uid, None)

@app.get("/")
async def root():
    return {"service": "AMIR VPN", "version": "1.0", "status": "active", "domain": get_domain()}

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    password = str(body.get("password") or "")
    if hash_password(password) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid password")
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    await destroy_session(token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    return {"authenticated": await is_valid_session(token)}

@app.post("/api/change-password")
async def api_change_password(request: Request, _=Depends(require_auth)):
    body = await request.json()
    current = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")
    if hash_password(current) != AUTH["password_hash"]:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    AUTH["password_hash"] = hash_password(new)
    current_token = request.cookies.get(SESSION_COOKIE)
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        if current_token:
            SESSIONS[current_token] = time.time() + SESSION_TTL
    return {"ok": True}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    return {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 * 1024), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(LINKS),
        "domain": get_domain(),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_percent": psutil.virtual_memory().percent,
        "hourly_traffic": dict(hourly_traffic),
    }


@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "New Link").strip()[:60]
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', label):
        raise HTTPException(status_code=400, detail="Inbound name must contain only English letters, numbers, and characters: - _ . space")
    if not label:
        raise HTTPException(status_code=400, detail="Inbound name is required")
    async with LINKS_LOCK:
        if label in LINKS:
            raise HTTPException(status_code=400, detail="An inbound with this name already exists")
    limit_value = float(body.get("limit_value") or 0)
    limit_unit = body.get("limit_unit") or "GB"
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    max_conn = int(body.get("max_connections") or 0)
    if max_conn < 0:
        max_conn = 0
    expiry = compute_expiry(body.get("expiry_days"))
    uid = label
    async with LINKS_LOCK:
        LINKS[uid] = {"label": label, "limit_bytes": limit_bytes, "used_bytes": 0, "max_connections": max_conn, "created_at": datetime.now().isoformat(), "active": True, "expiry": expiry}
    return {"uuid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": 0, "max_connections": max_conn, "active": True, "expiry": expiry, "created_at": LINKS[uid]["created_at"], "vless_link": generate_vless_link(uid, remark=f"AMIR VPN-{label}")}

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    result = []
    async with LINKS_LOCK:
        for uid, data in LINKS.items():
            result.append({"uuid": uid, "label": data["label"], "limit_bytes": data["limit_bytes"], "used_bytes": data["used_bytes"], "max_connections": data.get("max_connections", 0), "active": data["active"], "expiry": data.get("expiry", ""), "expired": is_expired(data), "created_at": data["created_at"], "current_connections": count_connections_for_link(uid), "vless_link": generate_vless_link(uid, remark=f"AMIR VPN-{data['label']}")})
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.patch("/api/links/{uid}")
async def toggle_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        if "active" in body:
            LINKS[uid]["active"] = bool(body["active"])
        if "limit_value" in body:
            limit_value = float(body.get("limit_value") or 0)
            limit_unit = body.get("limit_unit") or "GB"
            LINKS[uid]["limit_bytes"] = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
        if "reset_usage" in body and body["reset_usage"]:
            LINKS[uid]["used_bytes"] = 0
        if "expiry_days" in body:
            LINKS[uid]["expiry"] = compute_expiry(body.get("expiry_days"))
        if "label" in body:
            LINKS[uid]["label"] = str(body["label"])[:60]
        if "max_connections" in body:
            mc = int(body["max_connections"] or 0)
            LINKS[uid]["max_connections"] = mc if mc >= 0 else 0
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    await close_connections_for_link(uid)
    return {"ok": True}


@app.get("/api/domain")
async def get_custom_domain(_=Depends(require_auth)):
    async with CUSTOM_DOMAIN_LOCK:
        return {"domain": CUSTOM_DOMAIN}


@app.post("/api/domain")
async def set_custom_domain(request: Request, _=Depends(require_auth)):
    body = await request.json()
    domain = (body.get("domain") or "").strip().lower()
    if domain:
        domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
        if not re.match(r'^[a-z0-9\-_.]+$', domain):
            raise HTTPException(status_code=400, detail="Invalid domain format")
    async with CUSTOM_DOMAIN_LOCK:
        global CUSTOM_DOMAIN
        CUSTOM_DOMAIN = domain
    return {"ok": True, "domain": CUSTOM_DOMAIN}


@app.get("/api/addresses")
async def list_addresses(_=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        return {"addresses": list(CUSTOM_ADDRESSES)}


@app.post("/api/addresses")
async def add_address(request: Request, _=Depends(require_auth)):
    body = await request.json()
    address = (body.get("address") or "").strip()
    if not address:
        raise HTTPException(status_code=400, detail="Address is required")
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', address):
        raise HTTPException(status_code=400, detail="Address must contain only English letters, numbers, and characters: - _ .")
    async with CUSTOM_ADDRESSES_LOCK:
        if address in CUSTOM_ADDRESSES:
            raise HTTPException(status_code=400, detail="Address already exists")
        CUSTOM_ADDRESSES.append(address)
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}


@app.delete("/api/addresses/{index}")
async def delete_address(index: int, _=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        if 0 <= index < len(CUSTOM_ADDRESSES):
            CUSTOM_ADDRESSES.pop(index)
        else:
            raise HTTPException(status_code=404, detail="Address not found")
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.get("/api/links/{uid}/sub")
async def get_subscription(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="link not found")
    vless_link = generate_vless_link(uid, remark=f"AMIR VPN-{link['label']}")
    used = link["used_bytes"]
    limit = link["limit_bytes"]
    used_mb = round(used / (1024 * 1024), 2)
    limit_mb = round(limit / (1024 * 1024), 2) if limit > 0 else 0
    pct = round((used / limit) * 100, 1) if limit > 0 else 0
    remaining_mb = round((limit - used) / (1024 * 1024), 2) if limit > 0 else 0
    import base64
    sub_content = f"""# AMIR VPN Subscription
# Label: {link['label']}
# Used: {used_mb} MB / {limit_mb if limit > 0 else 'Unlimited'} MB
# Remaining: {remaining_mb if limit > 0 else 'Unlimited'} MB
# Usage: {pct}%
# Status: {'Active' if link['active'] else 'Disabled'}
# Expiry: {link.get('expiry', '')[:10] if link.get('expiry') else 'Unlimited'}
{vless_link}"""
    encoded = base64.b64encode(sub_content.encode()).decode()
    return {
        "subscription_url": f"{get_domain()}/api/links/{uid}/sub",
        "config": vless_link,
        "label": link["label"],
        "used_bytes": used,
        "limit_bytes": limit,
        "used_mb": used_mb,
        "limit_mb": limit_mb,
        "remaining_mb": remaining_mb,
        "usage_percent": pct,
        "active": link["active"],
        "sub_base64": encoded,
        "sub_text": sub_content,
    }


@app.get("/sub/{uid}", response_class=HTMLResponse)
async def subscription_page(request: Request, uid: str):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="link not found")
    return HTMLResponse(content=SUB_HTML)

@app.get("/api/sub/{uid}")
async def subscription_download(uid: str):
    import base64
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="link not found")
    if not link["active"]:
        raise HTTPException(status_code=403, detail="link disabled")
    if is_expired(link):
        raise HTTPException(status_code=403, detail="link expired")
    async with CUSTOM_ADDRESSES_LOCK:
        addresses = list(CUSTOM_ADDRESSES)
    sub_links = []
    server_link = generate_vless_link(uid, remark=f"AMIR VPN-{link['label']}-Server")
    sub_links.append(server_link)
    for i, addr in enumerate(addresses):
        remark = f"AMIR VPN-{link['label']}-IP{i+1}"
        vless_link = generate_vless_link(uid, remark=remark, address=addr)
        sub_links.append(vless_link)
    sub_content = "\n".join(sub_links)
    encoded = base64.b64encode(sub_content.encode()).decode()
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": "attachment; filename=\"sub.txt\"",
        "profile-update-interval": "6",
        "subscription-userinfo": f"upload={link['used_bytes']}; download=0; total={link['limit_bytes']}; expire={expiry_epoch(link)}"
    }
    return Response(content=encoded, headers=headers)

RELAY_BUF = 64 * 1024

async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24:
        raise ValueError("chunk too small")
    pos = 0
    pos += 1; pos += 16
    addon_len = first_chunk[pos]; pos += 1; pos += addon_len
    command = first_chunk[pos]; pos += 1
    port = int.from_bytes(first_chunk[pos:pos + 2], "big"); pos += 2
    addr_type = first_chunk[pos]; pos += 1
    if addr_type == 1:
        addr_bytes = first_chunk[pos:pos + 4]; pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        domain_len = first_chunk[pos]; pos += 1
        address = first_chunk[pos:pos + domain_len].decode("utf-8", errors="ignore"); pos += domain_len
    elif addr_type == 3:
        addr_bytes = first_chunk[pos:pos + 16]; pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown address type: {addr_type}")
    return command, address, port, first_chunk[pos:]

async def check_quota(uid: str, extra_bytes: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None: return False
        if not link["active"]: return False
        if is_expired(link): return False
        if link["limit_bytes"] == 0: return True
        return (link["used_bytes"] + extra_bytes) <= link["limit_bytes"]

async def add_usage(uid: str, n: int):
    async with LINKS_LOCK:
        if uid in LINKS:
            LINKS[uid]["used_bytes"] += n

async def ws_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter, conn_id: str, link_uid: str):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect": break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data: continue
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size; stats["total_requests"] += 1
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%H:00")] += size
            await add_usage(link_uid, size)
            writer.write(data); await writer.drain()
    except WebSocketDisconnect: pass
    finally:
        try: writer.write_eof()
        except: pass

async def tcp_to_ws(websocket: WebSocket, reader: asyncio.StreamReader, conn_id: str, link_uid: str):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data: break
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%H:00")] += size
            await add_usage(link_uid, size)
            await websocket.send_bytes((b"\x00\x00" + data) if first else data)
            first = False
    except: pass

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await ensure_default_link()
    await websocket.accept()
    writer = None
    conn_id = None
    client_ip = get_client_ip(websocket)
    try:
        async with LINKS_LOCK:
            link_data = LINKS.get(uuid)
            if link_data is None or not link_data["active"]:
                await websocket.close(code=1008, reason="link not found or disabled"); return
            if is_expired(link_data):
                await websocket.close(code=1008, reason="link expired"); return
            max_conn = link_data.get("max_connections", 0)
        if max_conn > 0:
            already_connected = client_ip in link_ip_map.get(uuid, set())
            if not already_connected:
                current = count_connections_for_link(uuid)
                if current >= max_conn:
                    await websocket.close(code=1008, reason="connection limit reached"); return
        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect": return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk: return
        command, address, port, initial_payload = await parse_vless_header(first_chunk)
        conn_id = secrets.token_urlsafe(8)
        connections[conn_id] = {"uuid": uuid, "ip": client_ip, "connected_at": datetime.now().isoformat(), "bytes": 0}
        connection_sockets[conn_id] = websocket
        link_ip_map[uuid].add(client_ip)
        size = len(first_chunk)
        stats["total_bytes"] += size; stats["total_requests"] += 1
        connections[conn_id]["bytes"] += size
        hourly_traffic[datetime.now().strftime("%H:00")] += size
        await add_usage(uuid, size)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)
        if initial_payload:
            p_size = len(initial_payload)
            stats["total_bytes"] += p_size
            connections[conn_id]["bytes"] += p_size
            hourly_traffic[datetime.now().strftime("%H:00")] += p_size
            await add_usage(uuid, p_size)
            writer.write(initial_payload); await writer.drain()
        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending: t.cancel()
    except WebSocketDisconnect: pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
    finally:
        if writer:
            try: writer.close()
            except: pass
        if conn_id:
            info = connections.pop(conn_id, None)
            connection_sockets.pop(conn_id, None)
            if info:
                uid = info.get("uuid")
                ip = info.get("ip")
                if uid and ip:
                    has_other = any(c.get("uuid") == uid and c.get("ip") == ip for c in connections.values())
                    if not has_other:
                        remove_ip_from_link(uid, ip)



LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AMIR VPN</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    html[data-theme="dark"]{--bg:#050508;--surface:rgba(20,20,20,0.85);--surface2:#1c1c1c;--border:rgba(255,255,255,0.06);--text:rgba(255,255,255,0.92);--text2:rgba(255,255,255,0.5);--text3:rgba(255,255,255,0.25);--primary:#ff1a1a;--primary-glow:rgba(255,26,26,0.15);--accent:#b91c1c;--error:#ef4444;--error-bg:rgba(239,68,68,0.08);--orb1:rgba(255,26,26,0.12);--orb2:rgba(139,0,0,0.1);--orb3:rgba(220,38,38,0.06)}
    html[data-theme="light"]{--bg:#080c0a;--surface:rgba(10,30,20,0.85);--surface2:#0a1a10;--border:rgba(0,255,136,0.06);--text:rgba(255,255,255,0.92);--text2:rgba(255,255,255,0.5);--text3:rgba(255,255,255,0.25);--primary:#00ff88;--primary-glow:rgba(0,255,136,0.15);--accent:#10b981;--error:#ef4444;--error-bg:rgba(239,68,68,0.08);--orb1:rgba(0,255,136,0.12);--orb2:rgba(5,150,105,0.1);--orb3:rgba(34,197,94,0.06)}
    html[data-theme="purple"]{--bg:#0a0610;--surface:rgba(40,10,60,0.85);--surface2:#1c0930;--border:rgba(168,85,247,0.06);--text:rgba(255,255,255,0.92);--text2:rgba(255,255,255,0.5);--text3:rgba(255,255,255,0.25);--primary:#a855f7;--primary-glow:rgba(168,85,247,0.15);--accent:#9333ea;--error:#ef4444;--error-bg:rgba(239,68,68,0.08);--orb1:rgba(168,85,247,0.12);--orb2:rgba(109,40,217,0.1);--orb3:rgba(139,92,246,0.06)}
    body{font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--text);transition:background .5s,color .5s;overflow:hidden}
    body[dir="rtl"]{direction:rtl;text-align:right}

    .bg-canvas{position:fixed;inset:0;z-index:0;pointer-events:none}
    .orb{position:absolute;border-radius:50%;filter:blur(80px);opacity:0;animation:orbFloat 20s ease-in-out infinite}
    .orb-1{width:400px;height:400px;background:var(--orb1);top:-10%;left:-5%;animation-delay:0s}
    .orb-2{width:350px;height:350px;background:var(--orb2);bottom:-10%;right:-5%;animation-delay:-7s}
    .orb-3{width:250px;height:250px;background:var(--orb3);top:40%;left:60%;animation-delay:-14s}
    @keyframes orbFloat{0%,100%{transform:translate(0,0) scale(1);opacity:0.6}25%{transform:translate(60px,-40px) scale(1.1);opacity:0.8}50%{transform:translate(-30px,50px) scale(0.9);opacity:0.5}75%{transform:translate(40px,20px) scale(1.05);opacity:0.7}}

    .grid-bg{position:fixed;inset:0;z-index:0;opacity:0.03;background-image:linear-gradient(rgba(255,255,255,0.1) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,0.1) 1px,transparent 1px);background-size:60px 60px;pointer-events:none}

    .toolbar{position:fixed;top:20px;right:20px;display:flex;gap:6px;z-index:10}
    .toolbar button{width:36px;height:36px;border-radius:10px;border:1px solid var(--border);background:var(--surface);color:var(--text2);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:15px;transition:all .3s;backdrop-filter:blur(20px)}
    .toolbar button:hover{border-color:var(--primary);color:var(--primary);transform:scale(1.05)}

    .login-page{width:100%;max-width:380px;padding:0 20px;position:relative;z-index:1}
    .login-card{background:var(--surface);border:1px solid var(--border);border-radius:24px;padding:48px 36px 36px;position:relative;overflow:hidden;backdrop-filter:blur(40px);box-shadow:0 8px 40px rgba(0,0,0,0.15),0 0 80px var(--primary-glow);animation:cardIn .8s cubic-bezier(0.16,1,0.3,1) forwards;opacity:0;transform:translateY(30px) scale(0.96)}
    @keyframes cardIn{to{opacity:1;transform:translateY(0) scale(1)}}
    .login-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--primary),transparent);animation:shimmer 3s ease-in-out infinite}
    @keyframes shimmer{0%,100%{opacity:0.5;transform:scaleX(0.5)}50%{opacity:1;transform:scaleX(1)}}
    .login-card::after{content:'';position:absolute;top:-50%;left:-50%;width:200%;height:200%;background:radial-gradient(circle at var(--mx,50%) var(--my,50%),var(--primary-glow) 0%,transparent 50%);pointer-events:none;transition:opacity .3s;opacity:0}
    .login-card:hover::after{opacity:1}

    .brand{text-align:center;margin-bottom:36px}
    .brand svg{margin-bottom:20px;filter:drop-shadow(0 0 20px var(--primary-glow));animation:logoPulse 4s ease-in-out infinite}
    @keyframes logoPulse{0%,100%{filter:drop-shadow(0 0 20px var(--primary-glow));transform:scale(1)}50%{filter:drop-shadow(0 0 30px var(--primary-glow));transform:scale(1.02)}}
    .brand h1{font-size:22px;font-weight:800;color:var(--text);letter-spacing:-0.03em;animation:fadeUp .6s .2s ease both}
    .brand p{font-size:11px;color:var(--text3);margin-top:6px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;animation:fadeUp .6s .3s ease both}
    @keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}

    .form-group{margin-bottom:20px;animation:fadeUp .6s .4s ease both}
    .form-group label{display:block;font-size:11px;font-weight:700;color:var(--text2);margin-bottom:8px;text-transform:uppercase;letter-spacing:0.06em}
    .form-group input{width:100%;padding:13px 16px;background:var(--surface2);border:1.5px solid var(--border);border-radius:12px;color:var(--text);font-size:14px;font-family:inherit;outline:none;transition:all .3s cubic-bezier(0.4,0,0.2,1)}
    .form-group input:focus{border-color:var(--primary);box-shadow:0 0 0 4px var(--primary-glow),0 0 20px var(--primary-glow)}
    .form-group input::placeholder{color:var(--text3)}

    .login-btn{width:100%;padding:13px;background:var(--primary);border:none;border-radius:12px;color:#fff;font-size:14px;font-weight:700;font-family:inherit;cursor:pointer;transition:all .3s cubic-bezier(0.4,0,0.2,1);letter-spacing:0.02em;position:relative;overflow:hidden;animation:fadeUp .6s .5s ease both}
    .login-btn::before{content:'';position:absolute;top:50%;left:50%;width:0;height:0;background:rgba(255,255,255,0.2);border-radius:50%;transform:translate(-50%,-50%);transition:width .5s,height .5s}
    .login-btn:hover{filter:brightness(1.15);transform:translateY(-2px);box-shadow:0 8px 25px var(--primary-glow)}
    .login-btn:hover::before{width:300px;height:300px}
    .login-btn:active{transform:translateY(0) scale(0.98)}
    .login-btn:active::before{width:0;height:0;transition:width .1s,height .1s}

    .error-msg{background:var(--error-bg);border:1px solid rgba(255,77,106,0.15);color:var(--error);padding:10px 14px;border-radius:10px;font-size:13px;display:none;margin-bottom:20px;text-align:center;font-weight:500;animation:shake .4s ease}
    .error-msg.show{display:block}
    @keyframes shake{0%,100%{transform:translateX(0)}20%,60%{transform:translateX(-6px)}40%,80%{transform:translateX(6px)}}

    .particles{position:fixed;inset:0;z-index:0;pointer-events:none;overflow:hidden}
    .particle{position:absolute;width:2px;height:2px;background:var(--primary);border-radius:50%;opacity:0;animation:particleFall linear infinite}
    @keyframes particleFall{0%{opacity:0;transform:translateY(-10px) scale(0)}10%{opacity:0.6;transform:translateY(0) scale(1)}90%{opacity:0.3;transform:translateY(calc(100vh - 20px)) scale(0.5)}100%{opacity:0;transform:translateY(100vh) scale(0)}}

    .theme-picker{position:fixed;top:20px;left:20px;z-index:10;background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:8px;display:flex;gap:4px;backdrop-filter:blur(20px)}
    .theme-option{width:24px;height:24px;border-radius:6px;cursor:pointer;transition:all .2s;border:2px solid transparent}
    .theme-option:hover{transform:scale(1.15)}
    .theme-option.selected{border-color:#fff;box-shadow:0 0 8px var(--primary-glow)}
    .theme-red{background:#ff1a1a}
    .theme-green{background:#00ff88}
    .theme-purple{background:#a855f7}
  </style>
</head>
<body>
  <div class="theme-picker">
    <div class="theme-option theme-red selected" onclick="setTheme('dark')" title="Red Neon Theme"></div>
    <div class="theme-option theme-green" onclick="setTheme('light')" title="Ghost Neon Theme"></div>
    <div class="theme-option theme-purple" onclick="setTheme('purple')" title="Purple Neon Theme"></div>
  </div>

  <div class="bg-canvas"><div class="orb orb-1"></div><div class="orb orb-2"></div><div class="orb orb-3"></div></div>
  <div class="grid-bg"></div>
  <div class="particles" id="particles"></div>

  <div class="toolbar">
    <button id="lang-toggle" onclick="cycleLang()" title="Language">EN</button>
  </div>

  <div class="login-page">
    <div class="login-card" id="login-card">
      <div class="brand">
        <svg width="110" height="110" viewBox="0 0 120 120" style="border-radius:24px;overflow:hidden;filter:drop-shadow(0 0 24px var(--primary-glow))">
          <defs>
            <linearGradient id="amir-g" x1="0" y1="0" x2="120" y2="120">
              <stop stop-color="#ff1a1a"/><stop offset="1" stop-color="#7f1d1d"/>
            </linearGradient>
            <filter id="glow"><feGaussianBlur stdDeviation="2" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
          </defs>
          <rect width="120" height="120" rx="24" fill="url(#amir-g)"/>
          <!-- Rotating circle -->
          <circle cx="60" cy="52" r="30" fill="none" stroke="#fff" stroke-width="0.6" opacity="0.2">
            <animateTransform attributeName="transform" type="rotate" from="0 60 52" to="360 60 52" dur="20s" repeatCount="indefinite"/>
          </circle>
          <!-- AMIR text with 3D flip to VPN -->
          <g filter="url(#glow)">
            <text x="60" y="48" text-anchor="middle" font-family="Inter, sans-serif" font-size="24" font-weight="900" fill="#fff">
              AMIR
              <animate attributeName="opacity" values="1,1,0,0,1" dur="6s" repeatCount="indefinite"/>
            </text>
            <text x="61.5" y="49.5" text-anchor="middle" font-family="Inter, sans-serif" font-size="24" font-weight="900" fill="rgba(255,255,255,0.15)">
              AMIR
              <animate attributeName="opacity" values="0.15,0.15,0,0,0.15" dur="6s" repeatCount="indefinite"/>
            </text>
            <text x="60" y="48" text-anchor="middle" font-family="Inter, sans-serif" font-size="24" font-weight="900" fill="#fff">
              VPN
              <animate attributeName="opacity" values="0,0,1,1,0" dur="6s" repeatCount="indefinite"/>
            </text>
            <text x="61.5" y="49.5" text-anchor="middle" font-family="Inter, sans-serif" font-size="24" font-weight="900" fill="rgba(255,255,255,0.15)">
              VPN
              <animate attributeName="opacity" values="0,0,0.15,0.15,0" dur="6s" repeatCount="indefinite"/>
            </text>
          </g>
          <!-- Center node -->
          <circle cx="60" cy="52" r="2" fill="#fff" opacity="0.8">
            <animate attributeName="r" values="2;3;2" dur="2s" repeatCount="indefinite"/>
          </circle>
          <!-- Orbiting dots -->
          <circle cx="60" cy="22" r="2.5" fill="#fff" opacity="0.7">
            <animateTransform attributeName="transform" type="rotate" from="0 60 52" to="360 60 52" dur="5s" repeatCount="indefinite"/>
          </circle>
          <circle cx="90" cy="52" r="2" fill="#fff" opacity="0.5">
            <animateTransform attributeName="transform" type="rotate" from="120 60 52" to="480 60 52" dur="7s" repeatCount="indefinite"/>
          </circle>
          <circle cx="30" cy="52" r="2" fill="#fff" opacity="0.5">
            <animateTransform attributeName="transform" type="rotate" from="240 60 52" to="600 60 52" dur="7s" repeatCount="indefinite"/>
          </circle>
          <!-- Bottom label -->
          <text x="60" y="78" text-anchor="middle" font-family="Inter, sans-serif" font-size="7" font-weight="700" fill="rgba(255,255,255,0.5)" letter-spacing="0.25em">SECURE VPN</text>
          <!-- Bottom network bar -->
          <circle cx="32" cy="100" r="3" fill="#fff" opacity="0.5">
            <animate attributeName="opacity" values="0.5;0.2;0.5" dur="3s" repeatCount="indefinite"/>
          </circle>
          <line x1="35" y1="100" x2="55" y2="100" stroke="#fff" stroke-width="0.8" opacity="0.3"/>
          <circle cx="60" cy="100" r="3" fill="#fff" opacity="0.8">
            <animate attributeName="r" values="3;4;3" dur="2.5s" repeatCount="indefinite"/>
          </circle>
          <line x1="63" y1="100" x2="85" y2="100" stroke="#fff" stroke-width="0.8" opacity="0.3"/>
          <circle cx="88" cy="100" r="3" fill="#fff" opacity="0.5">
            <animate attributeName="opacity" values="0.5;0.2;0.5" dur="3s" begin="0.5s" repeatCount="indefinite"/>
          </circle>
          </line>
          <circle cx="135" cy="105" r="3" fill="var(--primary)" opacity="0.6">
            <animate attributeName="opacity" values="0.6;0.2;0.6" dur="3s" begin="1s" repeatCount="indefinite"/>
          </circle>
        </svg>
        <h1>AMIR VPN</h1>
        <p>v1.0</p>
      </div>
      <div class="error-msg" id="err-box"></div>
      <form id="login-form">
        <div class="form-group">
          <label data-en="Password" data-fa="رمز عبور">Password</label>
          <input type="password" id="password" placeholder="Enter password" autofocus>
        </div>
        <button type="submit" class="login-btn" data-en="Sign In" data-fa="ورود">Sign In</button>
      </form>
    </div>
  </div>

  <canvas id="galaxy" style="position:fixed;inset:0;z-index:0;pointer-events:none"></canvas>

  <script>
    let lang = localStorage.getItem('amir_lang') || 'en';
    let theme = localStorage.getItem('amir_theme') || 'dark';
    function setLang(l) {lang=l;document.body.dir=l==='fa'?'rtl':'ltr';document.querySelectorAll('[data-en]').forEach(el=>{const v=el.getAttribute('data-'+l);if(v)el.textContent=v});document.getElementById('lang-toggle').textContent=l.toUpperCase();localStorage.setItem('amir_lang',l)}
    function cycleLang() {setLang(lang==='en'?'fa':'en')}
    function applyTheme(t) {theme=t;document.documentElement.setAttribute('data-theme',t);localStorage.setItem('amir_theme',t);document.querySelectorAll('.theme-option').forEach(o=>o.classList.remove('selected'));if(t==='dark')document.querySelector('.theme-red').classList.add('selected');if(t==='light')document.querySelector('.theme-green').classList.add('selected');if(t==='purple')document.querySelector('.theme-purple').classList.add('selected')}
    function toggleTheme(){applyTheme(theme==='dark'?'light':(theme==='light'?'purple':'dark'))}
    function setTheme(t){applyTheme(t)}
    applyTheme(theme);setLang(lang);

    const card=document.getElementById('login-card');
    card.addEventListener('mousemove',e=>{const r=card.getBoundingClientRect();card.style.setProperty('--mx',((e.clientX-r.left)/r.width*100)+'%');card.style.setProperty('--my',((e.clientY-r.top)/r.height*100)+'%')});

    // Galaxy background
    const canvas=document.getElementById('galaxy');
    const ctx=canvas.getContext('2d');
    let stars=[];
    function resizeCanvas(){canvas.width=window.innerWidth;canvas.height=window.innerHeight}
    function initStars(){stars=[];for(let i=0;i<200;i++)stars.push({x:Math.random()*canvas.width,y:Math.random()*canvas.height,r:Math.random()*1.5+0.3,speed:Math.random()*0.3+0.05,flicker:Math.random()*Math.PI*2})}
    function drawGalaxy(){ctx.clearRect(0,0,canvas.width,canvas.height);const t=Date.now()*0.001;stars.forEach(s=>{const alpha=0.3+0.4*Math.sin(t*s.speed+s.flicker);ctx.beginPath();ctx.arc(s.x,s.y,s.r,0,Math.PI*2);ctx.fillStyle='rgba(255,255,255,'+alpha+')';ctx.fill()});requestAnimationFrame(drawGalaxy)}
    resizeCanvas();initStars();drawGalaxy();
    window.addEventListener('resize',()=>{resizeCanvas();initStars()});

    // Particles
    const pc=document.getElementById('particles');
    for(let i=0;i<15;i++){const p=document.createElement('div');p.className='particle';p.style.left=Math.random()*100+'%';p.style.animationDuration=(8+Math.random()*12)+'s';p.style.animationDelay=Math.random()*10+'s';p.style.width=p.style.height=(1+Math.random()*2)+'px';pc.appendChild(p)}

    document.getElementById('login-form').addEventListener('submit',async e=>{
      e.preventDefault();const err=document.getElementById('err-box');err.classList.remove('show');
      try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('password').value})});if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'Failed');}location.href='/dashboard';}catch(e){err.textContent=e.message;err.classList.add('show')}
    });
  </script>
</body>
</html>"""


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AMIR VPN</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html[data-theme="dark"]{--bg:#050508;--surface:rgba(20,20,20,0.8);--surface2:rgba(28,28,28,0.9);--surface3:rgba(42,42,42,0.8);--border:rgba(255,255,255,0.06);--border2:rgba(255,255,255,0.1);--text:rgba(255,255,255,0.92);--text2:rgba(255,255,255,0.5);--text3:rgba(255,255,255,0.25);--primary:#ff1a1a;--primary-glow:rgba(255,26,26,0.15);--primary-dim:rgba(255,26,26,0.08);--accent:#b91c1c;--green:#00ff88;--green-dim:rgba(0,255,136,0.08);--red:#ef4444;--red-dim:rgba(239,68,68,0.08);--yellow:#fbbf24;--sidebar-bg:rgba(10,10,14,0.92);--shadow:0 2px 8px rgba(0,0,0,0.4);--glass-bg:rgba(255,255,255,0.03)}
html[data-theme="light"]{--bg:#080c0a;--surface:rgba(10,30,20,0.8);--surface2:rgba(15,40,25,0.9);--surface3:rgba(20,55,35,0.8);--border:rgba(0,255,136,0.06);--border2:rgba(0,255,136,0.1);--text:rgba(255,255,255,0.92);--text2:rgba(255,255,255,0.5);--text3:rgba(255,255,255,0.25);--primary:#00ff88;--primary-glow:rgba(0,255,136,0.12);--primary-dim:rgba(0,255,136,0.06);--accent:#10b981;--green:#22c55e;--green-dim:rgba(34,197,94,0.08);--red:#ef4444;--red-dim:rgba(239,68,68,0.08);--yellow:#fbbf24;--sidebar-bg:rgba(6,12,10,0.95);--shadow:0 2px 8px rgba(0,0,0,0.4);--glass-bg:rgba(0,255,136,0.02)}
html[data-theme="purple"]{--bg:#0a0610;--surface:rgba(40,10,60,0.8);--surface2:rgba(50,15,75,0.9);--surface3:rgba(60,20,90,0.8);--border:rgba(168,85,247,0.06);--border2:rgba(168,85,247,0.1);--text:rgba(255,255,255,0.92);--text2:rgba(255,255,255,0.5);--text3:rgba(255,255,255,0.25);--primary:#a855f7;--primary-glow:rgba(168,85,247,0.12);--primary-dim:rgba(168,85,247,0.06);--accent:#9333ea;--green:#22c55e;--green-dim:rgba(34,197,94,0.08);--red:#ef4444;--red-dim:rgba(239,68,68,0.08);--yellow:#fbbf24;--sidebar-bg:rgba(12,6,18,0.95);--shadow:0 2px 8px rgba(0,0,0,0.4);--glass-bg:rgba(168,85,247,0.02)}
html,body{height:100%}
body{font-family:'Inter','Vazirmatn',-apple-system,BlinkMacSystemFont,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;transition:background .3s,color .3s}
body[dir="rtl"]{direction:rtl;text-align:right}
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:3px}

.sidebar{width:220px;background:var(--sidebar-bg);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;left:0;top:0;bottom:0;z-index:100;transition:background .3s;backdrop-filter:blur(20px)}
.sidebar-brand{padding:16px 16px 14px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--border);position:relative;overflow:hidden}
.sidebar-brand::after{content:'';position:absolute;bottom:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--primary),transparent);animation:shimmer 4s ease-in-out infinite}
@keyframes shimmer{0%,100%{opacity:0.3;transform:scaleX(0.3)}50%{opacity:0.8;transform:scaleX(1)}}
.sidebar-brand-left{display:flex;align-items:center;gap:10px}
.sidebar-brand-left .brand-name{font-size:15px;font-weight:700;color:var(--text);letter-spacing:-0.02em}
.sidebar-brand-right{display:flex;gap:4px}
.sidebar-brand-right button{width:28px;height:28px;border-radius:7px;border:1px solid var(--border);background:var(--surface);color:var(--text3);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:12px;transition:all .2s}
.sidebar-brand-right button:hover{border-color:var(--primary);color:var(--primary)}
.sidebar-nav{flex:1;padding:8px;overflow-y:auto}
.nav-section{font-size:10px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.08em;padding:14px 12px 6px}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 12px;margin:1px 0;border-radius:8px;color:var(--text2);font-size:13px;font-weight:500;cursor:pointer;transition:all .15s;text-decoration:none;border:none;background:none;width:100%;text-align:left}
.nav-item:hover{background:var(--primary-dim);color:var(--text)}
.nav-item.active{background:var(--primary-dim);color:var(--primary);font-weight:600;box-shadow:inset 3px 0 0 var(--primary)}
.nav-icon{width:18px;height:18px;flex-shrink:0;opacity:0.7}
.nav-item.active .nav-icon{opacity:1}
.nav-badge{margin-left:auto;background:var(--surface3);color:var(--text3);font-size:10px;padding:2px 7px;border-radius:8px;font-weight:600}
.sidebar-footer{padding:12px;border-top:1px solid var(--border)}
.sidebar-footer .footer-row{display:flex;gap:4px;margin-bottom:8px}
.sidebar-footer .footer-btn{flex:1;padding:6px;border:1px solid var(--border);border-radius:7px;background:var(--surface);color:var(--text3);font-family:inherit;font-size:11px;font-weight:600;cursor:pointer;transition:all .2s;text-align:center}
.sidebar-footer .footer-btn.active{background:var(--primary);color:#fff;border-color:var(--primary)}
.sidebar-footer .footer-btn:hover:not(.active){border-color:var(--border2);color:var(--text2)}
.sidebar-footer .logout-btn{width:100%;padding:7px;border:1px solid var(--border);border-radius:7px;background:none;color:var(--text3);font-family:inherit;font-size:11px;font-weight:600;cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:center;gap:6px}
.sidebar-footer .logout-btn:hover{background:var(--red-dim);border-color:rgba(255,77,106,0.2);color:var(--red)}
.sidebar-footer .version{text-align:center;font-size:10px;color:var(--text3);margin-top:8px;letter-spacing:0.02em}
.theme-pick{display:flex;gap:4px;margin-bottom:8px;justify-content:center}
.theme-dot{width:20px;height:20px;border-radius:50%;cursor:pointer;border:2px solid transparent;transition:all .2s}
.theme-dot:hover{transform:scale(1.15)}
.theme-dot.sel{border-color:rgba(255,255,255,0.6)}
.theme-dot.red{background:#ff1a1a}
.theme-dot.green{background:#00ff88}
.theme-dot.purple{background:#a855f7}

.main{margin-left:220px;flex:1;padding:24px 28px 48px;min-height:100vh}
.page{display:none;animation:pageIn .4s ease}
.page.active{display:block}
@keyframes pageIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.page-header{margin-bottom:20px;display:flex;align-items:center;justify-content:space-between}
.page-title{font-size:18px;font-weight:700;color:var(--text);letter-spacing:-0.01em}
.page-sub{font-size:12px;color:var(--text3);margin-top:3px}

.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:18px 20px;transition:all .3s cubic-bezier(0.4,0,0.2,1);animation:cardIn .5s ease both;position:relative;overflow:hidden;backdrop-filter:blur(20px)}
.stat-card::after{content:'';position:absolute;top:-50%;right:-50%;width:100%;height:100%;background:radial-gradient(circle,var(--glass-bg) 0%,transparent 70%);pointer-events:none}
.stat-card:nth-child(1){animation-delay:.1s}.stat-card:nth-child(2){animation-delay:.2s}.stat-card:nth-child(3){animation-delay:.3s}.stat-card:nth-child(4){animation-delay:.4s}
@keyframes cardIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
.stat-card:hover{box-shadow:0 4px 20px var(--primary-glow);transform:translateY(-2px)}
.stat-icon{width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;margin-bottom:10px;background:var(--primary-dim)}
.stat-label{font-size:11px;color:var(--text3);font-weight:600;text-transform:uppercase;letter-spacing:0.04em;margin-bottom:4px}
.stat-value{font-size:22px;font-weight:700;color:var(--text);letter-spacing:-0.02em}
.stat-unit{font-size:12px;font-weight:400;color:var(--text3)}

.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:18px;margin-bottom:12px;transition:all .3s cubic-bezier(0.4,0,0.2,1);animation:cardIn .5s ease both;backdrop-filter:blur(20px)}
.card:hover{box-shadow:var(--shadow);transform:translateY(-1px)}
.card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
.card-title{font-size:13px;font-weight:600;display:flex;align-items:center;gap:8px;color:var(--text)}

.btn{font-family:inherit;font-size:12px;font-weight:600;border-radius:8px;padding:7px 14px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;border:none;transition:all .15s}
.btn-primary{background:var(--primary);color:#fff}
.btn-primary:hover{filter:brightness(1.15);box-shadow:0 4px 12px var(--primary-glow)}
.btn-secondary{background:var(--surface3);color:var(--text2);border:1px solid var(--border);position:relative;overflow:hidden}
.btn-secondary:hover{border-color:var(--primary);color:var(--primary);transform:translateY(-1px);box-shadow:0 2px 8px var(--primary-glow)}
.btn-danger{background:var(--red-dim);color:var(--red);border:1px solid rgba(255,77,106,0.12)}
.btn-danger:hover{background:rgba(255,77,106,0.15)}
.btn-sm{padding:5px 10px;font-size:11px}

.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:12px}

.table-wrap{overflow-x:auto}
.table{width:100%;border-collapse:collapse}
.table th{text-align:left;font-size:11px;font-weight:600;color:var(--text3);padding:10px 12px;text-transform:uppercase;letter-spacing:0.04em;border-bottom:1px solid var(--border);background:var(--surface2)}
.table td{padding:10px 12px;border-bottom:1px solid var(--border);font-size:13px;vertical-align:middle}
.table tr:last-child td{border-bottom:none}
.table tbody tr:hover td{background:var(--primary-dim)}

.tag{display:inline-flex;align-items:center;padding:2px 8px;border-radius:5px;font-size:10px;font-weight:700;letter-spacing:0.03em;text-transform:uppercase}
.tag-vless{background:var(--primary-dim);color:var(--primary)}
.tag-active{background:var(--green-dim);color:var(--green)}
.tag-disabled{background:var(--red-dim);color:var(--red)}
.tag-expired{background:rgba(251,191,36,0.1);color:var(--yellow)}

.usage-pill{display:flex;align-items:center;gap:8px;padding:3px 10px;border-radius:999px;background:var(--surface3);font-size:11px;color:var(--text2)}
.usage-pill .used{color:var(--text);font-weight:600}
.usage-pill .bar{flex:1;height:4px;background:var(--bg);border-radius:2px;min-width:50px}
.usage-pill .fill{height:100%;border-radius:2px;transition:width .3s}
.usage-pill .limit{color:var(--text3)}

.toggle{width:34px;height:18px;border-radius:10px;background:var(--surface3);position:relative;cursor:pointer;transition:all .3s cubic-bezier(0.4,0,0.2,1);border:1px solid var(--border)}
.toggle::after{content:'';position:absolute;width:12px;height:12px;border-radius:50%;background:var(--text3);top:2px;left:2px;transition:all .3s cubic-bezier(0.4,0,0.2,1)}
.toggle.on{background:var(--green);border-color:var(--green);box-shadow:0 0 12px rgba(0,255,136,0.3)}
.toggle.on::after{left:18px;background:#fff}

.sys-bar{height:6px;background:var(--surface3);border-radius:3px;overflow:hidden}
.sys-bar-fill{height:100%;border-radius:3px;transition:width .4s}

.status-item{display:flex;align-items:center;justify-content:space-between;padding:11px 0;border-bottom:1px solid var(--border)}
.status-item:last-child{border-bottom:none}
.status-key{color:var(--text2);font-size:12px;display:flex;align-items:center;gap:8px}
.status-val{color:var(--text);font-weight:600;font-size:12px}

.form-group{display:flex;flex-direction:column;gap:5px;margin-bottom:12px}
.form-label{font-size:11px;font-weight:600;color:var(--text2);text-transform:uppercase;letter-spacing:0.04em}
.form-input,.form-select{padding:8px 12px;border-radius:8px;border:1px solid var(--border);font-family:inherit;font-size:13px;outline:none;color:var(--text);background:var(--surface2);transition:all .2s;backdrop-filter:blur(10px)}
.form-input:focus,.form-select:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-glow)}
.form-select option{background:var(--surface2);color:var(--text)}
.form-row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}
.form-row .form-group{margin-bottom:0;flex:1;min-width:100px}

.empty{text-align:center;padding:40px 16px;color:var(--text3)}
.empty-icon{margin-bottom:10px;opacity:0.3}

.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%) translateY(20px);background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:10px;padding:10px 20px;font-size:12px;font-weight:500;opacity:0;transition:all .3s cubic-bezier(0.4,0,0.2,1);z-index:999;display:flex;align-items:center;gap:8px;box-shadow:0 8px 24px rgba(0,0,0,0.2);backdrop-filter:blur(20px)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.toast.error{border-color:var(--red-dim);color:var(--red)}

.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:200;display:none;align-items:center;justify-content:center;backdrop-filter:blur(6px)}
.modal-overlay.show{display:flex}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:24px;width:100%;max-width:460px;position:relative;box-shadow:0 20px 60px rgba(0,0,0,0.3),0 0 40px var(--primary-glow);transform:scale(0.9);opacity:0;transition:all .4s cubic-bezier(0.34,1.56,0.64,1);backdrop-filter:blur(30px)}
.modal-overlay.show .modal{transform:scale(1);opacity:1}
.modal-title{font-size:15px;font-weight:700;margin-bottom:18px;color:var(--text)}
.modal-close{position:absolute;top:12px;left:12px;background:var(--surface3);border:1px solid var(--border);color:var(--text3);width:28px;height:28px;border-radius:7px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .2s}
.modal-close:hover{background:var(--red-dim);color:var(--red);border-color:rgba(255,77,106,0.2)}

.qr-box{text-align:center;padding:24px;background:var(--surface2);border-radius:14px;margin-top:14px;border:1px solid var(--border);transition:all .3s;backdrop-filter:blur(10px)}
.qr-box:hover{border-color:var(--primary);box-shadow:0 0 20px var(--primary-glow)}
.qr-box img{max-width:220px;border-radius:10px;border:3px solid var(--surface);box-shadow:0 4px 16px rgba(0,0,0,0.1);transition:transform .3s}
.qr-box img:hover{transform:scale(1.05)}

@keyframes qrSlideUp{0%{transform:translateY(30px) scale(0.9);opacity:0}60%{transform:translateY(-4px) scale(1.02);opacity:1}100%{transform:translateY(0) scale(1);opacity:1}}
@keyframes qrGlow{0%,100%{box-shadow:0 0 10px var(--primary-glow)}50%{box-shadow:0 0 25px var(--primary-glow),0 0 50px var(--glass-bg)}}
.qr-box.animate-in{animation:qrSlideUp .5s cubic-bezier(0.34,1.56,0.64,1) forwards}
.qr-box.animate-glow{animation:qrGlow 2s ease-in-out 1}

.btn-copy,.btn-qr{position:relative;overflow:hidden;font-family:inherit;font-size:11px;font-weight:600;border-radius:8px;padding:5px 10px;cursor:pointer;border:none;display:inline-flex;align-items:center;gap:4px;transition:all .25s cubic-bezier(0.34,1.56,0.64,1)}
.btn-copy{background:var(--primary-dim);color:var(--primary);border:1px solid rgba(255,26,26,0.15)}
.btn-copy:hover{background:var(--primary);color:#fff;transform:translateY(-2px);box-shadow:0 4px 12px var(--primary-glow)}
.btn-qr{background:var(--green-dim);color:var(--green);border:1px solid rgba(0,255,136,0.15)}
.btn-qr:hover{background:var(--green);color:#000;transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,255,136,0.2)}
.btn-copy:active,.btn-qr:active{transform:translateY(0) scale(0.96)}

.detail-label{font-size:10px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:5px}
.detail-value{padding:8px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;font-size:12px;color:var(--text2);word-break:break-all;font-family:'SF Mono',Monaco,Consolas,monospace;line-height:1.6}
.detail-row{display:flex;gap:12px;margin-bottom:12px}
.detail-row .detail-col{flex:1}
.detail-actions{display:flex;gap:6px;flex-wrap:wrap;margin-top:14px}

.inbounds-toolbar{display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap}
.search-box{flex:1;min-width:180px;position:relative}
.search-box input{width:100%;padding:8px 12px 8px 32px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;font-family:inherit;outline:none;transition:all .2s;backdrop-filter:blur(10px)}
.search-box input:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-glow)}
.search-box svg{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--text3)}
.filter-chips{display:flex;gap:3px;padding:3px 5px;background:var(--surface2);border:1px solid var(--border);border-radius:8px}
.chip{padding:5px 12px;border-radius:6px;font-size:11px;font-weight:600;color:var(--text3);cursor:pointer;border:none;background:none;transition:all .2s;font-family:inherit}
.chip.active{background:var(--primary);color:#fff}
.chip:hover:not(.active){background:var(--surface3);color:var(--text2)}

.inbound-cards{display:none;flex-direction:column;gap:8px;padding:0 4px}
.inbound-card{border:1px solid var(--border);border-radius:10px;padding:12px;background:var(--surface2);display:flex;flex-direction:column;gap:8px;backdrop-filter:blur(10px)}
.inbound-card-header{display:flex;align-items:center;justify-content:space-between}
.inbound-card-id{font-size:10px;color:var(--text3);font-weight:600}
.inbound-card-name{font-size:13px;font-weight:600;color:var(--text)}
.inbound-card-actions{display:flex;gap:4px;justify-content:flex-end}

.mobile-header{display:none;position:fixed;top:0;left:0;right:0;height:44px;background:var(--sidebar-bg);border-bottom:1px solid var(--border);z-index:90;align-items:center;justify-content:space-between;padding:0 14px}
.menu-toggle{width:32px;height:32px;border-radius:8px;border:1px solid var(--border);background:var(--surface);color:var(--text2);display:flex;align-items:center;justify-content:center;cursor:pointer;font-size:14px}
.sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:99}
.sidebar-overlay.show{display:block}

@media(max-width:768px){
  .sidebar{transform:translateX(-100%);width:220px;z-index:200}
  .sidebar.open{transform:translateX(0);box-shadow:4px 0 20px rgba(0,0,0,0.4)}
  .main{margin-left:0;padding-top:60px;padding-left:12px;padding-right:12px}
  .mobile-header{display:flex}
  .stats-row{grid-template-columns:1fr 1fr}
  .grid-2{grid-template-columns:1fr}
  .inbounds-toolbar{flex-direction:column;align-items:stretch}
  .search-box{min-width:unset}
  .filter-chips{justify-content:center}
  .table-wrap{display:none}
  .inbound-cards{display:flex}
}
@media(max-width:480px){.stats-row{grid-template-columns:1fr}}
</style>
</head>
<body>

<div class="toast" id="toast"></div>

<div class="mobile-header">
  <span style="font-weight:700;font-size:13px">AMIR VPN</span>
  <button class="menu-toggle" onclick="document.getElementById('sidebar').classList.toggle('open');document.getElementById('sidebar-overlay').classList.toggle('show')">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
  </button>
</div>
<div class="sidebar-overlay" id="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('show')"></div>

<aside class="sidebar" id="sidebar">
  <div class="sidebar-brand">
    <div class="sidebar-brand-left">
      <svg width="28" height="28" viewBox="0 0 120 120" fill="none">
        <rect width="120" height="120" rx="28" fill="url(#lg)"/>
        <text x="60" y="68" text-anchor="middle" font-family="Inter, sans-serif" font-size="42" font-weight="800" fill="#fff" opacity="0.95">A</text>
        <text x="62" y="70" text-anchor="middle" font-family="Inter, sans-serif" font-size="42" font-weight="800" fill="rgba(255,255,255,0.2)">A</text>
        <defs><linearGradient id="lg" x1="0" y1="0" x2="120" y2="120"><stop stop-color="#ff1a1a"/><stop offset="1" stop-color="#dc2626"/></linearGradient></defs>
      </svg>
      <span class="brand-name">AMIR VPN</span>
    </div>
    <div class="sidebar-brand-right">
      <button onclick="toggleTheme()" id="theme-btn" title="Toggle theme">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
      </button>
    </div>
  </div>
  <nav class="sidebar-nav">
    <div class="nav-section">Main</div>
    <button class="nav-item active" data-page="dashboard">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
      <span data-en="Dashboard" data-fa="داشبورد">Dashboard</span>
    </button>
    <button class="nav-item" data-page="inbounds">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="8.5" cy="7" r="4"/><line x1="20" y1="8" x2="20" y2="14"/><line x1="23" y1="11" x2="17" y2="11"/></svg>
      <span data-en="Inbounds" data-fa="اینباندها">Inbounds</span>
      <span class="nav-badge" id="links-badge">0</span>
    </button>

    <button class="nav-item" data-page="domain">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>
      <span data-en="Domain" data-fa="دامنه">Domain</span>
    </button>
    <div class="nav-section">System</div>
    <button class="nav-item" data-page="security">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
      <span data-en="Security" data-fa="امنیت">Security</span>
    </button>
  </nav>
  <div class="sidebar-footer">
    <div class="theme-pick">
      <div class="theme-dot red sel" onclick="setTheme('dark')" title="Red Neon"></div>
      <div class="theme-dot green" onclick="setTheme('light')" title="Ghost Neon"></div>
      <div class="theme-dot purple" onclick="setTheme('purple')" title="Purple Neon"></div>
    </div>
    <div class="footer-row">
      <button class="footer-btn active" onclick="setLang('en')" id="lang-en">EN</button>
      <button class="footer-btn" onclick="setLang('fa')" id="lang-fa">FA</button>
    </div>
    <button class="logout-btn" onclick="fetch('/api/logout',{method:'POST'}).then(()=>location.href='/login')">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      <span data-en="Logout" data-fa="خروج">Logout</span>
    </button>
    <div class="version">AMIR VPN v1.0</div>
  </div>
</aside>

<main class="main">

  <section class="page active" id="page-dashboard">
    <div class="page-header">
      <div>
        <div class="page-title" data-en="Dashboard" data-fa="داشبورد">Dashboard</div>
        <div class="page-sub" id="last-update">Updated: --</div>
      </div>
      <div style="display:flex;gap:6px">
        <button class="btn btn-secondary" onclick="quickCreate(0.5,'GB')">+ 0.5 GB</button>
        <button class="btn btn-primary" onclick="quickCreate(1,'GB')">+ 1 GB</button>
      </div>
    </div>
    <div class="stats-row">
      <div class="stat-card">
        <div class="stat-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>
        </div>
        <div class="stat-label" data-en="Active Users" data-fa="کاربران فعال">Active Users</div>
        <div class="stat-value" id="s-traffic">--<span class="stat-unit"> MB</span></div>
      </div>
      <div class="stat-card">
        <div class="stat-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        </div>
        <div class="stat-label" data-en="Traffic" data-fa="ترافیک">Traffic</div>
        <div class="stat-value" id="s-links">--</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
        </div>
        <div class="stat-label" data-en="Uptime" data-fa="آپتایم">Uptime</div>
        <div class="stat-value" id="s-uptime" style="font-size:16px">--</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>
        </div>
        <div class="stat-label" data-en="Domain" data-fa="دامنه">Domain</div>
        <div class="stat-value" id="s-domain" style="font-size:11px;word-break:break-all;font-weight:500">--</div>
      </div>
    </div>
    <div class="grid-2">
      <div class="card">
        <div class="card-header"><div class="card-title">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/></svg>
          CPU Usage</div><span id="s-cpu-val" style="font-size:18px;font-weight:700;color:var(--primary)">--%</span></div>
        <div class="sys-bar"><div class="sys-bar-fill" id="s-cpu-bar" style="width:0%;background:var(--primary)"></div></div>
      </div>
      <div class="card">
        <div class="card-header"><div class="card-title">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2"><rect x="2" y="6" width="20" height="12" rx="2"/><line x1="6" y1="10" x2="6" y2="14"/><line x1="10" y1="10" x2="10" y2="14"/><line x1="14" y1="10" x2="14" y2="14"/><line x1="18" y1="10" x2="18" y2="14"/></svg>
          Memory</div><span id="s-mem-val" style="font-size:18px;font-weight:700;color:var(--green)">--%</span></div>
        <div class="sys-bar"><div class="sys-bar-fill" id="s-mem-bar" style="width:0%;background:var(--green)"></div></div>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><div class="card-title">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--text3)" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        Traffic Chart</div></div>
      <div style="height:180px"><canvas id="trafficChart"></canvas></div>
    </div>
  </section>

  <section class="page" id="page-inbounds">
    <div class="page-header">
      <div>
        <div class="page-title" data-en="Inbounds" data-fa="اینباندها">Inbounds</div>
        <div class="page-sub">VLESS over WebSocket</div>
      </div>
      <button class="btn btn-primary" onclick="showAddModal()">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
        Add
      </button>
    </div>
    <div class="inbounds-toolbar">
      <div class="search-box">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <input id="inbound-search" placeholder="Search by name or UUID..." oninput="filterInbounds()">
      </div>
      <div class="filter-chips">
        <button class="chip active" onclick="setFilter('all',this)">All</button>
        <button class="chip" onclick="setFilter('active',this)">Active</button>
        <button class="chip" onclick="setFilter('disabled',this)">Disabled</button>
      </div>
    </div>
    <div class="card" style="border-radius:12px;overflow:hidden;padding:0">
      <div class="table-wrap">
        <table class="table">
          <thead><tr>
            <th style="width:32px">ID</th>
            <th>Remark</th>
            <th style="width:56px">Type</th>
            <th>Traffic</th>
            <th style="width:80px">IPs</th>
            <th style="width:70px">Expiry</th>
            <th style="width:64px">Status</th>
            <th style="width:120px">Actions</th>
          </tr></thead>
          <tbody id="links-tbody"></tbody>
        </table>
      </div>
      <div class="inbound-cards" id="inbound-cards"></div>
      <div class="empty" id="links-empty" style="display:none">
        <div class="empty-icon">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.3"><circle cx="12" cy="12" r="10"/><path d="M8 12h8"/></svg>
        </div>
        <div>No inbounds found</div>
      </div>
    </div>
  </section>



  <section class="page" id="page-addresses">
    <div class="page-header">
      <div>
        <div class="page-title" data-en="Clean IP" data-fa="آی‌پی تمیز">Clean IP</div>
        <div class="page-sub" data-en="IPs and domains for subscription configs" data-fa="آی‌پی و دامنه‌ها برای کانفیگ‌های سابسکریپشن">IPs and domains for subscription configs</div>
      </div>
      <button class="btn btn-primary" onclick="showAddAddressModal()">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
        Add
      </button>
    </div>
    <div class="card">
      <div class="card-header"><div class="card-title" data-en="Clean IP List" data-fa="لیست آی‌پی تمیز">Clean IP List</div></div>
      <div class="status-item" style="flex-direction:column;gap:8px">
        <div style="display:flex;justify-content:space-between;width:100%">
          <span class="status-key" style="color:var(--text3);font-size:11px">Default: www.speedtest.net</span>
        </div>
        <div id="address-list" style="display:flex;flex-direction:column;gap:6px;width:100%"></div>
      </div>
    </div>
  </section>

  <section class="page" id="page-domain">
    <div class="page-header">
      <div>
        <div class="page-title" data-en="Domain" data-fa="دامنه">Domain</div>
        <div class="page-sub" data-en="Replace Render domain in configs with your custom domain" data-fa="جایگزینی دامنه رندر با دامنه اختصاصی در کانفیگ‌ها">Replace Render domain in configs with your custom domain</div>
      </div>
    </div>
    <div class="card" style="max-width:500px">
      <div class="card-header"><div class="card-title" data-en="Custom Domain" data-fa="دامنه اختصاصی">Custom Domain</div></div>
      <div id="domain-current" style="margin-bottom:16px">
        <div style="display:flex;align-items:center;justify-content:space-between;padding:12px;background:var(--surface2);border:1px solid var(--border);border-radius:10px">
          <div style="display:flex;align-items:center;gap:10px">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>
            <div>
              <div style="font-size:10px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.05em" data-en="Current Domain" data-fa="دامنه فعلی">Current Domain</div>
              <div id="domain-value" style="font-size:14px;font-weight:600;color:var(--text);margin-top:2px;font-family:monospace">--</div>
            </div>
          </div>
          <button class="btn btn-danger btn-sm" onclick="clearDomain()" style="display:none" id="domain-clear-btn" data-en="Clear" data-fa="پاک کردن">Clear</button>
        </div>
      </div>
      <div style="padding:12px;background:var(--surface2);border:1px solid var(--border);border-radius:10px;margin-bottom:12px">
        <div style="font-size:11px;font-weight:600;color:var(--text3);margin-bottom:8px;text-transform:uppercase;letter-spacing:0.04em" data-en="Render Default Domain" data-fa="دامنه پیش‌فرض رندر">Render Default Domain</div>
        <div id="render-domain" style="font-size:13px;color:var(--text2);font-family:monospace">--</div>
      </div>
      <div class="form-group">
        <label class="form-label" data-en="New Domain" data-fa="دامنه جدید">New Domain</label>
        <div style="display:flex;gap:8px">
          <input class="form-input" id="domain-input" placeholder="example.com" style="flex:1">
          <button class="btn btn-primary" onclick="saveDomain()" data-en="Save" data-fa="ذخیره">Save</button>
        </div>
      </div>
      <div style="margin-top:12px;padding:10px;background:var(--primary-dim);border:1px solid rgba(255,26,26,0.15);border-radius:8px">
        <div style="font-size:11px;color:var(--text2);line-height:1.6" data-en="Set a custom domain to replace the Render domain in all VLESS configs. Make sure your domain points to this service via CNAME or A record." data-fa="دامنه اختصاصی تنظیم کنید تا دامنه رندر در تمام کانفیگ‌های VLESS جایگزین شود. مطمئن شوید دامنه شما از طریق CNAME یا A record به این سرویس اشاره می‌کند.">Set a custom domain to replace the Render domain in all VLESS configs. Make sure your domain points to this service via CNAME or A record.</div>
      </div>
    </div>
  </section>

  <section class="page" id="page-security">
    <div class="page-header"><div><div class="page-title">Security</div><div class="page-sub">Change panel password</div></div></div>
    <div class="card" style="max-width:400px">
      <div class="form-group">
        <label class="form-label">Current Password</label>
        <input class="form-input" type="password" id="cur-pw" placeholder="Enter current password">
      </div>
      <div class="form-group">
        <label class="form-label">New Password</label>
        <input class="form-input" type="password" id="new-pw" placeholder="Min 4 characters">
      </div>
      <button class="btn btn-primary" onclick="changePassword()" style="margin-top:4px">Update Password</button>
    </div>
  </section>
</main>

<div class="modal-overlay" id="add-modal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal" style="position:relative">
    <button class="modal-close" onclick="$('#add-modal').classList.remove('show')">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    </button>
    <div class="modal-title">Add Inbound</div>
    <div class="form-group">
      <label class="form-label">Remark</label>
      <input class="form-input" id="new-label" placeholder="e.g. User 1">
    </div>
    <div class="form-row">
      <div class="form-group" style="flex:1">
        <label class="form-label">Traffic Limit</label>
        <input class="form-input" id="new-limit" type="number" min="0" step="0.1" placeholder="0 = Unlimited">
      </div>
      <div class="form-group" style="min-width:80px;max-width:100px">
        <label class="form-label">Unit</label>
        <select class="form-select" id="new-unit"><option value="GB">GB</option><option value="MB">MB</option></select>
      </div>
    </div>
    <div class="form-row">
      <div class="form-group" style="flex:1">
        <label class="form-label">Expiry (days)</label>
        <input class="form-input" id="new-expiry" type="number" min="0" step="1" placeholder="0 = No expiry">
      </div>
      <div class="form-group" style="flex:1">
        <label class="form-label">Max IPs</label>
        <input class="form-input" id="new-maxconn" type="number" min="0" step="1" placeholder="0 = Unlimited">
      </div>
    </div>
    <button class="btn btn-primary" onclick="createLink()" style="width:100%;margin-top:8px;justify-content:center">Create</button>
  </div>
</div>

<div class="modal-overlay" id="detail-modal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal" style="position:relative;max-width:540px">
    <button class="modal-close" onclick="$('#detail-modal').classList.remove('show')">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    </button>
    <div class="modal-title" id="detail-title">Inbound Details</div>
    <div id="detail-content"></div>
  </div>
</div>

<div class="modal-overlay" id="qr-modal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal" style="position:relative">
    <button class="modal-close" onclick="$('#qr-modal').classList.remove('show')">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    </button>
    <div class="modal-title">QR Code</div>
    <div class="qr-box"><img id="qr-img" src="" alt="QR"></div>
    <div style="margin-top:14px;text-align:center;display:flex;gap:8px;justify-content:center">
      <button class="btn btn-primary btn-sm" onclick="downloadQR()" style="padding:8px 20px">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        Download
      </button>
      <button class="btn btn-secondary btn-sm" onclick="$('#qr-modal').classList.remove('show')" style="padding:8px 20px">Close</button>
    </div>
  </div>
</div>

<div class="modal-overlay" id="edit-modal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal" style="position:relative">
    <button class="modal-close" onclick="$('#edit-modal').classList.remove('show')">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    </button>
    <div class="modal-title" id="edit-title">Edit Inbound</div>
    <input type="hidden" id="edit-uid">
    <div class="form-group">
      <label class="form-label">Name</label>
      <input class="form-input" id="edit-name" readonly style="opacity:0.6;cursor:not-allowed">
    </div>
    <div class="form-row">
      <div class="form-group" style="flex:1">
        <label class="form-label">Traffic Limit</label>
        <input class="form-input" id="edit-limit" type="number" min="0" step="0.1" placeholder="0 = Unlimited">
      </div>
      <div class="form-group" style="min-width:80px;max-width:100px">
        <label class="form-label">Unit</label>
        <select class="form-select" id="edit-unit"><option value="GB">GB</option><option value="MB">MB</option></select>
      </div>
    </div>
    <div class="form-row">
      <div class="form-group" style="flex:1">
        <label class="form-label">Expiry (days)</label>
        <input class="form-input" id="edit-expiry" type="number" min="0" step="1" placeholder="0 = No expiry">
      </div>
      <div class="form-group" style="flex:1">
        <label class="form-label">Max IPs</label>
        <input class="form-input" id="edit-maxconn" type="number" min="0" step="1" placeholder="0 = Unlimited">
      </div>
    </div>
    <div style="display:flex;gap:8px;margin-top:12px">
      <button class="btn btn-primary" onclick="saveEdit()" style="flex:1;justify-content:center">Save</button>
      <button class="btn btn-danger" onclick="resetEditTraffic()" style="justify-content:center">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 11-2.12-9.36L23 10"/></svg>
        Reset Traffic
      </button>
    </div>
  </div>
</div>

<div class="modal-overlay" id="add-address-modal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal" style="position:relative">
    <button class="modal-close" onclick="$('#add-address-modal').classList.remove('show')">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    </button>
    <div class="modal-title" data-en="Add Clean IP" data-fa="افزودن آی‌پی تمیز">Add Clean IP</div>
    <div class="form-group">
      <label class="form-label" data-en="IPs or Domains (one per line)" data-fa="آی‌پی یا دامنه (هر خط یکی)">IPs or Domains (one per line)</label>
      <textarea class="form-input" id="new-address" rows="5" placeholder="8.8.8.8&#10;example.com&#10;1.0.0.1" style="resize:vertical;font-family:monospace"></textarea>
    </div>
    <button class="btn btn-primary" onclick="addAddresses()" style="width:100%;margin-top:8px;justify-content:center" data-en="Add All" data-fa="افزودن همه">Add All</button>
  </div>
</div>

<canvas id="galaxy" style="position:fixed;inset:0;z-index:-1;pointer-events:none"></canvas>

<script>
let lang=localStorage.getItem('amir_lang')||'en';
let theme=localStorage.getItem('amir_theme')||'dark';
let allLinks=[];let currentFilter='all';let statsData={};let trafficChart=null;

function setLang(l){lang=l;document.getElementById('lang-en').classList.toggle('active',l==='en');document.getElementById('lang-fa').classList.toggle('active',l==='fa');document.body.dir=l==='fa'?'rtl':'ltr';document.querySelectorAll('[data-en]').forEach(el=>{const v=el.getAttribute('data-'+l);if(v)el.textContent=v});localStorage.setItem('amir_lang',l)}
function applyTheme(t){theme=t;document.documentElement.setAttribute('data-theme',t);localStorage.setItem('amir_theme',t);document.querySelectorAll('.theme-dot').forEach(d=>d.classList.remove('sel'));if(t==='dark')document.querySelector('.theme-dot.red').classList.add('sel');if(t==='light')document.querySelector('.theme-dot.green').classList.add('sel');if(t==='purple')document.querySelector('.theme-dot.purple').classList.add('sel');const btn=$('#theme-btn');if(btn)btn.innerHTML=t==='light'?'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg>':'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>';if(typeof trafficChart!=='undefined'&&trafficChart)updateChart()}
function toggleTheme(){applyTheme(theme==='dark'?'light':(theme==='light'?'purple':'dark'))}
function setTheme(t){applyTheme(t)}
function showAddModal(){$('#add-modal').classList.add('show')}
function setFilter(f,el){currentFilter=f;document.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));el.classList.add('active');filterInbounds()}
function filterInbounds(){const q=($('#inbound-search')?.value||'').toLowerCase();let filtered=allLinks;if(currentFilter==='active')filtered=filtered.filter(l=>l.active);if(currentFilter==='disabled')filtered=filtered.filter(l=>!l.active);if(q)filtered=filtered.filter(l=>l.label.toLowerCase().includes(q)||l.uuid.toLowerCase().includes(q));renderLinks(filtered)}
function fmtBytes(b){return b>1073741824?(b/1073741824).toFixed(2)+' GB':b>1048576?(b/1048576).toFixed(2)+' MB':(b/1024).toFixed(1)+' KB'}
function fmtLimit(b){if(b===0)return'Unlimited';const gb=b/1073741824;return(gb%1===0?gb.toFixed(0):gb.toFixed(1))+' GB'}
function fmtExpiry(exp){if(!exp)return'<span style="color:var(--text3)">Never</span>';const d=new Date(exp);const now=new Date();const diff=d-now;if(diff<=0)return'<span class="tag tag-expired">Expired</span>';const days=Math.ceil(diff/86400000);return days+'d left'}

const $=s=>document.querySelector(s);
const $$=s=>document.querySelectorAll(s);
$$('.nav-item').forEach(el=>el.addEventListener('click',()=>switchPage(el.dataset.page)));
function switchPage(id){$$('.page').forEach(p=>p.classList.remove('active'));$(`#page-${id}`)?.classList.add('active');$$('.nav-item').forEach(n=>n.classList.toggle('active',n.dataset.page===id));$('#sidebar').classList.remove('open');$('#sidebar-overlay').classList.remove('show')}
function toast(msg,err=false){const t=$('#toast');t.textContent=msg;t.className='toast'+(err?' error':'')+' show';setTimeout(()=>t.classList.remove('show'),3000)}
function esc(s){return s.replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;')}

async function loadStats(){
  try{
    const r=await fetch('/stats');if(!r.ok)throw new Error();statsData=await r.json();
    const pulse=(el,val)=>{if(el.textContent!==val){el.style.transition='color .2s';el.style.color='var(--primary)';el.textContent=val;setTimeout(()=>el.style.color='',400)}};
    pulse($('#s-traffic'),statsData.total_traffic_mb+' MB');$('#s-traffic').innerHTML=statsData.total_traffic_mb+'<span class="stat-unit"> MB</span>';
    pulse($('#s-links'),statsData.links_count);
    pulse($('#s-uptime'),statsData.uptime);
    pulse($('#s-domain'),statsData.domain);
    $('#links-badge').textContent=statsData.links_count;
    $('#last-update').textContent=(lang==='fa'?'Last update: ':'Updated: ')+new Date().toLocaleTimeString(lang==='fa'?'fa-IR':'en-US');
    if($('#t-traffic'))$('#t-traffic').textContent=statsData.total_traffic_mb+' MB';
    if($('#t-reqs'))$('#t-reqs').textContent=statsData.total_requests.toLocaleString();
    if($('#t-uptime'))$('#t-uptime').textContent=statsData.uptime;
    if(statsData.cpu_percent!==undefined){const c=statsData.cpu_percent;const cc=c>80?'var(--red)':c>50?'var(--yellow)':'var(--primary)';$('#s-cpu-val').textContent=c.toFixed(1)+'%';$('#s-cpu-val').style.color=cc;$('#s-cpu-bar').style.width=c+'%';$('#s-cpu-bar').style.background=cc}
    if(statsData.memory_percent!==undefined){const m=statsData.memory_percent;const mc=m>80?'var(--red)':m>50?'var(--yellow)':'var(--green)';$('#s-mem-val').textContent=m.toFixed(1)+'%';$('#s-mem-val').style.color=mc;$('#s-mem-bar').style.width=m+'%';$('#s-mem-bar').style.background=mc}
    updateChart();loadDomain();
  }catch(e){}
}

async function loadLinks(){try{const r=await fetch('/api/links');if(!r.ok)throw new Error();const d=await r.json();allLinks=d.links||[];filterInbounds();}catch(e){}}

function renderLinks(links){
  const tbody=$('#links-tbody');const empty=$('#links-empty');const cards=$('#inbound-cards');
  if(!links.length){tbody.innerHTML='';cards.innerHTML='';empty.style.display='block';return;}
  empty.style.display='none';
  let idx=links.length;
  const rows=links.map(l=>{
    const u=l.used_bytes,lim=l.limit_bytes;
    const uF=fmtBytes(u);const lF=fmtLimit(lim);
    const pct=lim>0?Math.min(100,(u/lim)*100):0;
    const col=pct>90?'var(--red)':pct>70?'var(--yellow)':'var(--primary)';
    const i=idx--;
    const expiryHtml=fmtExpiry(l.expiry);
    return {l,uF,lF,pct,col,i,maxConn:l.max_connections||0,curConn:l.current_connections||0,expiryHtml};
  });
  tbody.innerHTML=rows.map(r=>`<tr>
    <td style="color:var(--text3);font-size:11px">${r.i}</td>
    <td style="font-weight:600;font-size:13px">${esc(r.l.label)}</td>
    <td><span class="tag tag-vless">VLESS</span></td>
    <td><div class="usage-pill"><span class="used">${r.uF}</span><div class="bar"><div class="fill" style="width:${r.pct}%;background:${r.col}"></div></div><span class="limit">${r.lF}</span></div></td>
    <td style="font-size:12px;font-weight:600;color:${r.maxConn>0&&r.curConn>=r.maxConn?'var(--red)':'var(--text2)'}">${r.curConn}/${r.maxConn||'∞'}</td>
    <td style="font-size:11px">${r.expiryHtml}</td>
    <td><span class="tag ${r.l.active?'tag-active':'tag-disabled'}">${r.l.active?'On':'Off'}</span></td>
    <td><div style="display:flex;gap:3px;align-items:center">
      <button class="toggle ${r.l.active?'on':''}" data-uid="${r.l.uuid}" onclick="toggleLink(this)" title="Toggle"></button>
      <button class="btn btn-secondary btn-sm" onclick="showEditModal('${r.l.uuid}')" title="Edit" style="background:rgba(251,191,36,0.1);color:var(--yellow);border:1px solid rgba(251,191,36,0.2)">
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
      </button>
      <button class="btn-copy" onclick="copyLinkText('${esc(r.l.vless_link)}')" title="Copy">
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
      </button>
      <button class="btn-copy" onclick="copySubLink('${r.l.uuid}')" title="Copy Sub URL" style="background:var(--green-dim);color:var(--green);border:1px solid rgba(0,255,136,0.15)"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></svg></button>
      <button class="btn-copy" onclick="openSubPage('${r.l.uuid}')" title="Open Sub Page" style="background:rgba(99,102,241,0.1);color:#818cf8;border:1px solid rgba(99,102,241,0.2)"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg></button>
      <button class="btn-qr" onclick="showQRText('${esc(r.l.vless_link)}')" title="QR">qr</button>
      <button class="btn btn-danger btn-sm" onclick="deleteLink('${r.l.uuid}')" title="Delete">
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>
      </button>
    </div></td>
  </tr>`).join('');

  cards.innerHTML=rows.map(r=>`<div class="inbound-card">
    <div class="inbound-card-header">
      <div style="display:flex;align-items:center;gap:8px">
        <span class="inbound-card-id">#${r.i}</span>
        <span class="inbound-card-name">${esc(r.l.label)}</span>
        <span class="tag tag-vless">VLESS</span>
      </div>
      <button class="toggle ${r.l.active?'on':''}" data-uid="${r.l.uuid}" onclick="toggleLink(this)"></button>
    </div>
    <div class="usage-pill"><span class="used">${r.uF}</span><div class="bar"><div class="fill" style="width:${r.pct}%;background:${r.col}"></div></div><span class="limit">${r.lF}</span></div>
    <div style="display:flex;align-items:center;gap:6px;font-size:11px;color:var(--text2)"><span style="font-weight:600;color:${r.maxConn>0&&r.curConn>=r.maxConn?'var(--red)':'var(--text)'}">${r.curConn}/${r.maxConn||'∞'}</span> <span>IPs</span> ${r.expiryHtml}</div>
    <div class="inbound-card-actions">
      <button class="btn btn-secondary btn-sm" onclick="showEditModal('${r.l.uuid}')" style="background:rgba(251,191,36,0.1);color:var(--yellow);border:1px solid rgba(251,191,36,0.2)">e</button>
      <button class="btn-copy" onclick="copyAllConfigs('${r.l.uuid}')">c</button>
      <button class="btn-copy" onclick="copySubLink('${r.l.uuid}')" style="background:var(--green-dim);color:var(--green);border:1px solid rgba(0,255,136,0.15)"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></svg></button>
      <button class="btn-copy" onclick="openSubPage('${r.l.uuid}')" style="background:rgba(99,102,241,0.1);color:#818cf8;border:1px solid rgba(99,102,241,0.2)"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg></button>
      <button class="btn-qr" onclick="showQRText('${esc(r.l.vless_link)}')">qr</button>
      <button class="btn btn-danger btn-sm" onclick="deleteLink('${r.l.uuid}')">x</button>
    </div>
  </div>`).join('');
}

async function toggleLink(el){const uid=el.dataset.uid;const link=allLinks.find(l=>l.uuid===uid);if(!link)return;const newActive=!link.active;try{await fetch(`/api/links/${uid}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active:newActive})});link.active=newActive;filterInbounds();loadStats();}catch(e){}}
async function quickCreate(limit,unit){const names=['Ali','Sara','Reza','Nima','Mina','Arash','Yalda','Dariush','Cyrus','Shirin'];const name=names[Math.floor(Math.random()*names.length)]+'-'+Math.floor(Math.random()*100);try{const r=await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:name,limit_value:limit,limit_unit:unit})});if(!r.ok)throw new Error();toast('Created: '+name);await loadLinks();await loadStats();}catch(e){toast('Error',true)}}
async function createLink(){const label=$('#new-label').value.trim()||'New Link';const val=parseFloat($('#new-limit').value)||0;const unit=$('#new-unit').value||'GB';const maxconn=parseInt($('#new-maxconn').value)||0;const expiry=parseInt($('#new-expiry').value)||0;if(!/^[a-zA-Z0-9\\-_. ]+$/.test(label)){toast('Only English letters allowed',true);return;}try{const r=await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label,limit_value:val,limit_unit:unit,max_connections:maxconn,expiry_days:expiry})});if(!r.ok)throw new Error();toast('Created');$('#new-label').value='';$('#new-limit').value='';$('#new-maxconn').value='';$('#new-expiry').value='';$('#new-unit').value='GB';$('#add-modal').classList.remove('show');await loadLinks();await loadStats();}catch(e){toast('Error',true)}}
async function resetUsage(uid){try{await fetch(`/api/links/${uid}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({reset_usage:true})});toast('Reset');await loadLinks();}catch(e){}}
async function deleteLink(uid){if(!confirm('Delete this inbound?'))return;try{await fetch(`/api/links/${uid}`,{method:'DELETE'});toast('Deleted');await loadLinks();await loadStats();}catch(e){}}

function showEditModal(uid){const l=allLinks.find(x=>x.uuid===uid);if(!l)return;$('#edit-uid').value=uid;$('#edit-name').value=l.label;const gb=l.limit_bytes/1073741824;$('#edit-limit').value=l.limit_bytes>0?gb:'';$('#edit-unit').value='GB';$('#edit-maxconn').value=l.max_connections>0?l.max_connections:'';$('#edit-expiry').value='';$('#edit-title').textContent='Edit: '+l.label;$('#edit-modal').classList.add('show');}
async function saveEdit(){const uid=$('#edit-uid').value;const val=parseFloat($('#edit-limit').value)||0;const unit=$('#edit-unit').value;const maxconn=parseInt($('#edit-maxconn').value)||0;const expiry=parseInt($('#edit-expiry').value)||0;try{const body={limit_value:val,limit_unit:unit,max_connections:maxconn};if($('#edit-expiry').value!=='')body.expiry_days=expiry;const r=await fetch(`/api/links/${uid}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});if(!r.ok)throw new Error();toast('Updated');$('#edit-modal').classList.remove('show');await loadLinks();}catch(e){toast('Error',true)}}
async function resetEditTraffic(){const uid=$('#edit-uid').value;if(!confirm('Reset traffic usage to zero?'))return;try{const r=await fetch(`/api/links/${uid}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({reset_usage:true})});if(!r.ok)throw new Error();toast('Traffic reset');await loadLinks();}catch(e){toast('Error',true)}}

function showDetail(uid){const l=allLinks.find(x=>x.uuid===uid);if(!l)return;const u=l.used_bytes,lim=l.limit_bytes;const uF=fmtBytes(u);const lF=fmtLimit(lim);const pct=lim>0?Math.min(100,(u/lim)*100):0;const col=pct>90?'var(--red)':pct>70?'var(--yellow)':'var(--primary)';const created=l.created_at?new Date(l.created_at).toLocaleString(lang==='fa'?'fa-IR':'en-US'):'--';const expiryStr=l.expiry?new Date(l.expiry).toLocaleString(lang==='fa'?'fa-IR':'en-US'):'Never';$('#detail-title').textContent=l.label;$('#detail-content').innerHTML=`
    <div class="detail-row"><div class="detail-col"><div class="detail-label">Protocol</div><div class="detail-value" style="font-family:inherit"><span class="tag tag-vless">VLESS</span></div></div><div class="detail-col"><div class="detail-label">Status</div><div class="detail-value" style="font-family:inherit"><span class="tag ${l.active?'tag-active':'tag-disabled'}">${l.active?'Active':'Disabled'}</span></div></div></div>
    <div style="margin-bottom:12px"><div class="detail-label">UUID</div><div class="detail-value">${l.uuid}</div></div>
    <div class="detail-row"><div class="detail-col"><div class="detail-label">Used</div><div class="detail-value">${uF}</div></div><div class="detail-col"><div class="detail-label">Limit</div><div class="detail-value">${lF}</div></div><div class="detail-col"><div class="detail-label">Usage</div><div class="detail-value">${pct.toFixed(1)}%</div></div></div>
    <div class="sys-bar" style="margin-bottom:12px"><div class="sys-bar-fill" style="width:${pct}%;background:${col}"></div></div>
    <div class="detail-row"><div class="detail-col"><div class="detail-label">Connected IPs</div><div class="detail-value">${l.current_connections||0} / ${l.max_connections||'Unlimited'}</div></div><div class="detail-col"><div class="detail-label">Created</div><div class="detail-value" style="font-family:inherit">${created}</div></div></div>
    <div class="detail-row"><div class="detail-col"><div class="detail-label">Expiry</div><div class="detail-value" style="font-family:inherit">${expiryStr}</div></div></div>
    <div style="margin-bottom:0"><div class="detail-label">VLESS Link</div><div class="detail-value">${esc(l.vless_link)}</div></div>
    <div class="detail-actions">
      <button class="btn-copy" onclick="copyAllConfigs('${l.uuid}');$('#detail-modal').classList.remove('show')" style="padding:8px 18px;font-size:12px">Copy All</button>
      <button class="btn-qr" onclick="showQRText('${esc(l.vless_link)}');$('#detail-modal').classList.remove('show')" style="padding:8px 18px;font-size:12px">QR Code</button>
      <button class="btn btn-secondary btn-sm" onclick="copySubLink('${l.uuid}')" style="padding:8px 18px;font-size:12px">Copy Sub URL</button>
      <button class="btn btn-secondary btn-sm" onclick="openSubPage('${l.uuid}')" style="padding:8px 18px;font-size:12px;background:rgba(99,102,241,0.1);color:#818cf8;border:1px solid rgba(99,102,241,0.2)">Open Sub Page</button>
      <button class="btn btn-secondary btn-sm" onclick="resetUsage('${l.uuid}');$('#detail-modal').classList.remove('show')" style="padding:8px 18px">Reset Traffic</button>
    </div>`;
  $('#detail-modal').classList.add('show');
}

function copyLinkText(txt){navigator.clipboard.writeText(txt).then(()=>toast('Copied to clipboard')).catch(()=>toast('Failed to copy',true))}
function showQRText(txt){if(!txt)return;const box=document.querySelector('.qr-box');box.classList.remove('animate-in','animate-glow');$('#qr-img').src='https://api.qrserver.com/v1/create-qr-code/?size=300x300&data='+encodeURIComponent(txt);$('#qr-modal').classList.add('show');requestAnimationFrame(()=>{box.classList.add('animate-in');setTimeout(()=>box.classList.add('animate-glow'),500)})}
function downloadQR(){const img=$('#qr-img');if(!img.src)return;const a=document.createElement('a');a.href=img.src;a.download='amir-vpn-qr.png';a.click()}
async function copySubLink(uid){try{const domain=location.host;const subUrl=`https://${domain}/sub/${uid}`;await navigator.clipboard.writeText(subUrl);toast('Subscription page URL copied');}catch(e){toast('Failed to copy',true)}}function openSubPage(uid){const domain=location.host;window.open(`https://${domain}/sub/${uid}`,'_blank')}

async function changePassword(){const cur=$('#cur-pw').value;const nw=$('#new-pw').value;if(!cur||!nw){toast('Fill all fields',true);return;}try{const r=await fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:cur,new_password:nw})});if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'Error');}toast('Updated');$('#cur-pw').value='';$('#new-pw').value='';}catch(e){toast(e.message,true)}}

applyTheme(theme);setLang(lang);
loadStats();loadLinks();loadAddresses();loadDomain();
setInterval(()=>{loadStats()},10000);

let allAddresses=[];
async function loadAddresses(){try{const r=await fetch('/api/addresses');if(!r.ok)throw new Error();const d=await r.json();allAddresses=d.addresses||[];renderAddresses();}catch(e){}}

let currentDomain='';
async function loadDomain(){try{const r=await fetch('/api/domain');if(!r.ok)throw new Error();const d=await r.json();currentDomain=d.domain||'';const renderDomain=statsData.domain||location.host;$('#render-domain').textContent=renderDomain;if(currentDomain){$('#domain-value').textContent=currentDomain;$('#domain-value').style.color='var(--green)';$('#domain-clear-btn').style.display='block';}else{$('#domain-value').textContent=renderDomain+' (default)';$('#domain-value').style.color='var(--text2)';$('#domain-clear-btn').style.display='none';}}catch(e){}}
async function saveDomain(){const domain=$('#domain-input').value.trim();if(!domain){toast('Enter a domain',true);return;}try{const r=await fetch('/api/domain',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain})});if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'Error');}toast('Domain saved');$('#domain-input').value='';await loadDomain();await loadLinks();}catch(e){toast(e.message,true)}}
async function clearDomain(){try{await fetch('/api/domain',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain:''})});toast('Domain cleared');await loadDomain();await loadLinks();}catch(e){toast('Error',true)}}

function renderAddresses(){const list=$('#address-list');if(!list)return;if(!allAddresses.length){list.innerHTML='<div style="color:var(--text3);font-size:12px;padding:8px 0">No addresses added</div>';return;}list.innerHTML=allAddresses.map((a,i)=>`
    <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:8px">
      <div style="display:flex;align-items:center;gap:10px">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>
        <div>
          <div style="font-size:13px;font-weight:600;color:var(--text)">${esc(a)}</div>
          <div style="font-size:10px;color:var(--text3)">Address #${i+1}</div>
        </div>
      </div>
      <button class="btn btn-danger btn-sm" onclick="deleteAddress(${i})" style="padding:4px 10px">
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
  `).join('');}

function showAddAddressModal(){$('#new-address').value='';$('#add-address-modal').classList.add('show')}
async function addAddresses(){const text=$('#new-address').value.trim();if(!text){toast('Enter at least one IP or domain',true);return;}const lines=text.split('\n').map(l=>l.trim()).filter(l=>l);let added=0;let errors=0;for(const addr of lines){if(!/^[a-zA-Z0-9\\-_. ]+$/.test(addr)){errors++;continue;}try{const r=await fetch('/api/addresses',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({address:addr})});if(r.ok)added++;else errors++;}catch(e){errors++;}}if(added>0)toast(`Added ${added} address(es)`);if(errors>0)toast(`${errors} failed`,true);if(added>0){$('#add-address-modal').classList.remove('show');await loadAddresses();}}
async function deleteAddress(index){if(!confirm('Delete this address?'))return;try{const r=await fetch(`/api/addresses/${index}`,{method:'DELETE'});if(!r.ok)throw new Error();toast('Deleted');await loadAddresses();}catch(e){toast('Error',true)}}

let chartLabels=[];let chartData=[];
function getPrimaryColor(){const t=theme;if(t==='dark')return{bg:'rgba(255,26,26,0.7)',border:'#ff1a1a'};if(t==='light')return{bg:'rgba(0,255,136,0.7)',border:'#00ff88'};return{bg:'rgba(168,85,247,0.7)',border:'#a855f7'};}
function initChart(){const ctx=document.getElementById('trafficChart');if(!ctx)return;const c=getPrimaryColor();trafficChart=new Chart(ctx,{type:'bar',data:{labels:[],datasets:[{label:'MB',data:[],backgroundColor:c.bg,borderColor:c.border,borderWidth:1,borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{display:false},ticks:{color:'rgba(255,255,255,0.3)',font:{size:10}}},y:{grid:{color:'rgba(255,255,255,0.05)'},ticks:{color:'rgba(255,255,255,0.3)',font:{size:10},callback:v=>v+' MB'},beginAtZero:true}}}});}
initChart();
function updateChart(){if(!trafficChart||!statsData.hourly_traffic)return;const ht=statsData.hourly_traffic;const sorted=Object.entries(ht).sort((a,b)=>a[0].localeCompare(b[0])).slice(-12);const labels=sorted.map(e=>e[0]);const data=sorted.map(e=>Math.round(e[1]/1048576));trafficChart.data.labels=labels;trafficChart.data.datasets[0].data=data;const c=getPrimaryColor();trafficChart.data.datasets[0].backgroundColor=c.bg;trafficChart.data.datasets[0].borderColor=c.border;trafficChart.update();}

// Galaxy background
const canvas=document.getElementById('galaxy');
const gctx=canvas.getContext('2d');
let stars=[];
function resizeCanvas(){canvas.width=window.innerWidth;canvas.height=window.innerHeight}
function initStars(){stars=[];for(let i=0;i<150;i++)stars.push({x:Math.random()*canvas.width,y:Math.random()*canvas.height,r:Math.random()*1.2+0.3,speed:Math.random()*0.2+0.05,flicker:Math.random()*Math.PI*2})}
function drawGalaxy(){gctx.clearRect(0,0,canvas.width,canvas.height);const t=Date.now()*0.001;stars.forEach(s=>{const alpha=0.2+0.3*Math.sin(t*s.speed+s.flicker);gctx.beginPath();gctx.arc(s.x,s.y,s.r,0,Math.PI*2);gctx.fillStyle='rgba(255,255,255,'+alpha+')';gctx.fill()});requestAnimationFrame(drawGalaxy)}
resizeCanvas();initStars();drawGalaxy();window.addEventListener('resize',()=>{resizeCanvas();initStars()});
</script>
</body>
</html>"""


SUB_HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AMIR VPN - Subscription</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
html[data-theme="dark"]{--bg:#050508;--surface:rgba(20,20,20,0.85);--surface2:#1c1c1c;--surface3:#2a2a2a;--border:rgba(255,255,255,0.06);--text:rgba(255,255,255,0.92);--text2:rgba(255,255,255,0.5);--text3:rgba(255,255,255,0.25);--primary:#ff1a1a;--primary-glow:rgba(255,26,26,0.15);--primary-dim:rgba(255,26,26,0.08);--green:#00ff88;--green-dim:rgba(0,255,136,0.08);--red:#ef4444;--red-dim:rgba(239,68,68,0.08);--yellow:#fbbf24;--orb1:rgba(255,26,26,0.12);--orb2:rgba(139,0,0,0.1);--orb3:rgba(220,38,38,0.06)}
html[data-theme="light"]{--bg:#080c0a;--surface:rgba(10,30,20,0.85);--surface2:#0a1a10;--surface3:#152a1a;--border:rgba(0,255,136,0.06);--text:rgba(255,255,255,0.92);--text2:rgba(255,255,255,0.5);--text3:rgba(255,255,255,0.25);--primary:#00ff88;--primary-glow:rgba(0,255,136,0.15);--primary-dim:rgba(0,255,136,0.08);--green:#22c55e;--green-dim:rgba(34,197,94,0.08);--red:#ef4444;--red-dim:rgba(239,68,68,0.08);--yellow:#fbbf24;--orb1:rgba(0,255,136,0.12);--orb2:rgba(5,150,105,0.1);--orb3:rgba(34,197,94,0.06)}
html[data-theme="purple"]{--bg:#0a0610;--surface:rgba(40,10,60,0.85);--surface2:#1c0930;--surface3:#2a1040;--border:rgba(168,85,247,0.06);--text:rgba(255,255,255,0.92);--text2:rgba(255,255,255,0.5);--text3:rgba(255,255,255,0.25);--primary:#a855f7;--primary-glow:rgba(168,85,247,0.15);--primary-dim:rgba(168,85,247,0.08);--green:#22c55e;--green-dim:rgba(34,197,94,0.08);--red:#ef4444;--red-dim:rgba(239,68,68,0.08);--yellow:#fbbf24;--orb1:rgba(168,85,247,0.12);--orb2:rgba(109,40,217,0.1);--orb3:rgba(139,92,246,0.06)}
body{font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:20px}

.orb{position:fixed;border-radius:50%;filter:blur(80px);opacity:0.5;animation:orbFloat 20s ease-in-out infinite;pointer-events:none}
.orb-1{width:400px;height:400px;background:var(--orb1);top:-10%;left:-5%}
.orb-2{width:350px;height:350px;background:var(--orb2);bottom:-10%;right:-5%}
.orb-3{width:250px;height:250px;background:var(--orb3);top:40%;left:60%}
@keyframes orbFloat{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(-30px,50px) scale(0.9)}}

.theme-picker{position:fixed;top:20px;right:20px;z-index:10;background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:8px;display:flex;gap:4px;backdrop-filter:blur(20px)}
.theme-dot{width:20px;height:20px;border-radius:50%;cursor:pointer;border:2px solid transparent;transition:all .2s}
.theme-dot:hover{transform:scale(1.15)}
.theme-dot.sel{border-color:rgba(255,255,255,0.6)}
.theme-dot.red{background:#ff1a1a}
.theme-dot.green{background:#00ff88}
.theme-dot.purple{background:#a855f7}

.container{max-width:480px;width:100%;position:relative;z-index:1;margin-top:30px}
.header{text-align:center;margin-bottom:24px}
.header h1{font-size:24px;font-weight:800;letter-spacing:-0.02em;margin-bottom:4px}
.header p{font-size:13px;color:var(--text3)}

.glass-card{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:24px;margin-bottom:16px;backdrop-filter:blur(30px);position:relative;overflow:hidden}
.glass-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--primary),transparent);opacity:0.5}
.glass-card-title{font-size:13px;font-weight:700;color:var(--text2);margin-bottom:16px;display:flex;align-items:center;gap:8px;text-transform:uppercase;letter-spacing:0.04em}

/* Countdown */
.countdown{display:flex;gap:10px;justify-content:center}
.countdown-item{text-align:center;padding:12px 16px;background:var(--surface2);border:1px solid var(--border);border-radius:12px;min-width:65px}
.countdown-val{font-size:28px;font-weight:800;color:var(--primary);line-height:1}
.countdown-label{font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:0.05em;margin-top:4px}
.expiry-date{margin-top:12px;text-align:center;font-size:12px;color:var(--text2)}
.expiry-date span{color:var(--primary);font-weight:600}

/* Circular progress */
.progress-ring-wrap{display:flex;justify-content:center;margin-bottom:12px}
.progress-info{text-align:center}
.progress-info .usage-text{font-size:13px;color:var(--text2);margin-top:8px}
.progress-info .usage-text span{color:var(--text);font-weight:600}
.progress-info .used-val{font-size:20px;font-weight:700;color:var(--text)}
.progress-info .limit-val{font-size:12px;color:var(--text3)}

/* Connected users */
.connected-count{display:flex;align-items:center;justify-content:center;gap:10px;padding:16px;background:var(--surface2);border:1px solid var(--border);border-radius:12px}
.connected-count .num{font-size:28px;font-weight:800;color:var(--green)}
.connected-count .label{font-size:12px;color:var(--text3)}

/* Download links */
.app-list{display:flex;flex-direction:column;gap:8px}
.app-category{font-size:11px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.05em;margin-top:8px;margin-bottom:4px}
.app-item{display:flex;align-items:center;justify-content:space-between;padding:10px 14px;background:var(--surface2);border:1px solid var(--border);border-radius:10px;transition:all .2s;text-decoration:none;color:inherit}
.app-item:hover{border-color:var(--primary);transform:translateX(4px);box-shadow:0 2px 12px var(--primary-glow)}
.app-item-left{display:flex;align-items:center;gap:10px}
.app-item-icon{width:32px;height:32px;border-radius:8px;background:var(--primary-dim);display:flex;align-items:center;justify-content:center}
.app-item-name{font-size:13px;font-weight:600}
.app-item-desc{font-size:10px;color:var(--text3)}
.app-item-arrow{color:var(--text3);transition:color .2s}
.app-item:hover .app-item-arrow{color:var(--primary)}

.back-link{display:flex;align-items:center;justify-content:center;gap:6px;margin-top:16px;padding:10px;color:var(--text3);text-decoration:none;font-size:12px;font-weight:500;transition:color .2s}
.back-link:hover{color:var(--primary)}
</style>
</head>
<body>
<div class="orb orb-1"></div>
<div class="orb orb-2"></div>
<div class="orb orb-3"></div>

<div class="theme-picker">
  <div class="theme-dot red sel" onclick="setTheme('dark')" title="Red Neon"></div>
  <div class="theme-dot green" onclick="setTheme('light')" title="Ghost Neon"></div>
  <div class="theme-dot purple" onclick="setTheme('purple')" title="Purple Neon"></div>
</div>

<canvas id="galaxy" style="position:fixed;inset:0;z-index:0;pointer-events:none"></canvas>

<div class="container">
  <div class="header">
    <h1>AMIR VPN</h1>
    <p>Subscription Information</p>
  </div>

  <!-- Time Remaining -->
  <div class="glass-card">
    <div class="glass-card-title">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
      Time Remaining
    </div>
    <div class="countdown" id="countdown">
      <div class="countdown-item"><div class="countdown-val" id="cd-days">--</div><div class="countdown-label">Days</div></div>
      <div class="countdown-item"><div class="countdown-val" id="cd-hours">--</div><div class="countdown-label">Hours</div></div>
      <div class="countdown-item"><div class="countdown-val" id="cd-mins">--</div><div class="countdown-label">Mins</div></div>
      <div class="countdown-item"><div class="countdown-val" id="cd-secs">--</div><div class="countdown-label">Secs</div></div>
    </div>
    <div class="expiry-date">Expires: <span id="expiry-date-text">--</span></div>
  </div>

  <!-- Data Usage -->
  <div class="glass-card">
    <div class="glass-card-title">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
      Data Usage
    </div>
    <div style="display:flex;align-items:center;gap:20px">
      <div class="progress-ring-wrap">
        <svg width="120" height="120" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="50" fill="none" stroke="var(--surface3)" stroke-width="8"/>
          <circle id="progress-ring" cx="60" cy="60" r="50" fill="none" stroke="var(--primary)" stroke-width="8" stroke-linecap="round" stroke-dasharray="314" stroke-dashoffset="314" transform="rotate(-90 60 60)" style="transition:stroke-dashoffset 1s ease"/>
          <text x="60" y="56" text-anchor="middle" fill="var(--text)" font-size="18" font-weight="700" id="progress-pct">0%</text>
          <text x="60" y="72" text-anchor="middle" fill="var(--text3)" font-size="10">of limit</text>
        </svg>
      </div>
      <div class="progress-info">
        <div><span class="used-val" id="used-val">0 MB</span></div>
        <div><span class="limit-val" id="limit-val">/ Unlimited</span></div>
        <div class="usage-text" style="margin-top:8px">Status: <span id="status-text" style="color:var(--green)">Active</span></div>
      </div>
    </div>
  </div>

  <!-- Connected Users -->
  <div class="glass-card">
    <div class="glass-card-title">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>
      Connected Users
    </div>
    <div class="connected-count">
      <div class="num" id="conn-count">0</div>
      <div>
        <div class="label">Currently connected</div>
        <div style="font-size:10px;color:var(--text3)">Max: <span id="max-conn-text">Unlimited</span></div>
      </div>
    </div>
  </div>

  <!-- Client Downloads -->
  <div class="glass-card">
    <div class="glass-card-title">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
      Download Client
    </div>
    <div class="app-list">
      <div class="app-category">Android</div>
      <a class="app-item" href="https://github.com/2dust/v2rayNG/releases" target="_blank" rel="noopener">
        <div class="app-item-left">
          <div class="app-item-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><path d="M5 16V8a7 7 0 0114 0v8"/><rect x="1" y="16" width="22" height="4" rx="2"/></svg>
          </div>
          <div><div class="app-item-name">V2rayNG</div><div class="app-item-desc">Android VPN Client</div></div>
        </div>
        <svg class="app-item-arrow" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
      </a>
      <a class="app-item" href="https://github.com/MatsuriDayo/NekoBoxForAndroid/releases" target="_blank" rel="noopener">
        <div class="app-item-left">
          <div class="app-item-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/></svg>
          </div>
          <div><div class="app-item-name">NekoBox</div><div class="app-item-desc">Android VPN Client</div></div>
        </div>
        <svg class="app-item-arrow" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
      </a>
      <div class="app-category">iOS</div>
      <a class="app-item" href="https://apps.apple.com/app/streisand/id6450534064" target="_blank" rel="noopener">
        <div class="app-item-left">
          <div class="app-item-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/></svg>
          </div>
          <div><div class="app-item-name">Streisand</div><div class="app-item-desc">iOS VPN Client</div></div>
        </div>
        <svg class="app-item-arrow" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
      </a>
      <a class="app-item" href="https://apps.apple.com/app/shadowrocket/id932747118" target="_blank" rel="noopener">
        <div class="app-item-left">
          <div class="app-item-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
          </div>
          <div><div class="app-item-name">Shadowrocket</div><div class="app-item-desc">iOS VPN Client</div></div>
        </div>
        <svg class="app-item-arrow" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
      </a>
      <a class="app-item" href="https://apps.apple.com/app/v2box-v2ray-client/id6512947054" target="_blank" rel="noopener">
        <div class="app-item-left">
          <div class="app-item-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
          </div>
          <div><div class="app-item-name">V2Box</div><div class="app-item-desc">iOS VPN Client</div></div>
        </div>
        <svg class="app-item-arrow" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
      </a>
    </div>
  </div>

  <a href="javascript:history.back()" class="back-link">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>
    Back to panel
  </a>
</div>

<script>
const theme = localStorage.getItem('amir_theme') || 'dark';
function setTheme(t) {document.documentElement.setAttribute('data-theme', t);localStorage.setItem('amir_theme', t);document.querySelectorAll('.theme-dot').forEach(d => d.classList.remove('sel'));if(t==='dark')document.querySelector('.red').classList.add('sel');if(t==='light')document.querySelector('.green').classList.add('sel');if(t==='purple')document.querySelector('.purple').classList.add('sel')}
setTheme(theme);

let subData = null;
async function loadSub() {
  const pathParts = location.pathname.split('/');
  const subUid = pathParts[pathParts.length - 1];
  try {
    const r = await fetch(`/api/links/${subUid}/sub`);
    if (!r.ok) throw new Error();
    subData = await r.json();
    renderSub();
    startCountdown();
  } catch(e) {
    document.querySelector('.container').innerHTML = '<div class="glass-card" style="text-align:center"><p style="color:var(--red)">Unable to load subscription data</p></div>';
  }
}

function fmtBytes(b) {return b > 1073741824 ? (b/1073741824).toFixed(2)+' GB' : b > 1048576 ? (b/1048576).toFixed(2)+' MB' : (b/1024).toFixed(1)+' KB'}

function renderSub() {
  if (!subData) return;
  document.getElementById('used-val').textContent = fmtBytes(subData.used_bytes);
  if (subData.limit_bytes > 0) {
    document.getElementById('limit-val').textContent = '/ ' + fmtBytes(subData.limit_bytes);
    document.getElementById('progress-pct').textContent = subData.usage_percent + '%';
    const circumference = 314;
    const offset = circumference - (subData.usage_percent / 100) * circumference;
    document.getElementById('progress-ring').setAttribute('stroke-dashoffset', offset);
  } else {
    document.getElementById('limit-val').textContent = '/ Unlimited';
    document.getElementById('progress-pct').textContent = '∞';
    document.getElementById('progress-ring').setAttribute('stroke-dashoffset', 0);
    document.getElementById('progress-ring').setAttribute('stroke', 'var(--green)');
  }
  document.getElementById('status-text').textContent = subData.active ? 'Active' : 'Disabled';
  document.getElementById('status-text').style.color = subData.active ? 'var(--green)' : 'var(--red)';
}

let expiryTimestamp = null;
function startCountdown() {
  const expiryStr = subData && subData.expiry;
  if (!expiryStr) {
    document.getElementById('expiry-date-text').textContent = 'Never';
    return;
  }
  expiryTimestamp = new Date(expiryStr).getTime();
  document.getElementById('expiry-date-text').textContent = new Date(expiryStr).toLocaleDateString();
  updateCountdown();
  setInterval(updateCountdown, 1000);
}

function updateCountdown() {
  if (!expiryTimestamp) return;
  const now = Date.now();
  const diff = expiryTimestamp - now;
  if (diff <= 0) {
    document.getElementById('cd-days').textContent = '0';
    document.getElementById('cd-hours').textContent = '0';
    document.getElementById('cd-mins').textContent = '0';
    document.getElementById('cd-secs').textContent = '0';
    document.getElementById('expiry-date-text').innerHTML = '<span style="color:var(--red)">Expired</span>';
    return;
  }
  const days = Math.floor(diff / 86400000);
  const hours = Math.floor((diff % 86400000) / 3600000);
  const mins = Math.floor((diff % 3600000) / 60000);
  const secs = Math.floor((diff % 60000) / 1000);
  document.getElementById('cd-days').textContent = days;
  document.getElementById('cd-hours').textContent = hours;
  document.getElementById('cd-mins').textContent = mins;
  document.getElementById('cd-secs').textContent = secs;
}

// Galaxy background
const canvas = document.getElementById('galaxy');
const gctx = canvas.getContext('2d');
let stars = [];
function resizeCanvas() {canvas.width = window.innerWidth;canvas.height = window.innerHeight}
function initStars() {stars = [];for(let i = 0; i < 120; i++) stars.push({x:Math.random()*canvas.width,y:Math.random()*canvas.height,r:Math.random()*1.2+0.3,speed:Math.random()*0.2+0.05,flicker:Math.random()*Math.PI*2})}
function drawGalaxy() {gctx.clearRect(0,0,canvas.width,canvas.height);const t=Date.now()*0.001;stars.forEach(s=>{const alpha=0.2+0.3*Math.sin(t*s.speed+s.flicker);gctx.beginPath();gctx.arc(s.x,s.y,s.r,0,Math.PI*2);gctx.fillStyle='rgba(255,255,255,'+alpha+')';gctx.fill()});requestAnimationFrame(drawGalaxy)}
resizeCanvas();initStars();drawGalaxy();window.addEventListener('resize',()=>{resizeCanvas();initStars()});

loadSub();
setInterval(() => {loadSub()}, 30000);
</script>
</body>
</html>"""


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if await is_valid_session(token):
        return RedirectResponse(url="/dashboard")
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        return RedirectResponse(url="/login")
    return HTMLResponse(content=DASHBOARD_HTML)

@app.get("/sub-page/{uid}", response_class=HTMLResponse)
async def sub_page(request: Request, uid: str):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="link not found")
    return HTMLResponse(content=SUB_HTML)

@app.get("/subscription-info/{uid}", response_class=HTMLResponse)
async def subscription_info_page(request: Request, uid: str):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="link not found")
    return HTMLResponse(content=SUB_HTML)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=CONFIG["port"])
