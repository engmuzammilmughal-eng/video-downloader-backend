import os
import re
import socket
import ipaddress
from urllib.parse import urlparse, urljoin

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# ---------------- Settings ----------------
ALLOWED_EXT = {".mp4", ".webm", ".mov", ".mkv"}
MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500MB
TOKEN_MAX_AGE = 10 * 60                 # 10 minutes
SECRET = os.environ.get("APP_SECRET", "CHANGE_ME_TO_A_RANDOM_SECRET")
MAX_REDIRECTS = 5

serializer = URLSafeTimedSerializer(SECRET, salt="dl")

# ---------------- Helpers ----------------
def host_resolves_to_private_ip(hostname: str) -> bool:
    """SSRF protection: block private/loopback/link-local, etc."""
    try:
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if (
                ip.is_private or ip.is_loopback or ip.is_link_local or
                ip.is_reserved or ip.is_multicast
            ):
                return True
        return False
    except socket.gaierror:
        return True

def validate_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise HTTPException(400, "URL required")

    if len(url) > 2000:
        raise HTTPException(400, "URL too long")

    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        raise HTTPException(400, "Only http/https allowed")
    if not p.netloc:
        raise HTTPException(400, "Invalid URL")

    if not p.hostname or host_resolves_to_private_ip(p.hostname):
        raise HTTPException(400, "Host not allowed")

    path = (p.path or "").lower()
    if not any(path.endswith(ext) for ext in ALLOWED_EXT):
        raise HTTPException(400, "Only direct video file links allowed (.mp4/.webm/.mov/.mkv)")

    return url

def safe_filename_from_url(url: str) -> str:
    name = os.path.basename(urlparse(url).path) or "video.mp4"
    name = re.sub(r'[^A-Za-z0-9._-]+', '_', name)[:120]
    return name or "video.mp4"

async def head_or_range_probe(client: httpx.AsyncClient, url: str) -> httpx.Response:
    """Try HEAD, fallback to GET Range 0-0 for servers that don't support HEAD."""
    try:
        r = await client.request("HEAD", url, timeout=20.0)
        if r.status_code < 400 and ("content-type" in r.headers or "content-length" in r.headers):
            return r
    except httpx.HTTPError:
        pass

    try:
        r = await client.get(url, headers={"Range": "bytes=0-0"}, timeout=20.0)
        return r
    except httpx.HTTPError:
        raise HTTPException(400, "Could not reach URL")

async def resolve_redirects(url: str) -> str:
    """Follow redirects safely and validate each hop (prevents redirect-to-private SSRF)."""
    url = validate_url(url)

    async with httpx.AsyncClient(follow_redirects=False) as client:
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            r = await head_or_range_probe(client, current)

            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("location")
                if not loc:
                    raise HTTPException(400, "Redirect without location")
                next_url = urljoin(current, loc)
                current = validate_url(next_url)
                continue

            return current

    raise HTTPException(400, "Too many redirects")

# ---------------- App ----------------
app = FastAPI()

origins = [o.strip() for o in os.environ.get("CORS_ORIGINS", "*").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"ok": True, "message": "Backend is running. Open /docs"}

@app.post("/api/info")
async def api_info(payload: dict):
    raw_url = payload.get("url")
    final_url = await resolve_redirects(raw_url)

    async with httpx.AsyncClient(follow_redirects=False) as client:
        r = await head_or_range_probe(client, final_url)

    ctype = (r.headers.get("content-type") or "").lower()
    if not (ctype.startswith("video/") or "octet-stream" in ctype):
        raise HTTPException(400, f"Not a video content-type: {ctype or 'unknown'}")

    length = r.headers.get("content-length")
    size = int(length) if length and length.isdigit() else None
    if size and size > MAX_CONTENT_LENGTH:
        raise HTTPException(400, "File too large (max 500MB)")

    token = serializer.dumps({"url": final_url})
    return {
        "ok": True,
        "filename": safe_filename_from_url(final_url),
        "content_type": ctype or "application/octet-stream",
        "size": size,
        "download_path": f"/api/download?token={token}",
    }

@app.get("/api/download")
async def api_download(token: str, request: Request):
    try:
        data = serializer.loads(token, max_age=TOKEN_MAX_AGE)
    except SignatureExpired:
        raise HTTPException(400, "Link expired. Generate again.")
    except BadSignature:
        raise HTTPException(400, "Invalid token")

    final_url = await resolve_redirects(data.get("url"))
    filename = safe_filename_from_url(final_url)

    headers = {}
    if "range" in request.headers:
        headers["Range"] = request.headers["range"]

    async def stream():
        async with httpx.AsyncClient(timeout=None, follow_redirects=False) as client:
            async with client.stream("GET", final_url, headers=headers) as r:
                if r.status_code >= 400:
                    raise HTTPException(400, "Upstream download failed")
                async for chunk in r.aiter_bytes(chunk_size=1024 * 256):
                    yield chunk

    resp_headers = {
        "Content-Disposition": f'attachment; filename="{filename}"'
    }
    return StreamingResponse(stream(), media_type="application/octet-stream", headers=resp_headers)
