"""Authenticated HTTP API for the self-hosted Nexus Web Lab."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from collections import defaultdict, deque
from typing import Annotated

from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .correlate import OSINT_MODULES, detect_target_type, scan_one

SESSION_COOKIE = "nexus_session"
SESSION_TTL = 12 * 60 * 60
ALLOWED_MODULES = {
    "email",
    "username",
    "domain",
    "ip",
    "phone",
    "social",
    "breach",
    "github",
    "image",
    "crypto",
    "discord",
}


def _required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} must be configured")
    return value


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _sign_session(user: str, secret: str, now: int | None = None) -> str:
    issued_at = int(time.time() if now is None else now)
    payload = _b64encode(
        json.dumps(
            {"sub": user, "iat": issued_at, "exp": issued_at + SESSION_TTL},
            separators=(",", ":"),
        ).encode()
    )
    signature = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest()
    return f"{payload}.{_b64encode(signature)}"


def _verify_session(token: str, secret: str, now: int | None = None) -> str | None:
    try:
        payload, supplied_signature = token.split(".", 1)
        expected = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64decode(supplied_signature), expected):
            return None
        data = json.loads(_b64decode(payload))
        current = int(time.time() if now is None else now)
        if current >= int(data["exp"]) or int(data["iat"]) > current + 30:
            return None
        user = data["sub"]
        return user if isinstance(user, str) and user else None
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


class SlidingWindowLimiter:
    """Small in-memory limiter suitable for a single self-hosted process."""

    def __init__(self, limit: int, window: float) -> None:
        self.limit = limit
        self.window = window
        self.events: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, now: float | None = None) -> bool:
        timestamp = time.monotonic() if now is None else now
        bucket = self.events[key]
        while bucket and bucket[0] <= timestamp - self.window:
            bucket.popleft()
        if len(bucket) >= self.limit:
            return False
        bucket.append(timestamp)
        return True


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=8, max_length=256)


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=500)
    module: str = Field(default="auto", min_length=1, max_length=40)
    timeout: float = Field(default=20.0, ge=2.0, le=60.0)


app = FastAPI(
    title="Nexus API",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
login_limiter = SlidingWindowLimiter(limit=8, window=60)
scan_limiter = SlidingWindowLimiter(limit=30, window=60)


def _client_key(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    return forwarded.split(",", 1)[0].strip() or (
        request.client.host if request.client else "unknown"
    )


def _authenticated_user(
    nexus_session: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
) -> str:
    secret = _required_env("NEXUS_SESSION_SECRET")
    user = _verify_session(nexus_session or "", secret)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.exception_handler(RuntimeError)
async def configuration_error(_request: Request, exc: RuntimeError):
    return JSONResponse(status_code=503, content={"detail": str(exc)})


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok", "service": "nexus-api"}


@app.post("/api/auth/login")
async def login(payload: LoginRequest, request: Request, response: Response) -> dict:
    key = _client_key(request)
    if not login_limiter.allow(key):
        raise HTTPException(status_code=429, detail="Too many login attempts")

    configured_user = _required_env("NEXUS_ADMIN_USER")
    configured_password = _required_env("NEXUS_ADMIN_PASSWORD")
    user_ok = hmac.compare_digest(payload.username, configured_user)
    password_ok = hmac.compare_digest(payload.password, configured_password)
    if not (user_ok and password_ok):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = _sign_session(configured_user, _required_env("NEXUS_SESSION_SECRET"))
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_TTL,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )
    return {"user": configured_user}


@app.post("/api/auth/logout")
async def logout(response: Response) -> dict:
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, samesite="strict")
    return {"ok": True}


@app.get("/api/auth/session")
async def session(user: Annotated[str, Depends(_authenticated_user)]) -> dict:
    return {"user": user}


@app.get("/api/modules")
async def modules(_user: Annotated[str, Depends(_authenticated_user)]) -> dict:
    return {"osint": sorted(ALLOWED_MODULES)}


@app.post("/api/osint/scan")
async def osint_scan(
    payload: ScanRequest,
    request: Request,
    _user: Annotated[str, Depends(_authenticated_user)],
) -> dict:
    if not scan_limiter.allow(_client_key(request)):
        raise HTTPException(status_code=429, detail="Scan rate limit exceeded")

    target = payload.target.strip()
    module = payload.module.lower()
    if module == "auto":
        module = detect_target_type(target)
    if module not in ALLOWED_MODULES or module not in OSINT_MODULES:
        raise HTTPException(status_code=400, detail="Unsupported web OSINT module")

    result = await scan_one(
        target,
        category="osint",
        module=module,
        timeout=payload.timeout,
    )
    return result.as_dict()
