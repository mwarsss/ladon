"""Hardening for running Ladon on the public internet.

- client_ip(): the visitor's address. Behind Render, Cloudflare sets CF-Connecting-IP and
  overwrites any value a visitor sends; X-Forwarded-For is only appended to, so its first
  entry can be forged and is never trusted.
- RateLimiter: per-visitor sliding-window limits.
- SecurityMiddleware: security headers on every response and a cap on request body size.

PUBLIC=1 (LADON_PUBLIC) switches on the public-deployment behaviour used in server.py
and lab.py: no API docs, replay-only dashboard, limits on state-changing endpoints.
"""

from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict

from fastapi import HTTPException, Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

PUBLIC = os.environ.get("LADON_PUBLIC", "0") == "1"
# "cloudflare": trust CF-Connecting-IP (Render). "1": trust the first X-Forwarded-For entry
# (only behind a proxy you control that strips client-sent values). Anything else: socket address.
TRUST_PROXY = os.environ.get("TRUST_PROXY", "0").lower()
MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", str(64 * 1024)))

CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self'",
    # The dashboard keeps one small <style> block and a few inline style attributes.
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    "img-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])

HEADERS = [
    (b"content-security-policy", CSP.encode()),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), payment=()"),
    (b"cross-origin-opener-policy", b"same-origin"),
]


def client_ip(request: Request) -> str:
    if TRUST_PROXY == "cloudflare":
        ip = request.headers.get("cf-connecting-ip") or request.headers.get("true-client-ip")
        if ip:
            return ip.strip()
    elif TRUST_PROXY == "1":
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class RateLimiter:
    """At most `limit` calls per visitor per `window` seconds."""

    def __init__(self, limit: int, window: float = 3600.0):
        self.limit, self.window = limit, window
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, request: Request, what: str = "requests") -> None:
        now, key = time.time(), client_ip(request)
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                raise HTTPException(status_code=429, detail=f"Too many {what} from your connection. Try again later.")
            hits.append(now)
            if len(self._hits) > 10_000:  # forget idle visitors so memory stays bounded
                for k in [k for k, v in self._hits.items() if not v or now - v[-1] > self.window]:
                    del self._hits[k]

    def clear(self) -> None:
        with self._lock:
            self._hits.clear()


class SecurityMiddleware:
    """Adds security headers and rejects request bodies over MAX_BODY_BYTES."""

    def __init__(self, app: ASGIApp, public: bool = PUBLIC):
        self.app, self.public = app, public

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
            await _reject(send)
            return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > MAX_BODY_BYTES:
                    raise _BodyTooLarge()
            return message

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", [])) + HEADERS
                if self.public:
                    headers.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, limited_receive, send_with_headers)
        except _BodyTooLarge:
            await _reject(send)


class _BodyTooLarge(Exception):
    pass


async def _reject(send: Send) -> None:
    body = b'{"detail":"Request too large."}'
    await send({"type": "http.response.start", "status": 413,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())] + HEADERS})
    await send({"type": "http.response.body", "body": body})
