"""Hardening for the public deployment."""

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from ladon import security
from ladon.server import app


def make_request(headers, client=("10.0.0.1", 1234)):
    return Request({"type": "http", "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
                    "client": client})


def test_security_headers_on_every_page():
    client = TestClient(app)
    for path in ("/", "/lab", "/api/lab/status", "/static/lab.js"):
        r = client.get(path)
        assert r.status_code == 200
        csp = r.headers["content-security-policy"]
        assert "frame-ancestors 'none'" in csp and "object-src 'none'" in csp
        assert "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0]  # no inline scripts allowed
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["x-frame-options"] == "DENY"


def test_oversized_request_is_rejected():
    client = TestClient(app)
    r = client.post("/api/lab/run", content=b"x" * (security.MAX_BODY_BYTES + 1),
                    headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_spoofed_forwarded_for_is_ignored_behind_cloudflare(monkeypatch):
    monkeypatch.setattr(security, "TRUST_PROXY", "cloudflare")
    spoofed = make_request({"X-Forwarded-For": "1.2.3.4", "CF-Connecting-IP": "203.0.113.9"})
    assert security.client_ip(spoofed) == "203.0.113.9"
    no_cf = make_request({"X-Forwarded-For": "1.2.3.4"})
    assert security.client_ip(no_cf) == "10.0.0.1"  # falls back to the socket, never the forgeable header


def test_rate_limiter_blocks_after_limit():
    limiter = security.RateLimiter(limit=2, window=60)
    req = make_request({})
    limiter.check(req)
    limiter.check(req)
    with pytest.raises(HTTPException) as err:
        limiter.check(req)
    assert err.value.status_code == 429
