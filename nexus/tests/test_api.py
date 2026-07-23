"""Tests for the self-hosted Nexus API helpers."""

from fastapi.testclient import TestClient

from osint_toolkit.api import SlidingWindowLimiter, _sign_session, _verify_session, app


def test_signed_session_roundtrip_and_expiry():
    token = _sign_session("yanis", "test-secret", now=1_000)
    assert _verify_session(token, "test-secret", now=1_001) == "yanis"
    assert _verify_session(token, "wrong-secret", now=1_001) is None
    assert _verify_session(token, "test-secret", now=1_000 + 12 * 60 * 60) is None


def test_signed_session_rejects_tampering():
    token = _sign_session("yanis", "test-secret", now=1_000)
    payload, signature = token.split(".", 1)
    assert _verify_session(f"{payload}x.{signature}", "test-secret", now=1_001) is None


def test_sliding_window_limiter():
    limiter = SlidingWindowLimiter(limit=2, window=10)
    assert limiter.allow("client", now=0)
    assert limiter.allow("client", now=1)
    assert not limiter.allow("client", now=2)
    assert limiter.allow("client", now=11)


def test_health_and_authenticated_session(monkeypatch):
    monkeypatch.setenv("NEXUS_ADMIN_USER", "admin")
    monkeypatch.setenv("NEXUS_ADMIN_PASSWORD", "long-test-password")
    monkeypatch.setenv("NEXUS_SESSION_SECRET", "test-secret-for-signed-cookies")

    with TestClient(app, base_url="https://testserver") as client:
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/auth/session").status_code == 401

        bad = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "wrong-password"},
        )
        assert bad.status_code == 401

        login = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "long-test-password"},
        )
        assert login.status_code == 200
        assert login.json() == {"user": "admin"}
        assert client.get("/api/auth/session").json() == {"user": "admin"}
        assert "discord" in client.get("/api/modules").json()["osint"]
