"""Regression tests for dirs.py soft-404 / false-positive suppression.

The bug: soft-404 pages (HTTP 200 "page not found", catch-all redirects,
path-reflecting templates) were reported as discovered paths. These tests
mock three hostile-but-common server behaviours and assert that a known
real path survives while the soft-404 noise is dropped.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from osint_toolkit.pentest import dirs


def _found_paths(result) -> set[str]:
    return {f.label.lstrip("⚠ ").strip()
            for f in result.findings if f.source == "paths"}


# ── pure helpers ───────────────────────────────────────────────────

def _fp(status, body, loc=None):
    return dirs._Resp(status, len(body), dirs._tokens(body), loc)


def test_reflected_path_matches_baseline_short_body():
    # Two tiny soft-404 bodies differing only by the echoed path must be
    # treated as the same template despite a low Jaccard ratio.
    base = _fp(200, "<h1>The page /alpha was not located on this site</h1>")
    cand = _fp(200, "<h1>The page /bravo was not located on this site</h1>")
    assert dirs._matches_baseline(cand, [base])


def test_reflected_path_matches_baseline_large_body():
    tmpl = ("<html><nav>home shop about contact blog news careers press "
            "legal privacy terms help login signup cart search</nav>"
            "<main>We could not find the page {p}. Try the menu above.</main>"
            "</html>")
    base = _fp(200, tmpl.format(p="/alpha"))
    cand = _fp(200, tmpl.format(p="/bravo"))
    assert dirs._jaccard(base.tokens, cand.tokens) >= dirs._SIMILARITY
    assert dirs._matches_baseline(cand, [base])


def test_distinct_large_page_survives_baseline():
    base = _fp(200, "sorry this page does not exist here on our website")
    real = _fp(200, "<h1>Admin Panel</h1> username password login submit "
                    "dashboard settings users roles permissions audit logs")
    assert not dirs._matches_baseline(real, [base])


def test_tokens_strip_hashes_and_numbers():
    a = dirs._tokens("request id 9f3a2b7c8d1e4f5a0b built 1700000000")
    b = dirs._tokens("request id 0000111122223333aaaa built 1699999999")
    assert dirs._jaccard(a, b) == 1.0


# ── end-to-end against a mocked host ───────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_soft_404_as_200_is_suppressed():
    """Catch-all host: every unknown path returns 200 with a reflecting
    template. Only the genuinely different /admin/ page must be reported."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.rstrip("/") == "/admin":
            return httpx.Response(
                200, text="<html><body><h1>Admin Login</h1>"
                           "<form action='/auth'>password</form></body></html>")
        # Soft-404: 200, boilerplate template that echoes the requested path.
        return httpx.Response(
            200, text=f"<html><head><title>MySite</title></head><body>"
                      f"<nav>home shop contact about blog news</nav>"
                      f"<main>Sorry, we could not locate <code>{path}</code> "
                      f"here. Browse our catalogue instead.</main></body></html>")

    respx.get(url__regex=r"https://victim\.test/.*").mock(side_effect=handler)

    res = await dirs.scan("victim.test",
                          wordlist=["/admin/", "/backup/", "/config/", "/old/"],
                          timeout=3.0, concurrency=5)
    found = _found_paths(res)
    assert "/admin/" in found
    assert {"/backup/", "/config/", "/old/"}.isdisjoint(found)
    assert res.raw["catch_all"] is True


@pytest.mark.asyncio
@respx.mock
async def test_catch_all_redirect_is_suppressed():
    """Every unknown path 302s to /home; a real /dashboard 302s to /login."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.rstrip("/") == "/dashboard":
            return httpx.Response(302, headers={"location": "/login"})
        if path == "/":
            return httpx.Response(200, text="welcome home page content here")
        return httpx.Response(302, headers={"location": "/home"})

    respx.get(url__regex=r"https://victim\.test/.*").mock(side_effect=handler)

    res = await dirs.scan("victim.test",
                          wordlist=["/dashboard/", "/secret/", "/private/"],
                          timeout=3.0, concurrency=5)
    found = _found_paths(res)
    assert "/dashboard/" in found
    assert {"/secret/", "/private/"}.isdisjoint(found)


@pytest.mark.asyncio
@respx.mock
async def test_branded_404_text_suppressed_even_without_baseline_match():
    """A 200 body containing an explicit 404 phrase is dropped regardless."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, text="homepage root index landing")
        # Each page is textually unique (low Jaccard) but all say "404".
        return httpx.Response(
            200, text=f"<h1>Error 404</h1> unique words {path} "
                      + " ".join(f"w{i}" for i in range(50)))

    respx.get(url__regex=r"https://victim\.test/.*").mock(side_effect=handler)

    res = await dirs.scan("victim.test",
                          wordlist=["/a/", "/b/", "/c/"],
                          timeout=3.0, concurrency=5)
    assert _found_paths(res) == set()


@pytest.mark.asyncio
@respx.mock
async def test_real_sensitive_file_still_detected():
    """A hard-404 host (correct 404s) must still surface a real /.env."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/.env":
            return httpx.Response(
                200, text="DB_HOST=localhost\nDB_PASSWORD=s3cr3t\nAPI_KEY=abc")
        if path == "/":
            return httpx.Response(200, text="homepage root index landing page")
        return httpx.Response(404, text="Not Found")

    respx.get(url__regex=r"https://victim\.test/.*").mock(side_effect=handler)

    res = await dirs.scan("victim.test",
                          wordlist=["/.env", "/nope/", "/missing/"],
                          timeout=3.0, concurrency=5)
    found = _found_paths(res)
    assert "/.env" in found
    assert res.raw["catch_all"] is False


@pytest.mark.asyncio
@respx.mock
async def test_env_200_without_markers_rejected_on_catch_all():
    """On a catch-all host, /.env returning the generic template (no env
    markers) must NOT be reported as a secrets exposure."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        return httpx.Response(
            200, text=f"<html><nav>home shop about</nav>"
                      f"<main>page {path} not available</main></html>")

    respx.get(url__regex=r"https://victim\.test/.*").mock(side_effect=handler)

    res = await dirs.scan("victim.test",
                          wordlist=["/.env", "/admin/"],
                          timeout=3.0, concurrency=5)
    assert "/.env" not in _found_paths(res)
