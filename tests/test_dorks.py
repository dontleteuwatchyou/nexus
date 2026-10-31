"""Dork generator tests (offline, deterministic)."""
import asyncio

from osint_toolkit.modules import dorks


def _run(t, **kw):
    return asyncio.run(dorks.scan(t, **kw))


def test_detect_kind():
    assert dorks.detect_kind("a@b.com") == "email"
    assert dorks.detect_kind("example.com") == "domain"
    assert dorks.detect_kind("https://example.com/x") == "domain"
    assert dorks.detect_kind("John Doe") == "name"
    assert dorks.detect_kind("torvalds") == "username"


def test_domain_dorks_cover_key_groups():
    r = _run("example.com")
    groups = {f.source for f in r.findings}
    for g in ("Documents", "Login / admin", "Directory listing",
              "Config / secrets", "Off-site leaks", "Subdomains"):
        assert g in groups, g
    # every dork is a google/bing/ddg URL, nothing hits the target
    for f in r.findings:
        if f.url:
            assert any(se in f.url for se in ("google.com", "bing.com", "duckduckgo.com"))


def test_domain_dork_uses_site_operator():
    r = _run("example.com")
    assert any("site%3Aexample.com" in (f.url or "") for f in r.findings)


def test_email_dorks():
    r = _run("john@acme.com")
    assert r.raw["kind"] == "email"
    assert any("Paste sites" == f.source for f in r.findings)


def test_url_normalised_to_domain():
    r = _run("https://sub.example.com/path?x=1")
    assert r.raw["kind"] in ("domain", "url")
    assert any("sub.example.com" in (f.url or "") for f in r.findings)
