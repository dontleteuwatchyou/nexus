"""Tests for the entity graph (graph.py) and correlation engine (correlate)."""

from __future__ import annotations

import pytest

from osint_toolkit import correlate as C
from osint_toolkit.graph import EntityGraph, harvest, harvest_all
from osint_toolkit.models import ScanResult

# ── EntityGraph primitives ─────────────────────────────────────────

def test_dedup_and_corroboration():
    g = EntityGraph()
    g.add_entity("username", "Jax", source="email")
    g.add_entity("username", "jax", source="github")   # same node, different case
    assert len(g.by_kind("username")) == 1
    node = g.by_kind("username")[0]
    assert node.sources == {"email", "github"}
    assert node.corroborated
    assert node.confidence > 0.55


def test_edges_dedup_and_neighbors():
    g = EntityGraph()
    g.link("email", "a@b.com", "has_domain", "domain", "b.com", source="email")
    g.link("email", "a@b.com", "has_domain", "domain", "b.com", source="email")
    assert len(g.edges) == 1
    nb = g.neighbors(("email", "a@b.com"))
    assert ("has_domain", g.by_kind("domain")[0]) in [(r, n) for r, n in nb]


# ── harvest: one result -> entities + pivots ────────────────────────

def test_harvest_email_pivots_and_graph():
    r = ScanResult(target="alice@example.com", module="email")
    r.raw["gravatar"] = {
        "preferred_username": "alice_g",
        "name": "Alice Example",
        "verified_accounts": [{"shortname": "github", "url": "https://github.com/alice"}],
    }
    g = EntityGraph()
    pivots = harvest(g, r)
    assert ("domain", "example.com") in pivots
    assert ("username", "alice_g") in pivots
    assert g.by_kind("person")[0].value == "Alice Example"
    # verified account becomes a url node, not a scannable pivot
    assert any(n.value == "https://github.com/alice" for n in g.by_kind("url"))


def test_harvest_github_commit_emails_pivot():
    r = ScanResult(target="alice", module="github")
    r.raw["profile"] = {"name": "Alice", "twitter_username": "alice_tw"}
    r.raw["commit_emails"] = ["alice@corp.com", "99+alice@users.noreply.github.com"]
    g = EntityGraph()
    pivots = harvest(g, r)
    assert ("email", "alice@corp.com") in pivots
    assert ("username", "alice_tw") in pivots
    # noreply github addresses are never pivoted
    assert ("email", "99+alice@users.noreply.github.com") not in pivots


def test_harvest_domain_caps_subdomains_and_pivots_ip():
    r = ScanResult(target="example.com", module="domain")
    r.raw["dns"] = {"A": ["1.2.3.4", "5.6.7.8", "9.9.9.9"]}
    r.raw["subdomains"] = [f"s{i}.example.com" for i in range(50)]
    g = EntityGraph()
    pivots = harvest(g, r)
    ip_pivots = [p for p in pivots if p[0] == "ip"]
    assert ip_pivots == [("ip", "1.2.3.4"), ("ip", "5.6.7.8")]  # capped at 2
    assert len(g.by_kind("domain")) <= 26  # target + 25 subdomains


def test_harvest_all_builds_one_graph():
    r1 = ScanResult(target="a@b.com", module="email")
    r1.raw["gravatar"] = {"preferred_username": "bob"}
    r2 = ScanResult(target="bob", module="username")
    r2.raw["found"] = [{"name": "GitHub", "url": "https://github.com/bob"}]
    g = harvest_all([r1, r2])
    assert g.by_kind("username")[0].value in ("bob",)


# ── correlation engine (BFS, offline) ──────────────────────────────

def _fake_module(mod, builder):
    async def scan(value, *, timeout=30.0, **kw):
        res = ScanResult(target=value, module=mod)
        builder(res, value)
        return res
    return scan


@pytest.mark.asyncio
async def test_correlate_pivots_across_modules(monkeypatch):
    """email -> (username, domain); username -> github surfaces the seed email
    again, which must corroborate the email node."""

    def email_build(res, val):
        res.raw["gravatar"] = {"preferred_username": "alice_g"}

    def github_build(res, val):
        res.raw["profile"] = {"name": "Alice"}
        res.raw["commit_emails"] = ["alice@example.com"]  # back to the seed

    def username_build(res, val):
        res.raw["found"] = [{"name": "GitHub", "url": f"https://github.com/{val}"}]

    def domain_build(res, val):
        res.raw["dns"] = {"A": ["1.2.3.4"]}

    def noop(res, val):
        pass

    fakes = {
        "email": _fake_module("email", email_build),
        "username": _fake_module("username", username_build),
        "github": _fake_module("github", github_build),
        "social": _fake_module("social", noop),
        "domain": _fake_module("domain", domain_build),
        "ip": _fake_module("ip", noop),
        "web": _fake_module("web", noop),
        "phone": _fake_module("phone", noop),
        "crypto": _fake_module("crypto", noop),
    }
    monkeypatch.setattr(C, "OSINT_MODULES", fakes)

    corr = await C.correlate("alice@example.com", depth=3, timeout=5.0)

    # The seed email module + enrichment social ran, and the pivot username
    # was expanded with username+github+social.
    assert "email:alice@example.com" in corr.results
    assert "github:alice_g" in corr.results
    assert "domain:example.com" in corr.results

    # The email was asserted by the seed email scan AND re-surfaced by the
    # github commit email -> corroborated node in the graph.
    emails = {n.value.lower(): n for n in corr.graph.by_kind("email")}
    assert "alice@example.com" in emails
    assert emails["alice@example.com"].corroborated


@pytest.mark.asyncio
async def test_correlate_unknown_target(monkeypatch):
    corr = await C.correlate("???", depth=1)
    assert any(r.module == "unknown" for r in corr.results.values())
    assert corr.graph.summary() == {}


@pytest.mark.asyncio
async def test_correlate_module_exception_is_contained(monkeypatch):
    async def boom(value, *, timeout=30.0, **kw):
        raise RuntimeError("provider down")

    monkeypatch.setattr(C, "OSINT_MODULES", {
        "email": boom, "social": boom,
    })
    corr = await C.correlate("x@y.com", depth=1, timeout=2.0)
    r = corr.results["email:x@y.com"]
    assert r.errors and "provider down" in r.errors[0]


@pytest.mark.asyncio
async def test_scan_chained_backcompat(monkeypatch):
    monkeypatch.setattr(C, "OSINT_MODULES", {
        "email": _fake_module("email", lambda res, val: None),
        "social": _fake_module("social", lambda res, val: None),
    })
    out = await C.scan_chained("a@b.com", depth=1)
    assert isinstance(out, dict)
    assert "email:a@b.com" in out
