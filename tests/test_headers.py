"""Tests for the security-header audit pure logic (no network)."""

from osint_toolkit.pentest import headers as H


def test_normalize_adds_scheme():
    assert H._normalize("example.com").startswith("https://")
    assert H._normalize("http://example.com") == "http://example.com"


def test_grade_boundaries():
    assert H._grade(100) == "A"
    assert H._grade(90) == "A"
    assert H._grade(89) == "B"
    assert H._grade(75) == "B"
    assert H._grade(55) == "C"
    assert H._grade(35) == "D"
    assert H._grade(0) == "F"


def test_hsts_evaluator():
    ok, _, sev = H._eval_hsts("max-age=63072000; includeSubDomains; preload")
    assert ok and sev == "found"
    ok, _, sev = H._eval_hsts("max-age=100")
    assert ok and sev == "info"       # present but weak
    ok, _, sev = H._eval_hsts(None)
    assert not ok and sev == "warn"


def test_csp_evaluator_flags_unsafe():
    ok, note, sev = H._eval_csp("default-src 'self'")
    assert ok and sev == "found"
    ok, note, sev = H._eval_csp("script-src 'unsafe-inline' *")
    assert ok and sev == "info"
    assert "unsafe-inline" in note
    ok, _, sev = H._eval_csp(None)
    assert not ok and sev == "warn"


def test_xcto_requires_nosniff():
    ok, _, _ = H._eval_xcto("nosniff")
    assert ok
    ok, _, _ = H._eval_xcto("something-else")
    assert not ok
