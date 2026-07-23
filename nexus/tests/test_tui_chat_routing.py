"""Chat routing must distinguish conversation from explicit tool actions."""

from osint_toolkit.tui import _should_run_scan


def test_domain_mentioned_in_conversation_does_not_force_scan():
    targets = [("github.com", "domain")]
    assert not _should_run_scan("Tu penses quoi de github.com ?", targets)


def test_explicit_scan_request_runs_tools():
    targets = [("github.com", "domain")]
    assert _should_run_scan("Analyse github.com", targets)


def test_bare_target_keeps_direct_scan_shortcut():
    targets = [("github.com", "domain")]
    assert _should_run_scan("github.com", targets)
