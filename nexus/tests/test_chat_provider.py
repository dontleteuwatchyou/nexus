"""Tests for actionable TUI chat provider diagnostics."""

from osint_toolkit.tui import _friendly_provider_error


def test_no_provider_error_is_actionable():
    message = _friendly_provider_error("Error: No provider available")

    assert message is not None
    assert "opencode auth login" in message
    assert "CHAT_MODEL" in message


def test_unrelated_provider_text_is_not_rewritten():
    assert _friendly_provider_error("Provider returned a useful answer") is None
