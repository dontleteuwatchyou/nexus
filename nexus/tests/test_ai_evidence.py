"""Regression tests for identity-safe scan summaries."""

from osint_toolkit.models import ScanResult
from osint_toolkit.tui import OsintApp


def test_username_evidence_is_never_presented_as_identity_attribution():
    social = ScanResult(target="yanis", module="social")
    social.add(
        "Major platforms",
        "Twitter / X",
        "https://x.com/yanis",
        "info",
    )
    username = ScanResult(target="yanis", module="username")
    username.add("Sherlock", "Account", "https://example.test/yanis", "found")
    breach = ScanResult(target="yanis", module="breach")
    breach.add("hudson_rock", "Infostealer infection", "3 computer(s)", "warn")

    results = {
        "osint:social:yanis": social,
        "osint:username:yanis": username,
        "osint:breach:yanis": breach,
    }
    context = OsintApp._scan_context(results)

    assert "Même pseudo != même identité" in context
    assert "existence/propriété non confirmées" in context
    assert "NON ATTRIBUÉ : occurrences de l'identifiant uniquement" in context
    assert "NON ATTRIBUÉ | hudson_rock" in context


def test_terminal_summary_labels_candidates_and_unattributed_breaches():
    social = ScanResult(target="yanis", module="social")
    social.add("Major platforms", "Twitter / X", "https://x.com/yanis")
    breach = ScanResult(target="yanis", module="breach")
    breach.add("leakcheck", "Breaches", "1000 entries", "warn")

    rendered = OsintApp._scan_to_chat(
        None,
        {
            "osint:social:yanis": social,
            "osint:breach:yanis": breach,
        },
    )

    assert "liens candidats · identité non vérifiée" in rendered
    assert "correspondances du pseudo · non attribuées" in rendered
    assert "résultats" not in rendered
    assert "◆" not in rendered
    assert "•" not in rendered
    assert "[bold" not in rendered
    assert "SOCIAL | yanis |" in rendered


def test_chat_render_removes_markdown_decoration_from_assistant_output():
    rendered = OsintApp._chat_render(
        None,
        [
            {
                "role": "assistant",
                "content": (
                    "**Fait** : compte `yanis@example.test`\n"
                    "### Action\n"
                    "[Profil](https://example.test/profile)"
                ),
            }
        ],
    )

    assert "**" not in rendered
    assert "`" not in rendered
    assert "###" not in rendered
    assert "Fait : compte yanis@example.test" in rendered
    assert "Profil: https://example.test/profile" in rendered
