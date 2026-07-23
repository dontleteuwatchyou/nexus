"""Tests for target-type detection and module-catalogue wiring.

These guard against the classic regression where a new module is written
but never registered in the dispatch tables.
"""

from osint_toolkit import correlate as C


def test_detect_target_type():
    assert C.detect_target_type("test@example.com") == "email"
    assert C.detect_target_type("8.8.8.8") == "ip"
    assert C.detect_target_type("https://example.com") == "url"
    assert C.detect_target_type("example.com") == "domain"
    assert C.detect_target_type("johndoe") == "username"


def test_new_pentest_modules_registered():
    for name in ("headers", "dns-sec", "graphql"):
        assert name in C.PENTEST_MODULES, f"{name} missing from PENTEST_MODULES"
        assert callable(C.PENTEST_MODULES[name])


def test_pentest_modules_have_target_types():
    # Every dispatchable pentest module must declare which target types it
    # accepts, otherwise --fullscan silently skips it.
    for name in C.PENTEST_MODULES:
        assert name in C.PENTEST_TARGET_TYPES, f"{name} missing target-type mapping"
        assert C.PENTEST_TARGET_TYPES[name], f"{name} has an empty target-type set"


def test_list_modules_shape():
    mods = C.list_modules()
    assert {"osint", "pentest", "external"} <= set(mods)
    assert "graphql" in mods["pentest"]
