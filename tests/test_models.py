"""Tests for the ScanResult / Finding containers and timestamp format."""

import re

from osint_toolkit.models import Finding, ScanResult


def test_finding_as_dict_roundtrip():
    f = Finding(source="src", label="lbl", value="val", severity="warn",
                url="https://example.com")
    d = f.as_dict()
    assert d == {
        "source": "src", "label": "lbl", "value": "val",
        "severity": "warn", "url": "https://example.com",
    }


def test_scanresult_add_and_filters():
    r = ScanResult(target="example.com", module="headers")
    r.add("http", "Status", "200", "found")
    r.add("security-headers", "CSP", "missing", "warn")
    r.add("security-headers", "HSTS", "ok", "found")

    assert len(r.findings) == 3
    assert len(r.by_source("security-headers")) == 2
    assert len(r.by_severity("found")) == 2
    assert len(r.by_severity("warn")) == 1


def test_timestamp_is_iso_utc_with_z():
    r = ScanResult(target="t", module="m")
    # e.g. 2026-07-08T19:15:48Z — no offset, ends in Z, no deprecated utcnow
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", r.timestamp)


def test_as_dict_contains_all_fields():
    r = ScanResult(target="t", module="m")
    r.add("s", "l", "v")
    d = r.as_dict()
    assert set(d) == {"target", "module", "timestamp", "findings", "raw", "errors"}
    assert d["findings"][0]["label"] == "l"
