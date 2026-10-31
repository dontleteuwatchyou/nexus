"""Tests for external-tool output parsers + cross-tool correlation."""

from osint_toolkit import report
from osint_toolkit.external.nmap import parse_nmap
from osint_toolkit.external.nuclei import parse_nuclei_jsonl
from osint_toolkit.models import ScanResult

NUCLEI_SAMPLE = "\n".join([
    '{"template-id":"CVE-2021-44228","info":{"name":"Log4j RCE","severity":"critical","description":"Remote code execution"},"matched-at":"https://t/api"}',
    '{"template-id":"tls-version","info":{"name":"TLS 1.0","severity":"low"},"matched-at":"t:443"}',
    '{"template-id":"tech-detect","info":{"name":"nginx","severity":"info"},"matched-at":"https://t"}',
    'not-json-garbage',
    '',
])


def test_parse_nuclei_canonical_severities():
    items = parse_nuclei_jsonl(NUCLEI_SAMPLE)
    assert len(items) == 3  # garbage + blank skipped
    sev = {i["name"]: i["severity"] for i in items}
    assert sev["Log4j RCE"] == "critical"
    assert sev["TLS 1.0"] == "low"
    assert sev["nginx"] == "info"


def test_parse_nuclei_unknown_severity_defaults_info():
    items = parse_nuclei_jsonl('{"info":{"name":"x","severity":"bogus"},"matched-at":"y"}')
    assert items[0]["severity"] == "info"


NMAP_SAMPLE = """
Starting Nmap
80/tcp  open  http    Apache httpd 2.4.41
443/tcp open  https   nginx
| http-vuln-cve2017-5638:
|   VULNERABLE:
|   Apache Struts RCE
|_  CVE-2017-5638
"""


def test_parse_nmap_ports_and_vulns():
    items = parse_nmap(NMAP_SAMPLE)
    ports = [i for i in items if i["kind"] == "port"]
    scripts = [i for i in items if i["kind"] == "script"]
    assert any("Port 80/tcp" in i["label"] for i in ports)
    assert all(i["severity"] == "info" for i in ports)
    # a "VULNERABLE" script line is promoted to high
    assert any(i["severity"] == "high" for i in scripts)


def test_nuclei_findings_reach_vuln_report():
    r = ScanResult(target="t", module="external:nuclei")
    for it in parse_nuclei_jsonl(NUCLEI_SAMPLE):
        r.add("nuclei", it["name"], it["matched"], it["severity"])
    rows = report.collect({"external:nuclei:t": r})
    sevs = {row["label"]: row["severity"] for row in rows}
    assert sevs.get("Log4j RCE") == "critical"   # critical reaches the report
    assert "nginx" not in sevs                    # info is not a vuln


def test_report_dedup_and_corroboration():
    a = ScanResult(target="t", module="external:nuclei")
    a.add("nuclei", "Open admin panel", "https://t/admin", "high")
    b = ScanResult(target="t", module="pentest:admin-finder")
    b.add("panels", "Open admin panel", "https://t/admin", "high")
    rows = report.collect({"external:nuclei:t": a, "pentest:admin-finder:t": b})
    assert len(rows) == 1                 # merged, not duplicated
    assert rows[0]["corroborated"] is True
    assert len(rows[0]["sources"]) == 2
