"""Domain OSINT — WHOIS, DNS, SSL, subdomains.

Sources (100% free, no API keys):
- crt.sh (Certificate Transparency)
- HackerTarget (DNS, hostsearch, reverseiplookup) — 100/day free
- AlienVault OTX (passive DNS) — anonymous free
- urlscan.io search — anonymous free
- Wayback Machine (subdomain extraction from snapshots)
- RapidDNS (subdomain enum)
- WHOIS via subprocess
- DNS via dig
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from ..http import get_json, get_text, session
from ..models import ScanResult

log = logging.getLogger("osint.domain")

DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


def is_valid(domain: str) -> bool:
    return bool(DOMAIN_RE.match(domain or ""))


def normalize(domain: str) -> str:
    """Strip protocol, www, paths, ports."""
    d = (domain or "").strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/", 1)[0]
    d = d.split(":", 1)[0]
    if d.startswith("www."):
        d = d[4:]
    return d


# ─── DNS ─────────────────────────────────────────────────────────

async def _dig(domain: str, rtype: str, timeout: float = 6.0) -> list[str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            "dig", "+short", rtype, domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return [l.strip() for l in stdout.decode().splitlines() if l.strip()]
    except Exception:
        return []


async def _dns_all(domain: str) -> dict[str, list[str]]:
    types = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA")
    results = await asyncio.gather(*[_dig(domain, t) for t in types])
    return {t: r for t, r in zip(types, results)}


# ─── WHOIS ───────────────────────────────────────────────────────

async def _whois(domain: str) -> dict | None:
    try:
        proc = await asyncio.create_subprocess_exec(
            "whois", domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        text = stdout.decode("utf-8", errors="ignore")
        info: dict[str, str] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("%", "#", ">>>", "<<<")):
                continue
            if ":" in line:
                k, _, v = line.partition(":")
                k, v = k.strip(), v.strip()
                if k and v and k not in info:
                    info[k] = v
        return info or None
    except Exception:
        return None


# ─── Certificate Transparency (crt.sh) ───────────────────────────

async def _crtsh(client: httpx.AsyncClient, domain: str) -> dict | None:
    """Pull all certs for *.domain — primary source for subdomain enum."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    j = await get_json(client, url, timeout=25)
    if not j or not isinstance(j, list):
        return None
    seen_subs = set()
    seen_issuers = set()
    cert_count = 0
    for c in j:
        cert_count += 1
        names = (c.get("name_value") or "").split("\n")
        for n in names:
            n = n.strip().lstrip("*.").lower()
            if n and (n == domain or n.endswith("." + domain)):
                seen_subs.add(n)
        issuer = c.get("issuer_name", "")
        if issuer:
            seen_issuers.add(issuer.split(",")[0])
    return {
        "certs":      cert_count,
        "subdomains": sorted(seen_subs),
        "issuers":    sorted(seen_issuers),
    }


# ─── CertSpotter (Certificate Transparency, free no-key) ─────────

async def _certspotter(client: httpx.AsyncClient, domain: str) -> set[str]:
    """SSLMate CertSpotter CT log — subdomain enum from issued certs."""
    url = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
           "&include_subdomains=true&expand=dns_names")
    j = await get_json(client, url, timeout=20)
    if not j or not isinstance(j, list):
        return set()
    subs: set[str] = set()
    for cert in j:
        for name in cert.get("dns_names") or []:
            n = name.strip().lstrip("*.").lower()
            if n and (n == domain or n.endswith("." + domain)):
                subs.add(n)
    return subs


# ─── HackerTarget (free 100/day) ─────────────────────────────────

async def _hackertarget(client: httpx.AsyncClient, domain: str) -> dict | None:
    out: dict = {}
    # hostsearch returns "host,ip" lines
    status, text = await get_text(
        client, f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15
    )
    if text and "error" not in text.lower() and "API count exceeded" not in text:
        hosts = []
        for line in text.splitlines():
            if "," in line:
                host, _, ip = line.partition(",")
                hosts.append({"host": host.strip(), "ip": ip.strip()})
        if hosts:
            out["hostsearch"] = hosts

    # dnslookup
    status, text = await get_text(
        client, f"https://api.hackertarget.com/dnslookup/?q={domain}", timeout=10
    )
    if text and "error" not in text.lower() and "API count exceeded" not in text:
        out["dns"] = [l.strip() for l in text.splitlines() if l.strip()]

    return out or None


# ─── AlienVault OTX ──────────────────────────────────────────────

async def _alienvault(client: httpx.AsyncClient, domain: str) -> dict | None:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    j = await get_json(client, url, timeout=15)
    if not j or not isinstance(j, dict):
        return None
    records = j.get("passive_dns") or []
    subs = set()
    ips  = set()
    for r in records:
        hostname = (r.get("hostname") or "").lower()
        if hostname and (hostname == domain or hostname.endswith("." + domain)):
            subs.add(hostname)
        if r.get("address"):
            ips.add(r["address"])
    return {
        "passive_dns_count": len(records),
        "subdomains": sorted(subs),
        "associated_ips": sorted(ips),
    }


# ─── urlscan.io (anonymous search) ───────────────────────────────

async def _urlscan(client: httpx.AsyncClient, domain: str) -> dict | None:
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=20"
    j = await get_json(client, url, timeout=15)
    if not j or not isinstance(j, dict):
        return None
    results = j.get("results") or []
    if not results:
        return None
    pages = []
    for r in results[:10]:
        page = r.get("page", {})
        pages.append({
            "url":     page.get("url"),
            "ip":      page.get("ip"),
            "country": page.get("country"),
            "server":  page.get("server"),
            "asn":     page.get("asn"),
            "scan":    r.get("result"),
        })
    return {"total": j.get("total"), "scans": pages}


# ─── Wayback Machine ─────────────────────────────────────────────

async def _wayback(client: httpx.AsyncClient, domain: str) -> dict | None:
    """Get earliest snapshot + count, and extract subdomains from CDX."""
    url = (
        f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
        "&output=json&fl=timestamp,original&collapse=urlkey&limit=500"
    )
    j = await get_json(client, url, timeout=20)
    if not j or not isinstance(j, list) or len(j) < 2:
        return None
    rows = j[1:]  # skip header
    subs = set()
    timestamps = []
    for ts, orig in rows:
        timestamps.append(ts)
        try:
            host = urlparse(orig).netloc.lower()
        except Exception:
            continue
        if host and (host == domain or host.endswith("." + domain)):
            subs.add(host)
    timestamps.sort()
    return {
        "snapshots":  len(rows),
        "first":      timestamps[0] if timestamps else None,
        "last":       timestamps[-1] if timestamps else None,
        "subdomains": sorted(subs),
    }


# ─── RapidDNS (subdomain enum) ───────────────────────────────────

async def _rapiddns(client: httpx.AsyncClient, domain: str) -> set[str]:
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    status, html = await get_text(client, url, timeout=15)
    if not html:
        return set()
    # Crude HTML scrape — pull all hostnames matching domain
    pattern = re.compile(rf"([a-zA-Z0-9_\-\.]+\.{re.escape(domain)})\b")
    return {m.group(1).lower() for m in pattern.finditer(html)}


# ─── Orchestrator ────────────────────────────────────────────────

async def scan(domain: str, timeout: float = 30.0) -> ScanResult:
    domain = normalize(domain)
    result = ScanResult(target=domain, module="domain")

    if not is_valid(domain):
        result.errors.append(f"Invalid domain: {domain}")
        return result

    # Local + remote in parallel
    async with session(timeout=timeout) as client:
        (whois_data, dns_data, crtsh, ht, av, us, wb, rapid, certsp) = await asyncio.gather(
            _whois(domain),
            _dns_all(domain),
            _crtsh(client, domain),
            _hackertarget(client, domain),
            _alienvault(client, domain),
            _urlscan(client, domain),
            _wayback(client, domain),
            _rapiddns(client, domain),
            _certspotter(client, domain),
            return_exceptions=True,
        )

    def safe(x):
        return x if not isinstance(x, Exception) else None

    whois_data, crtsh, ht, av, us, wb, rapid, certsp = map(
        safe, (whois_data, crtsh, ht, av, us, wb, rapid, certsp)
    )

    # DNS
    if dns_data:
        result.raw["dns"] = dns_data
        for rtype, records in dns_data.items():
            if records:
                result.add("dns", rtype, " · ".join(records[:5]),
                           "found" if rtype in ("A", "MX", "NS") else "info")

    # WHOIS — surface the key fields
    if whois_data:
        result.raw["whois"] = whois_data
        whois_keys = [
            ("Domain Name",            "Domain"),
            ("Registrar",              "Registrar"),
            ("Creation Date",          "Created"),
            ("Updated Date",           "Updated"),
            ("Registry Expiry Date",   "Expires"),
            ("Registrant Country",     "Country"),
            ("Registrant Organization","Registrant"),
            ("DNSSEC",                 "DNSSEC"),
        ]
        for whois_field, label in whois_keys:
            for k, v in whois_data.items():
                if k.lower() == whois_field.lower() and v:
                    result.add("whois", label, v[:120], "found")
                    break

    # Aggregate subdomains from all sources
    all_subs: set[str] = set()
    if crtsh:
        result.raw["crtsh"] = crtsh
        result.add("crt.sh", "Certificates issued", str(crtsh["certs"]), "info")
        result.add("crt.sh", "Subdomains via SSL", str(len(crtsh["subdomains"])), "found")
        all_subs.update(crtsh["subdomains"])
    if av:
        result.raw["alienvault"] = av
        result.add("alienvault", "Passive DNS records", str(av["passive_dns_count"]), "info")
        all_subs.update(av["subdomains"])
    if wb:
        result.raw["wayback"] = wb
        result.add("wayback", "Snapshots", str(wb["snapshots"]), "info")
        if wb["first"]:
            result.add("wayback", "Earliest snapshot", wb["first"][:8], "info")
        if wb["last"]:
            result.add("wayback", "Latest snapshot", wb["last"][:8], "info")
        all_subs.update(wb["subdomains"])
    if rapid:
        result.raw["rapiddns"] = sorted(rapid)
        all_subs.update(rapid)
    if ht:
        result.raw["hackertarget"] = ht
        if ht.get("hostsearch"):
            for h in ht["hostsearch"][:50]:
                all_subs.add(h["host"].lower())
    if certsp:
        result.raw["certspotter"] = sorted(certsp)
        result.add("certspotter", "Subdomains via CT", str(len(certsp)), "found")
        all_subs.update(certsp)

    if all_subs:
        # Always include the apex
        all_subs.discard(domain)
        result.raw["subdomains"] = sorted(all_subs)
        result.add("subdomains", "Total unique", str(len(all_subs)), "warn")
        for sub in sorted(all_subs)[:30]:
            result.add("subdomains", "Subdomain", sub, "warn", url=f"https://{sub}")

    # urlscan
    if us:
        result.raw["urlscan"] = us
        result.add("urlscan", "Public scans", str(us.get("total", 0)), "info")
        for scan_info in us["scans"][:5]:
            label = scan_info.get("url", "?")[:80]
            ip    = scan_info.get("ip", "?")
            country = scan_info.get("country", "?")
            result.add("urlscan", label, f"{ip} · {country}", "info",
                       url=scan_info.get("scan"))

    return result
