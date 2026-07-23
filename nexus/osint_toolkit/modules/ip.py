"""IP OSINT — 100% free sources, no API keys.

Sources:
- ip-api.com (geolocation, ISP, AS, ZIP, lat/lon)
- ipwho.is (geolocation backup, currency, flag)
- Shodan InternetDB (open ports, hostnames, tags, vulns)
- GreyNoise community (threat classification, last seen)
- AlienVault OTX (reputation, pulses)
- Reverse DNS
- WHOIS via subprocess
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket

import httpx

from ..http import get_json, get_text, session
from ..models import ScanResult

log = logging.getLogger("osint.ip")


def is_valid(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# ─── Sources ──────────────────────────────────────────────────────

async def _ipapi(client: httpx.AsyncClient, ip: str) -> dict | None:
    """ip-api.com: 45 req/min anonymous."""
    j = await get_json(
        client, f"http://ip-api.com/json/{ip}?fields=66846719", timeout=10
    )
    if not j or not isinstance(j, dict) or j.get("status") != "success":
        return None
    return j


async def _ipwhois(client: httpx.AsyncClient, ip: str) -> dict | None:
    """ipwho.is: free unlimited."""
    j = await get_json(client, f"https://ipwho.is/{ip}", timeout=10)
    if not j or not isinstance(j, dict) or not j.get("success"):
        return None
    return j


async def _shodan_idb(client: httpx.AsyncClient, ip: str) -> dict | None:
    """Shodan InternetDB — free, no key. Open ports, hostnames, CVEs, tags."""
    j = await get_json(client, f"https://internetdb.shodan.io/{ip}", timeout=10)
    if not j or not isinstance(j, dict) or "ip" not in j:
        return None
    return {
        "hostnames": j.get("hostnames") or [],
        "ports":     j.get("ports") or [],
        "cpes":      j.get("cpes") or [],
        "vulns":     j.get("vulns") or [],
        "tags":      j.get("tags") or [],
    }


async def _greynoise(client: httpx.AsyncClient, ip: str) -> dict | None:
    """GreyNoise community API — free."""
    j = await get_json(
        client, f"https://api.greynoise.io/v3/community/{ip}", timeout=10
    )
    if not j or not isinstance(j, dict):
        return None
    if j.get("message") == "IP not observed scanning the internet or contained in RIOT data set.":
        return {"seen": False}
    return {
        "seen":           True,
        "classification": j.get("classification"),
        "name":           j.get("name"),
        "last_seen":      j.get("last_seen"),
        "noise":          j.get("noise"),
        "riot":           j.get("riot"),
        "link":           j.get("link"),
    }


async def _alienvault(client: httpx.AsyncClient, ip: str) -> dict | None:
    j = await get_json(
        client, f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
        timeout=15,
    )
    if not j or not isinstance(j, dict):
        return None
    return {
        "pulse_count": (j.get("pulse_info") or {}).get("count", 0),
        "reputation":  j.get("reputation"),
        "asn":         j.get("asn"),
        "country":     j.get("country_name"),
        "city":        j.get("city"),
    }


async def _stopforumspam(client: httpx.AsyncClient, ip: str) -> dict | None:
    """StopForumSpam — is this IP a known spam / abuse source? Free, no key."""
    j = await get_json(
        client, f"https://api.stopforumspam.org/api?ip={ip}&json", timeout=10
    )
    if not j or not isinstance(j, dict) or not j.get("success"):
        return None
    e = j.get("ip") or {}
    if not e.get("appears"):
        return {"listed": False}
    return {
        "listed":     True,
        "frequency":  e.get("frequency"),
        "confidence": e.get("confidence"),
        "last_seen":  e.get("lastseen"),
        "country":    e.get("delegated"),
    }


async def _reverse_dns(ip: str) -> str | None:
    try:
        host = await asyncio.get_event_loop().run_in_executor(
            None, socket.gethostbyaddr, ip
        )
        return host[0]
    except Exception:
        return None


async def _whois_ip(ip: str) -> dict | None:
    try:
        proc = await asyncio.create_subprocess_exec(
            "whois", ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=12)
        text = stdout.decode("utf-8", errors="ignore")
        info: dict[str, str] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("%", "#")):
                continue
            if ":" in line:
                k, _, v = line.partition(":")
                k, v = k.strip(), v.strip()
                if k and v and k not in info:
                    info[k] = v
        return info or None
    except Exception:
        return None


# ─── Orchestrator ─────────────────────────────────────────────────

async def scan(ip: str, timeout: float = 20.0) -> ScanResult:
    result = ScanResult(target=ip, module="ip")

    if not is_valid(ip):
        result.errors.append(f"Invalid IP address: {ip}")
        return result

    if is_private(ip):
        result.add("classification", "Type", "Private / RFC1918", "warn")
        result.errors.append("Private IP — most public sources will not respond")

    async with session(timeout=timeout) as client:
        ipapi, whois_, idb, gn, av, sfs, rdns, whois_data = await asyncio.gather(
            _ipapi(client, ip),
            _ipwhois(client, ip),
            _shodan_idb(client, ip),
            _greynoise(client, ip),
            _alienvault(client, ip),
            _stopforumspam(client, ip),
            _reverse_dns(ip),
            _whois_ip(ip),
            return_exceptions=True,
        )

    def safe(x):
        return x if not isinstance(x, Exception) else None
    ipapi, whois_, idb, gn, av, sfs, rdns, whois_data = map(
        safe, (ipapi, whois_, idb, gn, av, sfs, rdns, whois_data)
    )

    # Geo (prefer ip-api, fall back to ipwhois)
    if ipapi:
        result.raw["ipapi"] = ipapi
        for k, label, sev in (
            ("country",     "Country",       "found"),
            ("regionName",  "Region",        "info"),
            ("city",        "City",          "info"),
            ("zip",         "ZIP",           "info"),
            ("lat",         "Latitude",      "info"),
            ("lon",         "Longitude",     "info"),
            ("timezone",    "Timezone",      "info"),
            ("isp",         "ISP",           "found"),
            ("org",         "Organisation",  "found"),
            ("as",          "AS",            "found"),
            ("mobile",      "Mobile carrier","warn"),
            ("proxy",       "Proxy / VPN",   "warn"),
            ("hosting",     "Hosting",       "warn"),
        ):
            v = ipapi.get(k)
            if v not in (None, "", False):
                result.add("ip-api", label, str(v), sev)
            elif v is True:
                result.add("ip-api", label, "Yes", "warn")
    elif whois_:
        result.raw["ipwhois"] = whois_
        for k, label in (
            ("country",     "Country"),
            ("region",      "Region"),
            ("city",        "City"),
            ("postal",      "ZIP"),
            ("latitude",    "Latitude"),
            ("longitude",   "Longitude"),
            ("timezone.id", "Timezone"),
            ("connection.isp", "ISP"),
            ("connection.org", "Organisation"),
            ("connection.asn", "AS"),
        ):
            # support dotted path
            val = whois_
            for part in k.split("."):
                if not isinstance(val, dict):
                    val = None
                    break
                val = val.get(part)
            if val:
                result.add("ipwho.is", label, str(val), "found")

    if rdns:
        result.add("dns", "Reverse DNS (PTR)", rdns, "found")

    # Shodan InternetDB
    if idb:
        result.raw["shodan_internetdb"] = idb
        if idb["ports"]:
            result.add("shodan", "Open ports", ", ".join(map(str, idb["ports"])), "warn")
        if idb["hostnames"]:
            for h in idb["hostnames"][:10]:
                result.add("shodan", "Hostname", h, "found")
        if idb["vulns"]:
            result.add("shodan", "CVEs", f"{len(idb['vulns'])} vulnerabilities", "warn")
            for v in idb["vulns"][:8]:
                result.add("shodan", "CVE", v, "warn",
                           url=f"https://nvd.nist.gov/vuln/detail/{v}")
        if idb["tags"]:
            result.add("shodan", "Tags", ", ".join(idb["tags"]), "info")
        if idb["cpes"]:
            for cpe in idb["cpes"][:5]:
                result.add("shodan", "CPE", cpe, "info")

    # GreyNoise
    if gn:
        result.raw["greynoise"] = gn
        if gn["seen"]:
            klass = gn.get("classification", "unknown")
            sev = "warn" if klass == "malicious" else (
                "found" if klass == "benign" else "info"
            )
            result.add("greynoise", "Classification", klass, sev)
            if gn.get("name"):
                result.add("greynoise", "Name", gn["name"], "info")
            if gn.get("last_seen"):
                result.add("greynoise", "Last seen", gn["last_seen"], "info")
            if gn.get("link"):
                result.add("greynoise", "Visualiser", gn["link"], "info",
                           url=gn["link"])
        else:
            result.add("greynoise", "Internet scanning activity", "Not observed",
                       "found")

    # StopForumSpam — abuse reputation
    if sfs:
        result.raw["stopforumspam"] = sfs
        if sfs.get("listed"):
            result.add("stopforumspam", "Spam/abuse listed",
                       f"seen {sfs.get('frequency', '?')}× "
                       f"(confidence {sfs.get('confidence', '?')}%)", "warn")
            if sfs.get("last_seen"):
                result.add("stopforumspam", "Last abuse", sfs["last_seen"], "info")
        else:
            result.add("stopforumspam", "Spam/abuse listed", "Not listed", "found")

    # AlienVault
    if av:
        result.raw["alienvault"] = av
        pulses = av.get("pulse_count", 0)
        sev = "warn" if pulses > 0 else "found"
        result.add("alienvault", "Threat pulses", str(pulses), sev)
        if av.get("asn"):
            result.add("alienvault", "AS", av["asn"], "info")

    # WHOIS
    if whois_data:
        result.raw["whois"] = whois_data
        for key in ("NetName", "OrgName", "Country", "CIDR", "Organization",
                     "netname", "country", "descr"):
            for k, v in whois_data.items():
                if k.lower() == key.lower() and v:
                    result.add("whois", key, v[:80], "info")
                    break

    return result
