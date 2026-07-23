"""Dedicated breach OSINT — checks credentials / data leaks.

Takes email, username, or domain. Queries multiple free breach databases
in parallel and aggregates results. Passwords (when surfaced) are always
masked in output.

Sources:
  • Hudson Rock Cavalier (email + username + domain) — free, no key
  • ProxyNova COMB (email) — free, no key
  • XposedOrNot (email + domain breach list) — free, no key
  • LeakCheck public endpoint (email) — free, no key, may rate-limit
  • Pwnedpasswords k-anonymity (raw password) — free, no key
  • DeHashed (link only — public search requires registration)
  • IntelX (link only — public search)
  • BreachDirectory (link only)
  • Snusbase (link only)
  • Have I Been Pwned (link only — full API needs key)
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from typing import Optional
from urllib.parse import quote_plus

import httpx

from ..http import get_json, get_text, session
from ..models import ScanResult


EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,40}$")


def detect_kind(target: str) -> str:
    t = (target or "").strip()
    if EMAIL_RE.match(t):    return "email"
    if DOMAIN_RE.match(t):   return "domain"
    if USERNAME_RE.match(t): return "username"
    return "unknown"


def _mask(pwd: str) -> str:
    if not pwd:
        return ""
    if len(pwd) <= 2:
        return "•" * len(pwd)
    return f"{pwd[0]}{'•' * (len(pwd) - 2)}{pwd[-1]}"


# ── Active sources ───────────────────────────────────────────────

async def _hudson_rock_email(client: httpx.AsyncClient, email: str) -> dict | None:
    url = ("https://cavalier.hudsonrock.com/api/json/v2/"
           f"osint-tools/search-by-email?email={email}")
    return await get_json(client, url, timeout=20)


async def _hudson_rock_username(client: httpx.AsyncClient, username: str) -> dict | None:
    url = ("https://cavalier.hudsonrock.com/api/json/v2/"
           f"osint-tools/search-by-username?username={username}")
    return await get_json(client, url, timeout=20)


async def _hudson_rock_domain(client: httpx.AsyncClient, domain: str) -> dict | None:
    url = ("https://cavalier.hudsonrock.com/api/json/v2/"
           f"osint-tools/search-by-domain?domain={domain}")
    return await get_json(client, url, timeout=20)


async def _proxynova(client: httpx.AsyncClient, email: str) -> dict | None:
    url = f"https://api.proxynova.com/comb?query={email}&start=0&limit=20"
    j = await get_json(client, url, timeout=15)
    if not j or not isinstance(j, dict):
        return None
    lines = j.get("lines") or []
    leaks = []
    for line in lines[:20]:
        if ":" in line:
            ident, _, pwd = line.partition(":")
            leaks.append({"identifier": ident, "masked": _mask(pwd),
                          "length": len(pwd)})
    return {"found": len(leaks), "total": j.get("count", len(lines)),
            "leaks": leaks}


async def _xposedornot_email(client: httpx.AsyncClient, email: str) -> dict | None:
    """XposedOrNot check-email — list of breaches an email appears in."""
    j = await get_json(client, f"https://api.xposedornot.com/v1/check-email/{email}",
                       timeout=15)
    if not j or not isinstance(j, dict):
        return None
    # {"breaches":[[ "Adobe", "Dropbox", ... ]]} or {"Error":"Not found"}
    if j.get("Error"):
        return {"found": 0, "breaches": []}
    raw = j.get("breaches") or []
    names = raw[0] if raw and isinstance(raw[0], list) else raw
    return {"found": len(names), "breaches": names}


async def _xposedornot_domain(client: httpx.AsyncClient, domain: str) -> dict | None:
    """XposedOrNot domain breaches — breaches tied to a domain, with dates."""
    j = await get_json(client, f"https://api.xposedornot.com/v1/breaches?domain={domain}",
                       timeout=15)
    if not j or not isinstance(j, dict):
        return None
    breaches = j.get("exposedBreaches") or []
    out = []
    for b in breaches:
        if not isinstance(b, dict):
            continue
        out.append({
            "name":    b.get("breachID"),
            "date":    (b.get("breachedDate") or "")[:10],
            "records": b.get("exposedRecords"),
            "data":    b.get("exposedData") or [],
            "verified": b.get("verified"),
        })
    return {"found": len(out), "breaches": out}


async def _leakcheck_public(client: httpx.AsyncClient, query: str) -> dict | None:
    """LeakCheck.net public endpoint. May be rate-limited."""
    url = f"https://leakcheck.net/api/public?check={quote_plus(query)}"
    j = await get_json(client, url, timeout=15)
    if not j or not isinstance(j, dict):
        return None
    if not j.get("success"):
        return None
    return {
        "found":   j.get("found", 0),
        "sources": j.get("sources", []),
        "fields":  j.get("fields", []),
    }


async def _hibp_password_check(client: httpx.AsyncClient, password: str) -> int | None:
    """HIBP k-anonymity password check. Returns count of times seen, or None."""
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    status, body = await get_text(
        client, f"https://api.pwnedpasswords.com/range/{prefix}", timeout=10
    )
    if not body:
        return None
    for line in body.splitlines():
        if ":" in line:
            s, _, count = line.partition(":")
            if s.strip() == suffix:
                try:
                    return int(count.strip())
                except ValueError:
                    return 0
    return 0


# ── Link generators (sources that can't be queried free) ────────

def _breach_search_links(query: str, kind: str) -> list[tuple[str, str]]:
    q = quote_plus(query)
    if kind == "email":
        return [
            ("Have I Been Pwned",  f"https://haveibeenpwned.com/account/{q}"),
            ("DeHashed",           f"https://dehashed.com/search?query={q}"),
            ("IntelX",             f"https://intelx.io/?s={q}"),
            ("BreachDirectory",    f"https://breachdirectory.org/?q={q}"),
            ("Snusbase",           f"https://snusbase.com/search?term={q}"),
            ("LeakPeek",           f"https://leakpeek.com/?s={q}"),
            ("BreachChecker.com",  f"https://breachchecker.com/?email={q}"),
            ("PSBDMP (pastebins)", f"https://psbdmp.ws/search?query={q}"),
        ]
    if kind == "domain":
        return [
            ("HIBP · Breaches",    f"https://haveibeenpwned.com/DomainSearch/{q}"),
            ("DeHashed",           f"https://dehashed.com/search?query=domain%3A{q}"),
            ("IntelX",             f"https://intelx.io/?s={q}"),
        ]
    if kind == "username":
        return [
            ("DeHashed",           f"https://dehashed.com/search?query=username%3A{q}"),
            ("IntelX",             f"https://intelx.io/?s={q}"),
            ("Snusbase",           f"https://snusbase.com/search?term={q}"),
        ]
    return []


# ── Orchestrator ────────────────────────────────────────────────

async def scan(target: str, *, timeout: float = 25.0,
                kind: str | None = None) -> ScanResult:
    """Aggregate breach checks across free sources."""
    kind = kind or detect_kind(target)
    result = ScanResult(target=target, module="breach")

    if kind == "unknown":
        result.errors.append(f"Target type undetected: {target}")
        return result

    result.add("input", "Type", kind, "info")

    async with session(timeout=timeout) as client:
        if kind == "email":
            hr, pn, lc, xon = await asyncio.gather(
                _hudson_rock_email(client, target),
                _proxynova(client, target),
                _leakcheck_public(client, target),
                _xposedornot_email(client, target),
                return_exceptions=True,
            )
        elif kind == "username":
            hr, pn, lc, xon = await asyncio.gather(
                _hudson_rock_username(client, target),
                asyncio.sleep(0, result=None),       # no proxynova for username
                _leakcheck_public(client, target),
                asyncio.sleep(0, result=None),       # XposedOrNot needs email/domain
                return_exceptions=True,
            )
        elif kind == "domain":
            hr, pn, lc, xon = await asyncio.gather(
                _hudson_rock_domain(client, target),
                asyncio.sleep(0, result=None),
                asyncio.sleep(0, result=None),
                _xposedornot_domain(client, target),
                return_exceptions=True,
            )
        else:
            hr = pn = lc = xon = None

    def safe(x):
        return x if not isinstance(x, Exception) else None
    hr, pn, lc, xon = map(safe, (hr, pn, lc, xon))

    # ── Hudson Rock ─────────────────────────────────────────────
    if hr and isinstance(hr, dict):
        result.raw["hudson_rock"] = hr
        if kind == "email":
            stealers = hr.get("stealers") or []
            if stealers:
                result.add("hudson_rock", "Infostealer infection",
                           f"{len(stealers)} compromised computer(s)", "warn")
                for s in stealers[:5]:
                    date = (s.get("date_compromised") or "?")[:10]
                    family = s.get("stealer_family", "?")
                    result.add("hudson_rock", f"Infection · {date}",
                               f"{family} on {s.get('computer_name','?')}", "warn")
            else:
                result.add("hudson_rock", "Infostealer", "Clean", "found")

        elif kind == "username":
            stealers = hr.get("stealers") or hr.get("data") or []
            if stealers:
                result.add("hudson_rock", "Infostealer infection",
                           f"{len(stealers)} computer(s)", "warn")
            else:
                result.add("hudson_rock", "Infostealer", "Clean", "found")

        elif kind == "domain":
            # Domain search returns employee + user + 3rd-party stats
            employees = hr.get("employees", {}) if isinstance(hr.get("employees"), dict) else {}
            users     = hr.get("users", {}) if isinstance(hr.get("users"), dict) else {}
            third     = hr.get("third_parties", {}) if isinstance(hr.get("third_parties"), dict) else {}
            emp_count = employees.get("total_employees", 0)
            usr_count = users.get("total_users", 0)
            tp_count  = third.get("total", 0)
            if emp_count:
                result.add("hudson_rock", "Compromised employees", str(emp_count), "warn")
            if usr_count:
                result.add("hudson_rock", "Compromised users", str(usr_count), "warn")
            if tp_count:
                result.add("hudson_rock", "Third-party exposures", str(tp_count), "warn")
            if not (emp_count or usr_count or tp_count):
                result.add("hudson_rock", "Domain exposure", "Clean", "found")

    # ── ProxyNova ──────────────────────────────────────────────
    if pn and isinstance(pn, dict) and pn.get("found"):
        result.raw["proxynova"] = pn
        result.add("proxynova", "Credential leaks",
                   f"{pn['found']} entries (total ~{pn.get('total', '?')})", "warn")
        for leak in pn["leaks"][:8]:
            result.add("proxynova", "Leaked password (masked)",
                       f"{leak['masked']} ({leak['length']} chars)", "warn")
    elif pn is not None and isinstance(pn, dict):
        result.add("proxynova", "Credential leaks", "None found", "found")

    # ── XposedOrNot ────────────────────────────────────────────
    if xon and isinstance(xon, dict):
        result.raw["xposedornot"] = xon
        if kind == "email":
            if xon.get("found"):
                result.add("xposedornot", "Breaches",
                           f"{xon['found']} breach(es)", "warn")
                for name in xon["breaches"][:15]:
                    result.add("xposedornot", "Breach", str(name), "warn")
            else:
                result.add("xposedornot", "Breaches", "None found", "found")
        elif kind == "domain":
            if xon.get("found"):
                result.add("xposedornot", "Domain breaches",
                           f"{xon['found']} breach(es)", "warn")
                for b in xon["breaches"][:12]:
                    name = b.get("name") or "?"
                    date = b.get("date") or ""
                    data = ", ".join(b.get("data", [])[:5])
                    val = f"{date}".strip()
                    if data:
                        val = f"{val} · {data}" if val else data
                    result.add("xposedornot", name, val or "breach", "warn")
            else:
                result.add("xposedornot", "Domain breaches", "None found", "found")

    # ── LeakCheck ──────────────────────────────────────────────
    if lc and isinstance(lc, dict):
        result.raw["leakcheck"] = lc
        if lc.get("found"):
            result.add("leakcheck", "Breaches", f"{lc['found']} entries", "warn")
            for src in (lc.get("sources") or [])[:8]:
                if isinstance(src, dict):
                    name = src.get("name", "?")
                    date = src.get("date", "")
                    result.add("leakcheck", "Source", f"{name} {date}".strip(), "warn")
                else:
                    result.add("leakcheck", "Source", str(src), "warn")
            if lc.get("fields"):
                result.add("leakcheck", "Fields exposed",
                           ", ".join(lc["fields"]), "warn")
        else:
            result.add("leakcheck", "Breaches", "None found", "found")

    # ── Link-only sources (manual lookup) ──────────────────────
    links = _breach_search_links(target, kind)
    if links:
        for label, url in links:
            result.add("manual lookup", label, url, "info", url=url)

    return result


# ── Convenience: password-only check (HIBP k-anonymity) ─────────

async def check_password(password: str, *, timeout: float = 10.0) -> ScanResult:
    """Standalone: check if a raw password appears in any breach.
    Uses HIBP's k-anonymity API — only the first 5 SHA-1 chars leave the
    process, so the password itself is never sent.
    """
    result = ScanResult(target="<password>", module="breach_password")
    async with session(timeout=timeout) as client:
        count = await _hibp_password_check(client, password)
    if count is None:
        result.errors.append("HIBP query failed")
        return result
    if count == 0:
        result.add("hibp", "Found in breaches",
                   "Not seen in any known breach", "found")
    else:
        result.add("hibp", "Found in breaches",
                   f"Seen {count:,} times — DO NOT USE", "warn")
    return result
