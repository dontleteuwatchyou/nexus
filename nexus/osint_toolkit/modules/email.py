"""Email OSINT — 100% free sources, no API keys.

Sources:
- Holehe (120+ sites account check)
- Gravatar (MD5 + SHA256 profile lookup)
- Hudson Rock Cavalier (infostealer leak check)
- ProxyNova COMB (credentials leak)
- EmailRep.io (free quota, no auth)
- XposedOrNot (breach analytics: risk score, exposed data, breach list)
- StopForumSpam (spam / abuse reputation)
- DNS MX validation
- Disposable / role detection (rule-based)
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import socket
from typing import Any

import httpx

from ..http import get_json, get_text, session
from ..models import ScanResult

log = logging.getLogger("osint.email")

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

# Known disposable / temporary email domains (subset of the well-maintained list)
_DISPOSABLE = {
    "10minutemail.com", "guerrillamail.com", "mailinator.com", "tempmail.com",
    "throwawaymail.com", "yopmail.com", "trashmail.com", "fakeinbox.com",
    "getnada.com", "maildrop.cc", "tempinbox.com", "dispostable.com",
    "mintemail.com", "tempmailo.com", "temp-mail.org", "tempmailaddress.com",
    "discard.email", "emailondeck.com", "mohmal.com", "moakt.com",
}

_ROLE_LOCAL_PARTS = {
    "admin", "administrator", "info", "contact", "support", "help", "sales",
    "noreply", "no-reply", "postmaster", "webmaster", "abuse", "marketing",
    "team", "office", "hello", "hi", "service", "billing", "accounts",
}


def is_valid(email: str) -> bool:
    return bool(EMAIL_RE.match(email or ""))


def classify(email: str) -> dict[str, bool]:
    """Quick rule-based classification."""
    local, _, domain = email.partition("@")
    return {
        "disposable": domain.lower() in _DISPOSABLE,
        "role":       local.lower() in _ROLE_LOCAL_PARTS,
        "free":       domain.lower() in {"gmail.com", "outlook.com", "hotmail.com",
                                          "yahoo.com", "icloud.com", "proton.me",
                                          "protonmail.com", "gmx.com", "yandex.com",
                                          "mail.com", "aol.com", "live.com"},
    }


# ─── Sources ───────────────────────────────────────────────────────

async def _gravatar(client: httpx.AsyncClient, email: str) -> dict | None:
    """Gravatar profile JSON (free, no key)."""
    md5 = hashlib.md5(email.lower().strip().encode()).hexdigest()
    sha256 = hashlib.sha256(email.lower().strip().encode()).hexdigest()
    j = await get_json(client, f"https://en.gravatar.com/{md5}.json")
    if not j or not isinstance(j, dict):
        return None
    entry = (j.get("entry") or [{}])[0]
    if not entry:
        return None
    return {
        "profile_url":   f"https://gravatar.com/{md5}",
        "display_name":  entry.get("displayName"),
        "preferred_username": entry.get("preferredUsername"),
        "name":          (entry.get("name") or {}).get("formatted"),
        "location":      entry.get("currentLocation"),
        "about":         entry.get("aboutMe"),
        "avatar":        entry.get("thumbnailUrl"),
        "verified_accounts": [
            {"shortname": a.get("shortname"), "url": a.get("url")}
            for a in entry.get("accounts", []) if a.get("verified")
        ],
        "urls":          [{"title": u.get("title"), "url": u.get("value")}
                          for u in entry.get("urls", [])],
        "md5":           md5,
        "sha256":        sha256,
    }


async def _hudson_rock(client: httpx.AsyncClient, email: str) -> dict | None:
    """Hudson Rock Cavalier — infostealer leak check (free, no key)."""
    url = (
        "https://cavalier.hudsonrock.com/api/json/v2/"
        f"osint-tools/search-by-email?email={email}"
    )
    j = await get_json(client, url, timeout=20)
    if not j:
        return None
    # Returns {stealers: [...], ...}
    stealers = j.get("stealers") or []
    return {
        "compromised": bool(stealers),
        "infections":  len(stealers),
        "stealers":    [
            {
                "family":     s.get("stealer_family"),
                "date":       s.get("date_compromised"),
                "computer":   s.get("computer_name"),
                "ip":         s.get("ip"),
                "credentials_count": s.get("credentials_count"),
                "antiviruses":s.get("antiviruses"),
            }
            for s in stealers[:10]
        ],
        "message":     j.get("message"),
    }


async def _proxynova(client: httpx.AsyncClient, email: str) -> dict | None:
    """ProxyNova COMB — exposed credentials (free, no key)."""
    url = f"https://api.proxynova.com/comb?query={email}&start=0&limit=15"
    j = await get_json(client, url, timeout=15)
    if not j or not isinstance(j, dict):
        return None
    lines = j.get("lines") or []
    if not lines:
        return None
    leaks = []
    for line in lines[:15]:
        # Format is usually "email:password"
        if ":" in line:
            _, pwd = line.split(":", 1)
            # Mask the password — show length + first/last char only
            masked = (
                f"{pwd[0]}{'•' * max(0, len(pwd) - 2)}{pwd[-1]}"
                if len(pwd) >= 2 else "•" * len(pwd)
            )
            leaks.append({"masked_password": masked, "length": len(pwd)})
    return {
        "found":  len(leaks),
        "total":  j.get("count", len(lines)),
        "leaks":  leaks,
    }


async def _emailrep(client: httpx.AsyncClient, email: str) -> dict | None:
    """EmailRep.io — free quota without API key."""
    j = await get_json(client, f"https://emailrep.io/{email}", timeout=15)
    if not j or not isinstance(j, dict):
        return None
    details = j.get("details") or {}
    return {
        "reputation":   j.get("reputation"),
        "suspicious":   j.get("suspicious"),
        "references":   j.get("references"),
        "spam":         details.get("spam"),
        "malicious":    details.get("malicious_activity"),
        "credentials_leaked": details.get("credentials_leaked"),
        "data_breach":  details.get("data_breach"),
        "first_seen":   details.get("first_seen"),
        "last_seen":    details.get("last_seen"),
        "domain_exists":details.get("domain_exists"),
        "domain_age":   details.get("days_since_domain_creation"),
        "deliverable":  details.get("deliverable"),
        "free_provider":details.get("free_provider"),
        "disposable":   details.get("disposable"),
        "spoofable":    details.get("spoofable"),
        "profiles":     details.get("profiles") or [],
    }


async def _xposedornot(client: httpx.AsyncClient, email: str) -> dict | None:
    """XposedOrNot breach analytics — free, no key.

    Returns risk score, breach count, exposed data categories, password
    strength distribution and a per-breach list (name, year, industry).
    """
    url = f"https://api.xposedornot.com/v1/breach-analytics?email={email}"
    j = await get_json(client, url, timeout=15)
    if not j or not isinstance(j, dict):
        return None

    metrics = j.get("BreachMetrics") or {}
    risk = (metrics.get("risk") or [{}])[0]
    strength = (metrics.get("passwords_strength") or [{}])[0]

    # Exposed data categories (e.g. Passwords, Names, Phone numbers…)
    exposed_data: list[str] = []
    for grp in metrics.get("xposed_data") or []:
        for child in grp.get("children", []) if isinstance(grp, dict) else []:
            name = (child.get("name") or "").lstrip("🔒👤💰🌍📞 ").strip()
            if name:
                exposed_data.append(name)

    details = (j.get("ExposedBreaches") or {}).get("breaches_details") or []
    breaches = []
    for b in details:
        if not isinstance(b, dict):
            continue
        breaches.append({
            "name":     b.get("breach"),
            "domain":   b.get("domain"),
            "industry": b.get("industry"),
            "pw_risk":  b.get("password_risk"),
            "data":     b.get("xposed_data"),
        })

    if not breaches and not risk.get("risk_score"):
        return {"found": False}

    return {
        "found":         bool(breaches),
        "risk_score":    risk.get("risk_score"),
        "risk_label":    risk.get("risk_label"),
        "breach_count":  len(breaches),
        "exposed_data":  sorted(set(exposed_data)),
        "plaintext_pw":  strength.get("PlainText"),
        "weak_pw":        strength.get("EasyToCrack"),
        "breaches":      breaches,
    }


async def _stopforumspam(client: httpx.AsyncClient, email: str) -> dict | None:
    """StopForumSpam — is this email associated with spam/abuse? Free, no key."""
    j = await get_json(
        client, f"https://api.stopforumspam.org/api?email={email}&json", timeout=10
    )
    if not j or not isinstance(j, dict) or not j.get("success"):
        return None
    e = j.get("email") or {}
    if not e.get("appears"):
        return {"listed": False}
    return {
        "listed":     True,
        "frequency":  e.get("frequency"),
        "confidence": e.get("confidence"),
        "last_seen":  e.get("lastseen"),
    }


async def _holehe_check(email: str) -> dict | None:
    """Run holehe (120+ sites). Catches the holehe library if installed."""
    try:
        from holehe.core import import_submodules, get_functions, launch_module
    except ImportError:
        return None
    try:
        modules = import_submodules("holehe.modules")
        websites = get_functions(modules)
        out: list[dict] = []
        async with httpx.AsyncClient(timeout=15) as client:
            await asyncio.gather(
                *[launch_module(fn, email, client, out) for fn in websites],
                return_exceptions=True,
            )
        found = []
        rate_limited = []
        for entry in out:
            name = entry.get("name") or entry.get("domain") or "?"
            if entry.get("rateLimit"):
                rate_limited.append(name)
                continue
            if entry.get("exists"):
                found.append(name)
        return {
            "checked":      len(out),
            "found":        sorted(found),
            "rate_limited": rate_limited,
        }
    except Exception as e:
        log.debug("holehe error: %s", e)
        return None


async def _mx_check(domain: str) -> list[str] | None:
    """Check MX records for the domain — proves the domain accepts mail."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "dig", "+short", "MX", domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
        records = [
            line.strip() for line in stdout.decode().splitlines() if line.strip()
        ]
        return records if records else None
    except Exception:
        return None


# ─── Orchestrator ──────────────────────────────────────────────────

async def scan(email: str, timeout: float = 25.0) -> ScanResult:
    """Run all email sources concurrently, return aggregated result."""
    result = ScanResult(target=email, module="email")

    if not is_valid(email):
        result.errors.append(f"Invalid email format: {email}")
        return result

    domain = email.split("@", 1)[1].lower()
    classification = classify(email)

    # Rule-based findings first (instant)
    result.add("classification", "Free provider",
               "Yes" if classification["free"] else "No",
               "info")
    result.add("classification", "Disposable",
               "Yes" if classification["disposable"] else "No",
               "warn" if classification["disposable"] else "found")
    result.add("classification", "Role address",
               "Yes" if classification["role"] else "No",
               "info" if classification["role"] else "found")

    # Run all network sources in parallel
    async with session(timeout=timeout) as client:
        (gravatar, hudson, proxynova, emailrep, xon, sfs,
         holehe, mx) = await asyncio.gather(
            _gravatar(client, email),
            _hudson_rock(client, email),
            _proxynova(client, email),
            _emailrep(client, email),
            _xposedornot(client, email),
            _stopforumspam(client, email),
            _holehe_check(email),
            _mx_check(domain),
            return_exceptions=True,
        )

    # Normalise exceptions
    def _safe(x):
        return x if not isinstance(x, Exception) else None

    gravatar, hudson, proxynova, emailrep, xon, sfs, holehe, mx = map(
        _safe, (gravatar, hudson, proxynova, emailrep, xon, sfs, holehe, mx)
    )

    # MX
    if mx:
        result.add("dns", "MX records", f"{len(mx)} found", "found")
        for record in mx[:3]:
            result.add("dns", "MX", record, "info")
    else:
        result.add("dns", "MX records", "None — domain doesn't accept mail", "warn")

    # Gravatar
    if gravatar:
        result.raw["gravatar"] = gravatar
        result.add("gravatar", "Profile", gravatar["profile_url"], "found",
                   url=gravatar["profile_url"])
        if gravatar.get("display_name"):
            result.add("gravatar", "Display name", gravatar["display_name"], "found")
        if gravatar.get("name"):
            result.add("gravatar", "Real name", gravatar["name"], "warn")
        if gravatar.get("preferred_username"):
            result.add("gravatar", "Username", gravatar["preferred_username"], "warn")
        if gravatar.get("location"):
            result.add("gravatar", "Location", gravatar["location"], "warn")
        if gravatar.get("about"):
            result.add("gravatar", "About", gravatar["about"][:160], "info")
        for acc in gravatar.get("verified_accounts", []):
            result.add("gravatar", f"Verified · {acc['shortname']}",
                       acc["url"], "warn", url=acc["url"])

    # Hudson Rock — infostealer
    if hudson:
        result.raw["hudson_rock"] = hudson
        if hudson["compromised"]:
            result.add("hudson_rock", "Infostealer infection",
                       f"{hudson['infections']} computer(s) compromised", "warn")
            for s in hudson["stealers"][:5]:
                date = s.get("date", "?")[:10]
                family = s.get("family", "?")
                result.add("hudson_rock", f"Infection · {date}",
                           f"{family} on {s.get('computer','?')}", "warn")
        else:
            result.add("hudson_rock", "Infostealer infection", "Clean", "found")

    # ProxyNova
    if proxynova and proxynova["found"]:
        result.raw["proxynova"] = proxynova
        result.add("proxynova", "Credential leaks",
                   f"{proxynova['found']} entries (total ~{proxynova['total']})", "warn")
        for leak in proxynova["leaks"][:5]:
            result.add("proxynova", "Leaked password",
                       f"{leak['masked_password']} ({leak['length']} chars)", "warn")
    elif proxynova is not None:
        result.add("proxynova", "Credential leaks", "None found", "found")

    # EmailRep
    if emailrep:
        result.raw["emailrep"] = emailrep
        rep = emailrep.get("reputation")
        if rep:
            sev = "warn" if rep in ("low", "none") else "found"
            result.add("emailrep", "Reputation", rep, sev)
        if emailrep.get("suspicious"):
            result.add("emailrep", "Suspicious", "Yes", "warn")
        if emailrep.get("credentials_leaked"):
            result.add("emailrep", "Credentials leaked", "Yes", "warn")
        if emailrep.get("data_breach"):
            result.add("emailrep", "Data breach", "Yes", "warn")
        if emailrep.get("first_seen"):
            result.add("emailrep", "First seen", emailrep["first_seen"], "info")
        if emailrep.get("last_seen"):
            result.add("emailrep", "Last seen", emailrep["last_seen"], "info")
        for prof in emailrep.get("profiles", [])[:10]:
            result.add("emailrep", f"Profile · {prof}", "registered", "warn")

    # XposedOrNot — breach analytics
    if xon and xon.get("found"):
        result.raw["xposedornot"] = xon
        if xon.get("risk_label"):
            score = xon.get("risk_score")
            sev = "warn" if str(xon["risk_label"]).lower() in ("high", "critical") else "found"
            result.add("xposedornot", "Risk level",
                       f"{xon['risk_label']}" + (f" ({score}/100)" if score else ""), sev)
        result.add("xposedornot", "Breaches",
                   f"{xon['breach_count']} breach(es)", "warn")
        if xon.get("plaintext_pw"):
            result.add("xposedornot", "Plaintext passwords exposed",
                       str(xon["plaintext_pw"]), "warn")
        if xon.get("exposed_data"):
            result.add("xposedornot", "Data types exposed",
                       ", ".join(xon["exposed_data"][:12]), "warn")
        for b in xon["breaches"][:12]:
            name = b.get("name") or "?"
            extra = " · ".join(x for x in (b.get("industry"), b.get("pw_risk")) if x)
            result.add("xposedornot", "Breach", f"{name}" + (f" ({extra})" if extra else ""), "warn")
    elif xon is not None:
        result.add("xposedornot", "Breaches", "None found", "found")

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
            result.add("stopforumspam", "Spam/abuse listed", "No", "found")

    # Holehe
    if holehe:
        result.raw["holehe"] = holehe
        if holehe["found"]:
            result.add("holehe", "Accounts found",
                       f"{len(holehe['found'])} sites", "warn")
            for site in holehe["found"][:25]:
                result.add("holehe", "Site", site, "warn")
        else:
            result.add("holehe", "Accounts found",
                       f"None across {holehe['checked']} sites checked", "found")

    return result
