"""Username OSINT — WhatsMyName database (600+ sites maintained).

Uses the WhatsMyName JSON spec which provides per-site:
- URI template
- Expected HTTP status
- Expected response body string (anti-false-positive)

Source: https://github.com/WebBreacher/WhatsMyName
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

import httpx

from ..http import get_json, session
from ..models import ScanResult

log = logging.getLogger("osint.username")

WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,40}$")

# Cache the WhatsMyName DB in memory for the lifetime of the process.
_WMN_CACHE: dict[str, Any] | None = None


def is_valid(username: str) -> bool:
    return bool(USERNAME_RE.match(username or ""))


async def _load_wmn(client: httpx.AsyncClient) -> dict | None:
    global _WMN_CACHE
    if _WMN_CACHE is not None:
        return _WMN_CACHE
    j = await get_json(client, WMN_URL, timeout=20)
    if j and isinstance(j, dict) and "sites" in j:
        _WMN_CACHE = j
        return j
    return None


async def _check_site(client: httpx.AsyncClient, site: dict, username: str,
                       sem: asyncio.Semaphore) -> dict | None:
    """Check one site per the WhatsMyName spec.

    Site dict fields used: name, uri_check, e_string, m_string, e_code, m_code, cat.
    `e_string` must be present in the body when account exists.
    `m_string` is present when account does NOT exist (sometimes used).
    """
    name = site.get("name") or "?"
    uri  = site.get("uri_check") or ""
    if not uri or "{account}" not in uri:
        return None
    url = uri.replace("{account}", username)
    e_string = site.get("e_string")
    m_string = site.get("m_string")
    e_code   = site.get("e_code", 200)
    m_code   = site.get("m_code")
    category = site.get("cat", "")
    headers  = site.get("headers", {}) or {}
    post_body = site.get("post_body")
    method   = "POST" if post_body else "GET"

    async with sem:
        try:
            if method == "POST":
                r = await client.post(url, data=post_body, headers=headers, timeout=10)
            else:
                r = await client.get(url, headers=headers, timeout=10)
        except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPError):
            return None
        except Exception:
            return None

    if r.status_code != e_code:
        return None
    body = r.text
    # Strong positive: e_string must be present
    if e_string and e_string not in body:
        return None
    # Hard negative: m_string present means "not found"
    if m_string and m_string in body:
        return None
    # Hard negative: m_code matched
    if m_code and r.status_code == m_code:
        return None
    return {"name": name, "url": url, "category": category}


# ─── Orchestrator ──────────────────────────────────────────────────

async def scan(username: str, timeout: float = 25.0,
               progress_cb=None) -> ScanResult:
    """Check username across WhatsMyName's 600+ sites in parallel.

    progress_cb: optional callable(done, total, current_site_name) for UI updates.
    """
    result = ScanResult(target=username, module="username")

    if not is_valid(username):
        result.errors.append(f"Invalid username: {username}")
        return result

    async with session(timeout=timeout) as client:
        wmn = await _load_wmn(client)
        if not wmn:
            result.errors.append("Could not load WhatsMyName database")
            return result

        sites = wmn.get("sites", [])
        # Skip NSFW unless explicitly enabled
        sites = [s for s in sites if s.get("cat") != "xx adult"]
        total = len(sites)
        result.raw["sites_checked"] = total

        sem = asyncio.Semaphore(40)
        done = 0
        lock = asyncio.Lock()

        async def _run(site):
            nonlocal done
            res = await _check_site(client, site, username, sem)
            async with lock:
                done += 1
                if progress_cb:
                    progress_cb(done, total, site.get("name", "?"))
            return res

        results = await asyncio.gather(*[_run(s) for s in sites],
                                        return_exceptions=True)

    # Aggregate
    found = [r for r in results if isinstance(r, dict) and r]
    by_cat: dict[str, list[dict]] = {}
    for r in found:
        by_cat.setdefault(r["category"] or "other", []).append(r)

    result.raw["found"] = found
    result.raw["categories"] = list(by_cat.keys())

    result.add("summary", "Sites checked", str(total), "info")
    if found:
        result.add("summary", "Accounts found", str(len(found)), "warn")
    else:
        result.add("summary", "Accounts found", "None", "found")

    # Add findings grouped by category
    for cat in sorted(by_cat.keys()):
        for r in by_cat[cat]:
            result.add(cat or "other", r["name"], r["url"], "warn", url=r["url"])

    return result
