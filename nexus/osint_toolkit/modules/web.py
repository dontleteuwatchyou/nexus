"""Web OSINT — analyse a single URL.

Sources:
- HTTP headers / security headers grade
- Tech-stack fingerprint (HTML + headers)
- Wayback Machine (first/last snapshot, count)
- urlscan.io (anonymous search)
- SSL certificate inspection (Python ssl module)
- robots.txt + sitemap discovery
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse

import httpx

from ..http import get_json, get_text, session
from ..models import ScanResult

log = logging.getLogger("osint.web")


def normalize(url: str) -> str:
    u = (url or "").strip()
    if not re.match(r"^https?://", u):
        u = "https://" + u
    return u


# ─── HTTP headers ──────────────────────────────────────────────────

_SECURITY_HEADERS = {
    "strict-transport-security":    "HSTS",
    "content-security-policy":      "CSP",
    "x-frame-options":               "X-Frame-Options",
    "x-content-type-options":        "X-Content-Type-Options",
    "referrer-policy":                "Referrer-Policy",
    "permissions-policy":            "Permissions-Policy",
    "cross-origin-opener-policy":   "COOP",
    "cross-origin-resource-policy":  "CORP",
    "cross-origin-embedder-policy":  "COEP",
}


async def _fetch(client: httpx.AsyncClient, url: str):
    try:
        r = await client.get(url, timeout=15)
        return r
    except Exception as e:
        log.debug("fetch %s: %s", url, e)
        return None


def _grade(present: int, total: int) -> str:
    pct = present / total * 100
    if pct >= 90:  return "A+"
    if pct >= 80:  return "A"
    if pct >= 70:  return "B"
    if pct >= 50:  return "C"
    if pct >= 30:  return "D"
    return "F"


# ─── Tech detection ────────────────────────────────────────────────

_TECH_SIGS = {
    "WordPress":  ["wp-content", "wp-includes", "wp-json"],
    "Drupal":     ["drupal-settings", "/sites/default/files", "drupal.js"],
    "Joomla":     ["/media/jui/", "joomla!"],
    "Shopify":    ["cdn.shopify.com", "shopify_analytics"],
    "Magento":    ["mage/cookies", "magento"],
    "Squarespace":["squarespace", "static1.squarespace.com"],
    "Wix":        ["static.wixstatic", "wix-warmup"],
    "Webflow":    ["webflow.js", "webflow.com"],
    "Ghost":      ["ghost-sdk", "/ghost/"],
    "React":      ["__reactfiber", "react-dom"],
    "Vue.js":     ["vue.min.js", "__vue__", "data-v-"],
    "Angular":    ["ng-version", "ng-app"],
    "Svelte":     ["svelte-"],
    "Next.js":    ["__next", "_next/static"],
    "Nuxt":       ["__nuxt", "/_nuxt/"],
    "Gatsby":     ["___gatsby"],
    "Astro":      ["astro-island"],
    "jQuery":     ["jquery.min.js", "jquery.js"],
    "Bootstrap":  ["bootstrap.min.css", "bootstrap.min.js"],
    "Tailwind":   ["tailwindcss", "tw-"],
    "Material UI":["mui-", "material-ui"],
    "Laravel":    ["laravel_session", "csrf-token"],
    "Django":     ["csrfmiddlewaretoken"],
    "Rails":      ["data-turbo", "csrf-token"],
    "Cloudflare": ["cf-ray", "__cf_bm", "cloudflare"],
    "Fastly":     ["fastly"],
    "Vercel":     ["x-vercel"],
    "Netlify":    ["netlify"],
    "Google Analytics": ["google-analytics", "googletagmanager", "gtag"],
    "Plausible":  ["plausible.io"],
    "Matomo":     ["matomo.js", "_paq"],
    "Hotjar":     ["hotjar"],
    "Stripe":     ["js.stripe.com"],
    "PayPal":     ["paypal.com/sdk"],
    "Intercom":   ["intercom.io"],
    "HubSpot":    ["hs-scripts.com"],
    "Algolia":    ["algolia"],
}


def _detect_tech(html: str, headers: dict) -> list[str]:
    found = set()
    hl = html.lower()
    server = headers.get("server", "").lower()
    powered = headers.get("x-powered-by", "").lower()

    for tech, patterns in _TECH_SIGS.items():
        if any(p.lower() in hl for p in patterns):
            found.add(tech)

    if "nginx" in server:    found.add("Nginx")
    if "apache" in server:   found.add("Apache")
    if "iis" in server:      found.add("IIS")
    if "caddy" in server:    found.add("Caddy")
    if "openresty" in server: found.add("OpenResty")
    if "php" in powered:     found.add("PHP")
    if "express" in powered: found.add("Express")
    if "asp.net" in powered: found.add("ASP.NET")

    return sorted(found)


# ─── SSL cert ──────────────────────────────────────────────────────

async def _ssl_cert(host: str, port: int = 443) -> dict | None:
    def _do_handshake():
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                return ss.getpeercert()

    try:
        cert = await asyncio.get_event_loop().run_in_executor(None, _do_handshake)
    except Exception as e:
        log.debug("ssl: %s", e)
        return None
    if not cert:
        return None

    def _name(seq):
        return ", ".join(f"{k}={v}" for items in seq for k, v in items)

    not_after = cert.get("notAfter")
    days_left = None
    if not_after:
        try:
            dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (dt - datetime.utcnow()).days
        except Exception:
            pass

    return {
        "subject":    _name(cert.get("subject", [])),
        "issuer":     _name(cert.get("issuer", [])),
        "not_before": cert.get("notBefore"),
        "not_after":  not_after,
        "days_left":  days_left,
        "san":        [s[1] for s in cert.get("subjectAltName", [])],
        "serial":     cert.get("serialNumber"),
    }


# ─── Wayback ───────────────────────────────────────────────────────

async def _wayback(client: httpx.AsyncClient, host: str) -> dict | None:
    url = (
        f"https://web.archive.org/cdx/search/cdx?url={host}"
        "&output=json&fl=timestamp&collapse=timestamp:6&limit=1000"
    )
    j = await get_json(client, url, timeout=20)
    if not j or not isinstance(j, list) or len(j) < 2:
        return None
    timestamps = [r[0] for r in j[1:]]
    timestamps.sort()
    return {
        "snapshots": len(timestamps),
        "first":     timestamps[0],
        "last":      timestamps[-1],
    }


async def _urlscan(client: httpx.AsyncClient, host: str) -> dict | None:
    j = await get_json(
        client, f"https://urlscan.io/api/v1/search/?q=domain:{host}&size=3",
        timeout=15,
    )
    if not j or not isinstance(j, dict):
        return None
    return {
        "total": j.get("total", 0),
        "latest": [{
            "url":     r.get("page", {}).get("url"),
            "scanned": r.get("task", {}).get("time"),
            "result":  r.get("result"),
        } for r in (j.get("results") or [])[:3]],
    }


async def _robots(client: httpx.AsyncClient, base: str) -> dict | None:
    status, text = await get_text(client, f"{base}/robots.txt", timeout=10)
    if not text or status != 200:
        return None
    sitemaps = re.findall(r"(?im)^Sitemap:\s*(\S+)", text)
    disallows = re.findall(r"(?im)^Disallow:\s*(\S+)", text)
    return {
        "size":      len(text),
        "sitemaps":  sitemaps[:10],
        "disallow":  disallows[:20],
    }


# ─── Orchestrator ──────────────────────────────────────────────────

async def scan(url: str, timeout: float = 25.0) -> ScanResult:
    url = normalize(url)
    parsed = urlparse(url)
    host = parsed.hostname or ""
    result = ScanResult(target=url, module="web")

    if not host:
        result.errors.append(f"Could not parse host from URL: {url}")
        return result

    async with session(timeout=timeout) as client:
        resp, wayback, urlscan, robots, ssl_info = await asyncio.gather(
            _fetch(client, url),
            _wayback(client, host),
            _urlscan(client, host),
            _robots(client, f"{parsed.scheme}://{host}"),
            _ssl_cert(host) if parsed.scheme == "https" else asyncio.sleep(0, result=None),
            return_exceptions=True,
        )

    def safe(x):
        return x if not isinstance(x, Exception) else None
    resp, wayback, urlscan, robots, ssl_info = map(
        safe, (resp, wayback, urlscan, robots, ssl_info)
    )

    # HTTP response
    if resp is not None:
        result.raw["status"] = resp.status_code
        result.raw["headers"] = dict(resp.headers)
        result.add("http", "Status", str(resp.status_code),
                   "found" if 200 <= resp.status_code < 400 else "warn")

        # Surface key headers
        for h in ("server", "x-powered-by", "x-generator", "via"):
            v = resp.headers.get(h)
            if v:
                result.add("http", h, v, "info")

        # Security headers grade
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        present = [n for h, n in _SECURITY_HEADERS.items() if h in headers_lower]
        missing = [n for h, n in _SECURITY_HEADERS.items() if h not in headers_lower]
        total = len(_SECURITY_HEADERS)
        grade = _grade(len(present), total)
        sev = "found" if grade in ("A+", "A") else ("warn" if grade in ("B", "C") else "warn")
        result.add("security headers", "Grade",
                   f"{grade}  ({len(present)}/{total})", sev)
        if present:
            result.add("security headers", "Present", " · ".join(present), "found")
        if missing:
            result.add("security headers", "Missing", " · ".join(missing), "warn")

        # Tech stack
        techs = _detect_tech(resp.text or "", resp.headers)
        if techs:
            result.add("tech stack", "Detected", " · ".join(techs), "found")

        # Title
        m = re.search(r"<title[^>]*>(.*?)</title>", resp.text or "",
                       re.IGNORECASE | re.DOTALL)
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()
            result.add("http", "Page title", title[:120], "info")

    # SSL
    if ssl_info:
        result.raw["ssl"] = ssl_info
        result.add("ssl", "Issuer", ssl_info["issuer"][:80], "found")
        result.add("ssl", "Subject", ssl_info["subject"][:80], "info")
        if ssl_info["not_after"]:
            sev = "warn" if (ssl_info["days_left"] or 0) < 14 else "found"
            result.add("ssl", "Expires", f"{ssl_info['not_after']} ({ssl_info['days_left']}d left)", sev)
        if ssl_info["san"]:
            result.add("ssl", "SAN count", str(len(ssl_info["san"])), "info")

    # Wayback
    if wayback:
        result.raw["wayback"] = wayback
        result.add("wayback", "Snapshots", str(wayback["snapshots"]), "info")
        result.add("wayback", "First snapshot", wayback["first"][:8], "info")
        result.add("wayback", "Latest snapshot", wayback["last"][:8], "info")

    # urlscan
    if urlscan:
        result.raw["urlscan"] = urlscan
        if urlscan["total"]:
            result.add("urlscan", "Public scans", str(urlscan["total"]), "info")

    # robots
    if robots:
        result.raw["robots"] = robots
        result.add("robots.txt", "Size", f"{robots['size']} bytes", "info")
        if robots["sitemaps"]:
            for sm in robots["sitemaps"]:
                result.add("robots.txt", "Sitemap", sm, "found", url=sm)
        if robots["disallow"]:
            result.add("robots.txt", "Disallow rules",
                       str(len(robots["disallow"])), "info")
            for d in robots["disallow"][:8]:
                result.add("robots.txt", "Disallow", d, "info")

    return result
