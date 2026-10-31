"""Search-engine dork generator — passive OSINT.

Given a domain, URL, email, username or name, build ready-to-click
search-engine queries ("Google dorks") that surface commonly-exposed
material: documents, login/admin panels, open directory listings,
configuration and backup files, exposed VCS, and third-party leaks
(pastebin, GitHub, cloud buckets).

100% passive: no request ever reaches the target or any search engine — this
module only *constructs* the query URLs. The operator clicks what is relevant.
"""

from __future__ import annotations

import re
from urllib.parse import quote_plus

from ..models import ScanResult

GOOGLE = "https://www.google.com/search?q={q}"
BING = "https://www.bing.com/search?q={q}"
DUCK = "https://duckduckgo.com/?q={q}"

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_URL_RE = re.compile(r"^https?://", re.I)
_DOMAIN_RE = re.compile(r"^(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,}$")


def _g(query: str) -> str:
    return GOOGLE.format(q=quote_plus(query))


def _b(query: str) -> str:
    return BING.format(q=quote_plus(query))


def _domain_of(target: str) -> str:
    t = re.sub(r"^https?://", "", (target or "").strip()).split("/", 1)[0]
    return t.split("@", 1)[-1].lower()


def detect_kind(target: str) -> str:
    t = (target or "").strip()
    if _EMAIL_RE.match(t):
        return "email"
    if _URL_RE.match(t) or _DOMAIN_RE.match(t):
        return "domain"
    if " " in t and len(t.split()) >= 2:
        return "name"
    return "username"


# ── Dork catalogues ───────────────────────────────────────────────

def _domain_dorks(target: str) -> list[tuple[str, str, str]]:
    d = _domain_of(target)
    rows: list[tuple[str, str, str]] = []

    def add(group, label, query):
        rows.append((group, label, _g(query)))

    # Documents
    for ft in ("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "txt"):
        add("Documents", f"filetype:{ft}", f"site:{d} filetype:{ft}")
    # Login / admin surfaces
    add("Login / admin", "inurl:admin", f"site:{d} inurl:admin")
    add("Login / admin", "inurl:login", f"site:{d} inurl:login")
    add("Login / admin", "intitle:login", f'site:{d} intitle:"login"')
    add("Login / admin", "admin panel", f'site:{d} (inurl:admin | inurl:dashboard | inurl:portal)')
    # Open directory listings
    add("Directory listing", 'intitle:"index of"', f'site:{d} intitle:"index of"')
    add("Directory listing", "parent directory", f'site:{d} intitle:"index of" "parent directory"')
    # Config / secrets / backups
    for ext in ("env", "ini", "conf", "config", "yml", "yaml", "json", "sql",
                "bak", "old", "log", "backup"):
        add("Config / secrets", f"ext:{ext}", f"site:{d} ext:{ext}")
    add("Config / secrets", "db password", f'site:{d} intext:"db_password" | intext:"DB_PASSWORD"')
    add("Config / secrets", "api key", f'site:{d} intext:"api_key" | intext:"apikey"')
    add("Config / secrets", "archives", f"site:{d} (ext:zip | ext:rar | ext:tar | ext:gz | ext:7z)")
    # Exposed VCS / dev
    add("VCS / dev", ".git exposure", f"site:{d} inurl:.git")
    add("VCS / dev", ".env exposure", f"site:{d} inurl:.env")
    add("VCS / dev", "phpinfo", f'site:{d} intitle:"phpinfo()"')
    add("VCS / dev", "wp-content", f"site:{d} inurl:wp-content")
    # Errors / debug leaks
    add("Errors / debug", "sql errors", f'site:{d} intext:"sql syntax near" | intext:"mysql_fetch"')
    add("Errors / debug", "stack traces", f'site:{d} intext:"Warning:" | intext:"Fatal error:"')
    # Subdomains
    add("Subdomains", "site:*.domain", f"site:*.{d} -www")
    # Parameters (potential injection points — for an authorised tester to review)
    add("Parameters", "url/redirect params", f"site:{d} (inurl:redirect | inurl:url= | inurl:return=)")
    add("Parameters", "id/query params", f"site:{d} (inurl:id= | inurl:page= | inurl:query=)")
    # Third-party / off-site leaks
    rows.append(("Off-site leaks", "Pastebin", _g(f'site:pastebin.com "{d}"')))
    rows.append(("Off-site leaks", "GitHub", _g(f'site:github.com "{d}"')))
    rows.append(("Off-site leaks", "GitLab", _g(f'site:gitlab.com "{d}"')))
    rows.append(("Off-site leaks", "Trello", _g(f'site:trello.com "{d}"')))
    rows.append(("Off-site leaks", "S3 buckets", _g(f'site:s3.amazonaws.com "{d}"')))
    rows.append(("Off-site leaks", "Azure blobs", _g(f'site:blob.core.windows.net "{d}"')))
    rows.append(("Off-site leaks", "Google Drive", _g(f'site:drive.google.com "{d}"')))
    return rows


def _identity_dorks(target: str, kind: str) -> list[tuple[str, str, str]]:
    exact = f'"{target}"'
    rows: list[tuple[str, str, str]] = []
    rows.append(("Search engines", "Google (exact)", _g(exact)))
    rows.append(("Search engines", "Bing (exact)", _b(exact)))
    rows.append(("Search engines", "DuckDuckGo", DUCK.format(q=quote_plus(exact))))
    # Paste / leak sites
    for site in ("pastebin.com", "ghostbin.com", "paste.ee", "justpaste.it",
                 "controlc.com", "0bin.net"):
        rows.append(("Paste sites", site, _g(f'{exact} site:{site}')))
    # Code / repos
    for site in ("github.com", "gitlab.com", "raw.githubusercontent.com"):
        rows.append(("Code / repos", site, _g(f'{exact} site:{site}')))
    # Documents mentioning the identity
    rows.append(("Documents", "any document", _g(f'{exact} (filetype:pdf | filetype:xlsx | filetype:docx)')))
    if kind == "email":
        local = target.split("@", 1)[0]
        rows.append(("Breach context", "credential dumps", _g(f'{exact} (password | passwd | leak | dump)')))
        rows.append(("Breach context", "local-part as username", _g(f'"{local}"')))
    if kind == "name":
        rows.append(("Social", "LinkedIn", _g(f'{exact} site:linkedin.com')))
        rows.append(("Social", "Facebook", _g(f'{exact} site:facebook.com')))
        rows.append(("Social", "profiles", _g(f'{exact} (intitle:profile | inurl:profile)')))
    if kind == "username":
        rows.append(("Social", "mentions", _g(f'{exact} (site:twitter.com | site:reddit.com | site:instagram.com)')))
    return rows


async def scan(target: str, *, timeout: float = 5.0,
               kind: str | None = None) -> ScanResult:
    """Build search-engine dork links for *target* (no network requests)."""
    kind = kind or detect_kind(target)
    result = ScanResult(target=target, module="dorks")
    result.add("kind", "Dork target type", kind, "info")

    rows = _domain_dorks(target) if kind in ("domain", "url") \
        else _identity_dorks(target, kind)

    for group, label, url in rows:
        result.add(group, label, url, "info", url=url)

    result.raw["kind"] = kind
    result.raw["dork_count"] = len(rows)
    return result
