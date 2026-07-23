"""GitHub OSINT — user profile, repos, activity, leaked emails.

Uses the public GitHub API (no auth, 60 req/h rate limit). For deeper
inspection, set GH_TOKEN env var (auto-detected).

Surfaces:
  • Public profile (name, bio, location, email, hire status)
  • Repository count, stars, forks
  • Most-starred repos
  • Activity (recent push events)
  • Email leak via the `users/{user}/events/public` PushEvent commits
  • Public gists
  • SSH / GPG keys (public via /users/{user}/keys)
  • Linked organisations
"""

from __future__ import annotations

import asyncio
import os
import re
from typing import Optional

import httpx

from ..http import get_json, session
from ..models import ScanResult


USERNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$")
NOREPLY_EMAIL_RE = re.compile(r"(\d+)\+([\w.\-]+)@users\.noreply\.github\.com",
                               re.IGNORECASE)


def is_valid(username: str) -> bool:
    return bool(USERNAME_RE.match(username or ""))


def _auth_headers() -> dict:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        return {"Authorization": f"token {token}",
                "Accept": "application/vnd.github+json"}
    return {"Accept": "application/vnd.github+json"}


# ── Sources ───────────────────────────────────────────────────────

async def _profile(client: httpx.AsyncClient, username: str) -> dict | None:
    return await get_json(
        client, f"https://api.github.com/users/{username}",
        headers=_auth_headers(), timeout=12,
    )


async def _repos(client: httpx.AsyncClient, username: str) -> list | None:
    j = await get_json(
        client,
        f"https://api.github.com/users/{username}/repos?per_page=100&sort=updated",
        headers=_auth_headers(), timeout=15,
    )
    return j if isinstance(j, list) else None


async def _gists(client: httpx.AsyncClient, username: str) -> list | None:
    j = await get_json(
        client, f"https://api.github.com/users/{username}/gists?per_page=30",
        headers=_auth_headers(), timeout=12,
    )
    return j if isinstance(j, list) else None


async def _events(client: httpx.AsyncClient, username: str) -> list | None:
    j = await get_json(
        client,
        f"https://api.github.com/users/{username}/events/public?per_page=30",
        headers=_auth_headers(), timeout=12,
    )
    return j if isinstance(j, list) else None


async def _ssh_keys(client: httpx.AsyncClient, username: str) -> str | None:
    """Public SSH keys — GitHub exposes them at /username.keys (plain text)."""
    try:
        r = await client.get(f"https://github.com/{username}.keys", timeout=10)
        if r.status_code == 200 and r.text:
            return r.text
    except Exception:
        return None
    return None


async def _gpg_keys(client: httpx.AsyncClient, username: str) -> str | None:
    """Public GPG keys via /username.gpg."""
    try:
        r = await client.get(f"https://github.com/{username}.gpg", timeout=10)
        if r.status_code == 200 and r.text and "PGP" in r.text:
            return r.text
    except Exception:
        return None
    return None


async def _orgs(client: httpx.AsyncClient, username: str) -> list | None:
    j = await get_json(
        client, f"https://api.github.com/users/{username}/orgs",
        headers=_auth_headers(), timeout=10,
    )
    return j if isinstance(j, list) else None


# ── Email extraction from PushEvents ───────────────────────────

def _emails_from_events(events: list) -> set[tuple[str, str]]:
    """Pull commit author emails from PushEvent commits.

    Returns set of (email, source_repo) tuples. Filters GitHub noreply but
    keeps the real-user noreply form (`12345+user@users.noreply.github.com`)
    as a soft positive (still ties an identity to a GitHub account).
    """
    found: set[tuple[str, str]] = set()
    for e in events or []:
        if e.get("type") != "PushEvent":
            continue
        repo = (e.get("repo") or {}).get("name", "?")
        payload = e.get("payload") or {}
        for commit in payload.get("commits") or []:
            author = (commit.get("author") or {}).get("email")
            if not author:
                continue
            found.add((author.lower(), repo))
    return found


# ── Orchestrator ──────────────────────────────────────────────

async def scan(username: str, *, timeout: float = 25.0) -> ScanResult:
    result = ScanResult(target=username, module="github")

    if not is_valid(username):
        result.errors.append(f"Invalid GitHub username: {username}")
        return result

    async with session(timeout=timeout) as client:
        profile, repos, gists, events, ssh, gpg, orgs = await asyncio.gather(
            _profile(client, username),
            _repos(client, username),
            _gists(client, username),
            _events(client, username),
            _ssh_keys(client, username),
            _gpg_keys(client, username),
            _orgs(client, username),
            return_exceptions=True,
        )

    def safe(x):
        return x if not isinstance(x, Exception) else None
    profile, repos, gists, events, ssh, gpg, orgs = map(
        safe, (profile, repos, gists, events, ssh, gpg, orgs)
    )

    # ── Profile ─────────────────────────────────────────────
    if not profile or not isinstance(profile, dict) or "login" not in profile:
        result.add("profile", "Account", "Not found or rate-limited", "warn")
        result.errors.append("GitHub user lookup failed (404 or rate limit)")
        return result

    result.raw["profile"] = profile
    result.add("profile", "Login", profile.get("login", "?"), "found",
               url=profile.get("html_url"))
    if profile.get("name"):
        result.add("profile", "Name", profile["name"], "warn")
    if profile.get("email"):
        result.add("profile", "Email (public)", profile["email"], "warn")
    if profile.get("company"):
        result.add("profile", "Company", profile["company"], "warn")
    if profile.get("location"):
        result.add("profile", "Location", profile["location"], "warn")
    if profile.get("blog"):
        result.add("profile", "Blog", profile["blog"], "info", url=profile["blog"])
    if profile.get("twitter_username"):
        tw = profile["twitter_username"]
        result.add("profile", "Twitter", tw, "warn", url=f"https://x.com/{tw}")
    if profile.get("bio"):
        result.add("profile", "Bio", profile["bio"][:160], "info")
    if profile.get("hireable"):
        result.add("profile", "Hireable", "Yes", "info")
    result.add("profile", "Public repos",
               str(profile.get("public_repos", 0)), "info")
    result.add("profile", "Public gists",
               str(profile.get("public_gists", 0)), "info")
    result.add("profile", "Followers",
               str(profile.get("followers", 0)), "info")
    if profile.get("created_at"):
        result.add("profile", "Created", profile["created_at"][:10], "info")
    if profile.get("updated_at"):
        result.add("profile", "Last update", profile["updated_at"][:10], "info")

    # ── Repos ─────────────────────────────────────────────
    if isinstance(repos, list) and repos:
        result.raw["repos"] = [{"name": r.get("name"), "stars": r.get("stargazers_count"),
                                 "lang": r.get("language"), "fork": r.get("fork")}
                                for r in repos]
        non_fork = [r for r in repos if not r.get("fork")]
        total_stars = sum(r.get("stargazers_count", 0) for r in repos)
        result.add("repos", "Total (incl. forks)", str(len(repos)), "info")
        result.add("repos", "Own (non-fork)", str(len(non_fork)), "info")
        result.add("repos", "Total stars", str(total_stars), "info")
        # Top 5 by stars
        top = sorted(non_fork, key=lambda r: r.get("stargazers_count", 0),
                      reverse=True)[:5]
        for r in top:
            label = r.get("name", "?")
            stars = r.get("stargazers_count", 0)
            lang  = r.get("language", "?")
            val = f"⭐ {stars}  ·  {lang}  ·  {r.get('description', '')[:80]}"
            result.add("top repos", label, val, "info",
                       url=r.get("html_url"))

    # ── Gists ─────────────────────────────────────────────
    if isinstance(gists, list) and gists:
        result.raw["gists"] = len(gists)
        result.add("gists", "Public gists", str(len(gists)), "info")
        for g in gists[:5]:
            desc = (g.get("description") or "")[:80]
            result.add("gists", "Gist", desc or "(no description)", "info",
                       url=g.get("html_url"))

    # ── Email leak via PushEvents ─────────────────────────
    if isinstance(events, list):
        emails = _emails_from_events(events)
        result.raw["commit_emails"] = sorted(emails)
        result.raw["events_count"] = len(events)
        if emails:
            result.add("commits", "Distinct emails in commits",
                       str(len(emails)), "warn")
            for email, repo in sorted(emails)[:10]:
                m = NOREPLY_EMAIL_RE.search(email)
                if m:
                    sev = "info"
                    note = f"noreply (id={m.group(1)}, user={m.group(2)})"
                    result.add("commits", email, f"{note} · in {repo}", sev)
                else:
                    sev = "warn"
                    result.add("commits", email, f"in {repo}", sev)

    # ── SSH / GPG keys ────────────────────────────────────
    if ssh:
        keys = [k for k in ssh.splitlines() if k.strip()]
        result.raw["ssh_keys_count"] = len(keys)
        result.add("keys", "Public SSH keys", str(len(keys)), "info",
                   url=f"https://github.com/{username}.keys")
        for k in keys[:3]:
            parts = k.split()
            if len(parts) >= 2:
                ktype = parts[0]
                fingerprint = parts[1][:30] + "..."
                result.add("keys", ktype, fingerprint, "info")
    if gpg:
        result.raw["gpg_keys"] = True
        result.add("keys", "Public GPG keys", "Yes", "info",
                   url=f"https://github.com/{username}.gpg")

    # ── Orgs ──────────────────────────────────────────────
    if isinstance(orgs, list) and orgs:
        result.raw["orgs"] = [o.get("login") for o in orgs]
        result.add("orgs", "Public organisations", str(len(orgs)), "warn")
        for o in orgs[:10]:
            login = o.get("login", "?")
            result.add("orgs", login, o.get("description", "")[:80] or "",
                       "warn", url=f"https://github.com/{login}")

    return result
