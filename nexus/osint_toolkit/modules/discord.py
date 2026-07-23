"""Passive Discord username/tag helper.

Discord does not expose an unauthenticated public endpoint for checking whether
a username exists.  This module therefore validates and normalises identifiers
locally, decodes public snowflake metadata, and prepares manual lookup pivots.
It never claims that a username is registered or available.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from urllib.parse import quote_plus

from ..models import ScanResult

DISCORD_EPOCH_MS = 1_420_070_400_000
SNOWFLAKE_RE = re.compile(r"^\d{17,20}$")
LEGACY_TAG_RE = re.compile(r"^(.{2,32})#(\d{4})$")
USERNAME_RE = re.compile(r"^[a-z0-9._]{2,32}$")


def classify(value: str) -> tuple[str, str]:
    """Return ``(kind, normalized_value)`` for a Discord identifier."""
    target = (value or "").strip()
    if SNOWFLAKE_RE.fullmatch(target):
        return "snowflake", target

    legacy = LEGACY_TAG_RE.fullmatch(target)
    if legacy and not any(ord(char) < 32 for char in legacy.group(1)):
        return "legacy-tag", target

    username = target.removeprefix("@").lower()
    if USERNAME_RE.fullmatch(username) and ".." not in username:
        return "username", username

    return "invalid", target


def snowflake_created_at(value: str) -> str:
    """Decode the creation timestamp embedded in a Discord snowflake."""
    timestamp_ms = (int(value) >> 22) + DISCORD_EPOCH_MS
    return datetime.fromtimestamp(timestamp_ms / 1000, timezone.utc).isoformat()


async def scan(target: str, *, timeout: float = 5.0) -> ScanResult:
    """Validate a Discord identifier and prepare passive/manual pivots."""
    del timeout  # No network request is made by this module.
    kind, normalized = classify(target)
    result = ScanResult(target=target, module="discord")
    result.raw.update({"kind": kind, "normalized": normalized})

    if kind == "invalid":
        result.errors.append(
            "Invalid Discord identifier: expected @username, username#1234, or a 17–20 digit user ID"
        )
        return result

    labels = {
        "username": "New Discord username",
        "legacy-tag": "Legacy Discord tag",
        "snowflake": "Discord user ID (snowflake)",
    }
    result.add("discord", "Identifier type", labels[kind], "found")
    result.add("discord", "Normalized value", normalized, "info")

    if kind == "snowflake":
        created_at = snowflake_created_at(normalized)
        result.raw["snowflake_created_at"] = created_at
        result.add(
            "snowflake",
            "Embedded creation time",
            created_at,
            "info",
        )
        lookup_url = f"https://discordlookup.com/user/{normalized}"
        result.add("manual lookup", "DiscordLookup", lookup_url, "info", url=lookup_url)

    prefill = quote_plus(normalized)
    discord_id_url = f"https://discord.id/?prefill={prefill}"
    result.add("manual lookup", "discord.id", discord_id_url, "info", url=discord_id_url)

    exact = quote_plus(f'"{normalized}" Discord')
    google_url = f"https://www.google.com/search?q={exact}"
    result.add("public search", "Exact web search", google_url, "info", url=google_url)
    result.add(
        "limitations",
        "Existence / availability",
        "Not verifiable through Discord's unauthenticated public API",
        "warn",
    )
    result.add(
        "limitations",
        "Identity warning",
        "A matching tag or username does not prove that two accounts belong to the same person",
        "warn",
    )
    return result
