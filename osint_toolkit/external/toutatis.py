"""Toutatis — extract email + phone from Instagram profile (megadose/toutatis).

Repo:    https://github.com/megadose/toutatis
PyPI:    https://pypi.org/project/toutatis/
Install: pip install toutatis

Requires an Instagram session ID from a logged-in browser:
  $IG_SESSION_ID env var, or pass session_id="..." to scan().

Output: JSON. Useful for username → contact info pivoting.
"""

from __future__ import annotations

import json
import os
import shutil

from ..models import ScanResult
from .base import ExternalTool


class Toutatis(ExternalTool):
    name = "toutatis"
    pip_package = "toutatis"
    bin_name = "toutatis"
    accepted_kinds = {"username"}

    @classmethod
    async def scan(cls, target: str, *, session_id: str | None = None,
                    timeout: float = 30.0, **kwargs) -> ScanResult:
        # kwargs may include kind="unknown" — toutatis is username-only so ignore
        if not cls.is_installed():
            return cls._not_installed_result(target)

        sid = session_id or os.environ.get("IG_SESSION_ID")
        if not sid:
            result = ScanResult(target=target, module=f"external:{cls.name}")
            result.add("config", "Instagram session ID", "Missing", "warn")
            result.add("config", "How to provide",
                       "Set IG_SESSION_ID env var with your sessionid cookie",
                       "info")
            return result

        bin_path = shutil.which(cls.bin_name) or "toutatis"
        rc, stdout, stderr = await cls._run_subprocess(
            [bin_path, "-s", sid, "-u", target, "--json"],
            timeout=timeout,
        )

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:4000]

        if rc != 0 and not stdout.strip().startswith("{"):
            result.errors.append(f"toutatis failed (rc={rc}): {stderr[:200]}")
            return result

        # Try to parse JSON
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            # Fall back to scraping the textual output
            result.add("output", "Raw", stdout[:200], "info")
            return result

        result.raw["data"] = data
        user = data.get("user") or {}
        if not user:
            result.add("profile", "User", "Not found or session expired", "warn")
            return result

        result.add("profile", "Username", user.get("username", "?"), "found")
        if user.get("full_name"):
            result.add("profile", "Full name", user["full_name"], "warn")
        if user.get("biography"):
            result.add("profile", "Bio", user["biography"][:160], "info")
        if user.get("external_url"):
            result.add("profile", "External URL", user["external_url"], "info",
                       url=user["external_url"])
        if user.get("public_email"):
            result.add("contact", "Email (public)",
                       user["public_email"], "warn")
        if user.get("obfuscated_email"):
            result.add("contact", "Email (obfuscated)",
                       user["obfuscated_email"], "warn")
        if user.get("public_phone_number"):
            cc = user.get("public_phone_country_code", "")
            num = user["public_phone_number"]
            result.add("contact", "Phone", f"+{cc} {num}", "warn")
        if user.get("obfuscated_phone"):
            result.add("contact", "Phone (obfuscated)",
                       user["obfuscated_phone"], "warn")
        if user.get("is_business"):
            result.add("profile", "Account type", "Business", "info")
        if user.get("is_verified"):
            result.add("profile", "Verified", "Yes", "info")
        if user.get("follower_count") is not None:
            result.add("profile", "Followers",
                       str(user["follower_count"]), "info")
        if user.get("following_count") is not None:
            result.add("profile", "Following",
                       str(user["following_count"]), "info")

        return result
