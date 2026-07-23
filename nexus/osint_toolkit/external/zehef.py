"""Zehef — email-focused OSINT (N0rz3/Zehef).

Repo:    https://github.com/N0rz3/Zehef
PyPI:    https://pypi.org/project/zehef/
Install: pip install zehef

Commands: track (account check) and breach (data leaks).
Accepted inputs: email.
"""

from __future__ import annotations

import re
import shutil

from ..models import ScanResult
from .base import ExternalTool


class Zehef(ExternalTool):
    name = "Zehef"
    pip_package = "zehef"
    bin_name = "zehef"
    accepted_kinds = {"email"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 90.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "zehef"
        rc, stdout, stderr = await cls._run_subprocess(
            [bin_path, target], timeout=timeout,
        )

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:4000]

        clean = re.sub(r"\x1b\[[0-9;]*m", "", stdout)

        if rc != 0 and not clean.strip():
            result.errors.append(f"zehef failed (rc={rc}): {stderr[:200]}")
            return result

        # Zehef formats output with section headers and [+]/[-] tags.
        # Extract "registered on X" and "breach: X" lines.
        sites_registered = []
        breaches = []
        urls = sorted(set(re.findall(r"https?://[^\s\)\]]+", clean)))

        for line in clean.splitlines():
            l = line.strip()
            if not l:
                continue
            low = l.lower()
            if "[+]" in l and ("registered" in low or "found" in low or "exist" in low):
                sites_registered.append(l)
            if "breach" in low or "leak" in low or "compromised" in low:
                breaches.append(l)

        result.add("summary", "Run", "OK" if rc == 0 else f"rc={rc}",
                   "found" if rc == 0 else "warn")

        if sites_registered:
            result.add("accounts", "Sites with account",
                       str(len(sites_registered)), "warn")
            for s in sites_registered[:30]:
                result.add("accounts", "line", s[:160], "warn")

        if breaches:
            result.add("breaches", "Breach mentions", str(len(breaches)), "warn")
            for b in breaches[:15]:
                result.add("breaches", "line", b[:160], "warn")

        if urls:
            for u in urls[:20]:
                result.add("urls", u[:80], u, "info", url=u)

        return result
