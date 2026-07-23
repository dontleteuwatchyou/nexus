"""Feroxbuster — fast recursive content discovery."""

from __future__ import annotations

import json
import shutil

from ..models import ScanResult
from .base import ExternalTool


class Feroxbuster(ExternalTool):
    name = "feroxbuster"
    bin_name = "feroxbuster"
    accepted_kinds = {"url", "domain"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 300.0,
        wordlist: str | None = None,
        extensions: str = "php,html,js,txt,json,xml,asp,aspx,jsp",
        depth: int = 2,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        if not wordlist:
            wordlist = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"

        bin_path = shutil.which(cls.bin_name) or "feroxbuster"
        args = [
            bin_path,
            "-u", target,
            "-w", wordlist,
            "-x", extensions,
            "-d", str(depth),
            "--json",
            "--silent",
            "-t", "50",
        ]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"feroxbuster failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                url = data.get("url", "")
                status = data.get("status", 0)
                length = data.get("content_length", 0)
                sev = "found" if 200 <= status < 400 else "warn"
                result.add("feroxbuster", f"Path [{status}]", f"{url} ({length}b)", sev, url=url)
            except json.JSONDecodeError:
                continue

        return result