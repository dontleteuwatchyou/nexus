"""Gobuster — directory/file/DNS busting tool."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class Gobuster(ExternalTool):
    name = "gobuster"
    bin_name = "gobuster"
    accepted_kinds = {"url", "domain"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 300.0,
        mode: str = "dir",
        wordlist: str | None = None,
        extensions: str = "php,html,js,txt,json,xml,asp,aspx,jsp",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        if not wordlist:
            if mode == "dir":
                wordlist = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
            elif mode == "dns":
                wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
            else:
                wordlist = "/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt"

        bin_path = shutil.which(cls.bin_name) or "gobuster"
        args = [
            bin_path,
            mode,
            "-u", target,
            "-w", wordlist,
            "-q",
            "-t", "50",
        ]

        if mode == "dir":
            args.extend(["-x", extensions])

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"gobuster failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line and ("Status:" in line or "Found:" in line):
                result.add("gobuster", mode.capitalize(), line, "found")

        return result