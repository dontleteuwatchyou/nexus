"""FFUF — fast web fuzzer."""

from __future__ import annotations

import json
import shutil

from ..models import ScanResult
from .base import ExternalTool


class FFUF(ExternalTool):
    name = "ffuf"
    bin_name = "ffuf"
    accepted_kinds = {"url", "domain"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 300.0,
        wordlist: str | None = None,
        extensions: str = "php,html,js,txt,json,xml,asp,aspx,jsp",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        if not wordlist:
            wordlist = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"

        bin_path = shutil.which(cls.bin_name) or "ffuf"
        args = [
            bin_path,
            "-u", f"{target}/FUZZ",
            "-w", wordlist,
            "-e", extensions,
            "-json",
            "-silent",
            "-t", "50",
            "-timeout", "10",
        ]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"ffuf failed (rc={rc}): {stderr[:200]}")
            return result

        try:
            data = json.loads(stdout)
            for item in data.get("results", []):
                url = item.get("url", "")
                status = item.get("status", 0)
                length = item.get("length", 0)
                words = item.get("words", 0)
                sev = "found" if 200 <= status < 400 else "warn"
                result.add("ffuf", f"Dir [{status}]", f"{url} ({length}b, {words}w)", sev, url=url)
        except json.JSONDecodeError:
            pass

        return result