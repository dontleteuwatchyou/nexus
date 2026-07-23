"""WaybackURLs — Wayback Machine URL discovery."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class WaybackURLs(ExternalTool):
    name = "waybackurls"
    bin_name = "waybackurls"
    accepted_kinds = {"domain", "url"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 120.0,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "waybackurls"
        args = [bin_path, target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"waybackurls failed (rc={rc}): {stderr[:200]}")
            return result

        urls = set()
        for line in stdout.splitlines():
            line = line.strip()
            if line and line not in urls:
                urls.add(line)
                result.add("waybackurls", "URL", line, "found")

        result.add("waybackurls", "Summary", f"Found {len(urls)} Wayback Machine URLs", "info")
        return result