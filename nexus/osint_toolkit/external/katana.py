"""Katana — next-generation crawling framework."""

from __future__ import annotations

import json
import shutil

from ..models import ScanResult
from .base import ExternalTool


class Katana(ExternalTool):
    name = "katana"
    bin_name = "katana"
    accepted_kinds = {"url", "domain"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 300.0,
        depth: int = 2,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "katana"
        args = [
            bin_path,
            "-u", target,
            "-d", str(depth),
            "-jc",  # javascript crawling
            "-kf",  # known files
            "-ef", "woff,css,png,svg,jpg,jpeg,gif,ico",
            "-silent",
            "-jsonl",
        ]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"katana failed (rc={rc}): {stderr[:200]}")
            return result

        urls = set()
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                url = data.get("url", "")
                if url and url not in urls:
                    urls.add(url)
                    result.add("katana", "URL", url, "found")
            except json.JSONDecodeError:
                continue

        result.add("katana", "Summary", f"Crawled {len(urls)} unique URLs", "info")
        return result