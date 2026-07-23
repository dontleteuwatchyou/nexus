"""Assetfinder — find domains and subdomains."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class Assetfinder(ExternalTool):
    name = "assetfinder"
    bin_name = "assetfinder"
    accepted_kinds = {"domain"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 120.0,
        subs_only: bool = True,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "assetfinder"
        args = [bin_path]
        if subs_only:
            args.append("--subs-only")
        args.append(target)

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"assetfinder failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line:
                result.add("assetfinder", "Asset", line, "found")

        return result