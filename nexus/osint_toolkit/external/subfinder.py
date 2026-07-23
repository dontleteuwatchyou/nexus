"""Subfinder — passive subdomain enumeration."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class Subfinder(ExternalTool):
    name = "subfinder"
    bin_name = "subfinder"
    accepted_kinds = {"domain"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 180.0,
        silent: bool = True,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "subfinder"
        args = [bin_path, "-d", target]
        if silent:
            args.append("-silent")

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"subfinder failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("["):
                result.add("subfinder", "Subdomain", line, "found")

        return result