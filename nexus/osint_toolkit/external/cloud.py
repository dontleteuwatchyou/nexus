"""Prowler / Pacu — Cloud security auditing."""

from __future__ import annotations

import json
import shutil

from ..models import ScanResult
from .base import ExternalTool


class Prowler(ExternalTool):
    name = "prowler"
    bin_name = "prowler"
    accepted_kinds = {"aws", "azure", "gcp"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 600.0,
        provider: str = "aws",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "prowler"
        args = [bin_path, "-P", provider, "-M", "json-asff", "-o", "/tmp/prowler_out"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"prowler failed (rc={rc}): {stderr[:200]}")
            return result

        result.add("prowler", "Status", "Scan completed. Check /tmp/prowler_out for detailed results.", "found")
        return result


class Pacu(ExternalTool):
    name = "pacu"
    bin_name = "pacu"
    accepted_kinds = {"aws"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 60.0,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("pacu", "Note", "Pacu is an interactive AWS exploitation framework. Run manually: pacu", "info")
        return result