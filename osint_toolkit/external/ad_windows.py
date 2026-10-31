"""Chntpw / Samdump2 / Smbmap — Windows AD & credential tools."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class Chntpw(ExternalTool):
    name = "chntpw"
    bin_name = "chntpw"
    accepted_kinds = {"file", "disk"}

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
        result.add("chntpw", "Note", "Chntpw is an interactive Windows password reset tool. Run manually with sudo: chntpw /path/to/SAM", "info")
        return result


class Samdump2(ExternalTool):
    name = "samdump2"
    bin_name = "samdump2"
    accepted_kinds = {"file"}

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

        bin_path = shutil.which(cls.bin_name) or "samdump2"
        args = [bin_path, target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"samdump2 failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            if line.strip() and ":" in line:
                result.add("samdump2", "Hash", line[:200], "found")

        return result


class Smbmap(ExternalTool):
    name = "smbmap"
    bin_name = "smbmap"
    accepted_kinds = {"ip"}

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

        bin_path = shutil.which(cls.bin_name) or "smbmap"
        args = [bin_path, "-H", target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"smbmap failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            if "Disk" in line or "Perms" in line or "READ" in line or "WRITE" in line:
                result.add("smbmap", "Share", line[:200], "found")
            elif line.strip() and ":" in line:
                result.add("smbmap", "Entry", line[:200], "info")

        return result
