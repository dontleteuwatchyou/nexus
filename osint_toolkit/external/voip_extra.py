"""SIPVicious — Svmap / Svwar / Svcrack / Svreport / Svcrash — SIP testing tools."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class Svmap(ExternalTool):
    name = "sipvicious-svmap"
    bin_name = "svmap"
    accepted_kinds = {"ip", "domain"}

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

        bin_path = shutil.which(cls.bin_name) or "svmap"
        args = [bin_path, target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"svmap failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line:
                result.add("svmap", "Output", line[:200], "info")

        return result


class Svwar(ExternalTool):
    name = "sipvicious-svwar"
    bin_name = "svwar"
    accepted_kinds = {"ip", "domain"}

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

        bin_path = shutil.which(cls.bin_name) or "svwar"
        args = [bin_path, target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"svwar failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line:
                result.add("svwar", "Output", line[:200], "info")

        return result


class Svcrack(ExternalTool):
    name = "sipvicious-svcrack"
    bin_name = "svcrack"
    accepted_kinds = {"ip", "domain"}

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

        bin_path = shutil.which(cls.bin_name) or "svcrack"
        args = [bin_path, target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"svcrack failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line:
                result.add("svcrack", "Output", line[:200], "info")

        return result


class Svreport(ExternalTool):
    name = "sipvicious-svreport"
    bin_name = "svreport"
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

        bin_path = shutil.which(cls.bin_name) or "svreport"
        args = [bin_path, target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"svreport failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line:
                result.add("svreport", "Output", line[:200], "info")

        return result


class Svcrash(ExternalTool):
    name = "sipvicious-svcrash"
    bin_name = "svcrash"
    accepted_kinds = {"ip", "domain"}

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
        result.add("svcrash", "Note", "Svcrash is a SIP DoS tool. Run manually with caution: svcrash", "warn")
        return result
