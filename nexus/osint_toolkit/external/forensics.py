"""Autopsy / Volatility3 / Bulk Extractor / Binwalk — Forensics & Memory Analysis."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class Autopsy(ExternalTool):
    name = "autopsy"
    bin_name = "autopsy"
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
        result.add("autopsy", "Note", "Autopsy is a GUI-based digital forensics platform. Run manually: autopsy", "info")
        return result


class Volatility3(ExternalTool):
    name = "volatility3"
    bin_name = "volatility3"
    accepted_kinds = {"file"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 600.0,
        plugin: str = "windows.info",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "vol"
        args = [bin_path, "-f", target, plugin]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"volatility3 failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines()[:50]:
            if line.strip():
                result.add("volatility3", plugin, line[:160], "info")

        return result


class BulkExtractor(ExternalTool):
    name = "bulk_extractor"
    bin_name = "bulk_extractor"
    accepted_kinds = {"file", "disk"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 600.0,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "bulk_extractor"
        args = [bin_path, "-o", "/tmp/bulk_out", target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"bulk_extractor failed (rc={rc}): {stderr[:200]}")
            return result

        result.add("bulk_extractor", "Output", "Extracted features to /tmp/bulk_out", "found")
        return result


class Binwalk(ExternalTool):
    name = "binwalk"
    bin_name = "binwalk"
    accepted_kinds = {"file"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 300.0,
        extract: bool = False,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "binwalk"
        args = [bin_path, target]
        if extract:
            args.extend(["-e", "-C", "/tmp/binwalk_out"])

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"binwalk failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            if "DECIMAL" in line or "HEXADECIMAL" in line or "DESCRIPTION" in line:
                continue
            if line.strip() and any(c.isdigit() for c in line[:10]):
                result.add("binwalk", "Signature", line[:160], "found")

        return result