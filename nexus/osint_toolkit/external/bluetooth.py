"""Bettercap / Bluetooth tools."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class Bettercap(ExternalTool):
    name = "bettercap"
    bin_name = "bettercap"
    accepted_kinds = {"interface", "ip", "domain"}

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

        bin_path = shutil.which(cls.bin_name) or "bettercap"
        args = [bin_path, "-eval", f"net.pentest on; net.show; wifi.pentest on; wifi.show; bluetooth.pentest on; bluetooth.show; quit"]

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("bettercap", "Note", "Bettercap is interactive. Use the eval command above or run manually with sudo.", "info")
        result.raw["command"] = " ".join(args)
        return result


class Bluelog(ExternalTool):
    name = "bluelog"
    bin_name = "bluelog"
    accepted_kinds = {"interface"}

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

        bin_path = shutil.which(cls.bin_name) or "bluelog"
        args = [bin_path, "-o", "/tmp/bluelog_out"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        return result


class BlueRanger(ExternalTool):
    name = "blueranger"
    bin_name = "blueranger"
    accepted_kinds = {"interface"}

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

        bin_path = shutil.which(cls.bin_name) or "blueranger"
        args = [bin_path, "-o", "/tmp/blueranger_out"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        return result