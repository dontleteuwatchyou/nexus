"""Aircrack-ng suite — WiFi security auditing."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class AircrackNg(ExternalTool):
    name = "aircrack-ng"
    bin_name = "aircrack-ng"
    accepted_kinds = {"interface"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 300.0,
        bssid: str = "",
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "aircrack-ng"
        args = [bin_path, "-w", wordlist]

        if bssid:
            args.extend(["-b", bssid])

        args.append(target)

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"aircrack-ng failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            if "KEY FOUND" in line or "FOUND" in line:
                result.add("aircrack-ng", "Key Found", line[:160], "error")
            elif "WPA" in line or "WEP" in line:
                result.add("aircrack-ng", "Progress", line[:160], "warn")

        return result


class Airgeddon(ExternalTool):
    name = "airgeddon"
    bin_name = "airgeddon"
    accepted_kinds = {"interface"}

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
        result.add("airgeddon", "Note", "Airgeddon is an interactive menu-driven tool. Run manually: sudo airgeddon", "info")
        return result


class Wifite(ExternalTool):
    name = "wifite"
    bin_name = "wifite"
    accepted_kinds = {"interface"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 300.0,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "wifite"
        args = [bin_path, "-i", target, "--crack", "--dict", "/usr/share/wordlists/rockyou.txt"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"wifite failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            if "cracked" in line.lower() or "key" in line.lower() or "handshake" in line.lower():
                result.add("wifite", "Result", line[:160], "warn")

        return result