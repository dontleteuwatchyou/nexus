"""Crackle / Hash-Identifier / PSK-Crack / Sucrack /
THC-PPTP-Bruter / THC-SSL-DoS / Polenum / Fern-Wifi-Cracker —
Additional cracking & security testing tools."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class Crackle(ExternalTool):
    name = "crackle"
    bin_name = "crackle"
    accepted_kinds = {"file", "interface"}

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
        result.add("crackle", "Note", "Crackle is a BLE security testing tool. Run manually: crackle", "info")
        return result


class HashIdentifier(ExternalTool):
    name = "hash-identifier"
    bin_name = "hash-identifier"
    accepted_kinds = {"hash", "file"}

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

        bin_path = shutil.which(cls.bin_name) or "hash-identifier"
        args = [bin_path, target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"hash-identifier failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            result.add("hash-identifier", "Hash type", stripped[:200], "found")

        return result


class PskCrack(ExternalTool):
    name = "psk-crack"
    bin_name = "psk-crack"
    accepted_kinds = {"file"}

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

        bin_path = shutil.which(cls.bin_name) or "psk-crack"
        args = [bin_path, "-b", target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"psk-crack failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            result.add("psk-crack", "Result", stripped[:200], "info")

        return result


class Sucrack(ExternalTool):
    name = "sucrack"
    bin_name = "sucrack"
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
        result.add("sucrack", "Note", "Sucrack is a su brute force tool. Run manually: sucrack", "info")
        return result


class THCPptpBruter(ExternalTool):
    name = "thc-pptp-bruter"
    bin_name = "thc-pptp-bruter"
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

        bin_path = shutil.which(cls.bin_name) or "thc-pptp-bruter"
        args = [bin_path, "-W", target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"thc-pptp-bruter failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            result.add("thc-pptp-bruter", "Result", stripped[:200], "info")

        return result


class THCSslDos(ExternalTool):
    name = "thc-ssl-dos"
    bin_name = "thc-ssl-dos"
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
        result.add("thc-ssl-dos", "Note", "THC-SSL-DoS is a denial of service testing tool. Run manually: thc-ssl-dos", "info")
        return result


class PoleNum(ExternalTool):
    name = "polenum"
    bin_name = "polenum"
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

        bin_path = shutil.which(cls.bin_name) or "polenum"
        args = [bin_path, "-u", "", "-p", "", target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"polenum failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            result.add("polenum", "Policy", stripped[:200], "info")

        return result


class FernWifiCracker(ExternalTool):
    name = "fern-wifi-cracker"
    bin_name = "fern-wifi-cracker"
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
        result.add("fern-wifi-cracker", "Note", "Fern Wi-Fi Cracker is a GUI tool. Launch manually: fern-wifi-cracker", "info")
        return result
