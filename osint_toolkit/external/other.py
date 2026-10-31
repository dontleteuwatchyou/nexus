"""Chkrootkit / Lynis / Unhide / Xspy / Yersinia / Macchanger /
Socat / Netmask / Pwnat — Miscellaneous system & network tools."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class Chkrootkit(ExternalTool):
    name = "chkrootkit"
    bin_name = "chkrootkit"
    accepted_kinds = {"system"}

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

        bin_path = shutil.which(cls.bin_name) or "chkrootkit"
        args = [bin_path, "-q"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"chkrootkit failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if "INFECTED" in stripped or "detected" in stripped.lower():
                result.add("chkrootkit", "Alert", stripped[:200], "error")
            elif "not infected" in stripped.lower() or "not found" in stripped.lower():
                result.add("chkrootkit", "Check", stripped[:200], "info")
            else:
                result.add("chkrootkit", "Result", stripped[:200], "info")

        return result


class Lynis(ExternalTool):
    name = "lynis"
    bin_name = "lynis"
    accepted_kinds = {"system"}

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

        bin_path = shutil.which(cls.bin_name) or "lynis"
        args = [bin_path, "audit", "system", "-q"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"lynis failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if "[WARNING]" in stripped or "[ERROR]" in stripped:
                result.add("lynis", "Alert", stripped[:200], "error")
            elif "[SUGGESTION]" in stripped:
                result.add("lynis", "Suggestion", stripped[:200], "warn")
            else:
                result.add("lynis", "Result", stripped[:200], "info")

        return result


class Unhide(ExternalTool):
    name = "unhide"
    bin_name = "unhide"
    accepted_kinds = {"system"}

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

        bin_path = shutil.which(cls.bin_name) or "unhide"
        args = [bin_path, "quick"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"unhide failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            result.add("unhide", "Result", stripped[:200], "info")

        return result


class Xspy(ExternalTool):
    name = "xspy"
    bin_name = "xspy"
    accepted_kinds = {"system"}

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
        result.add("xspy", "Note", "Xspy is an X11 keylogger requiring display access. Run manually: xspy", "warn")
        return result


class Yersinia(ExternalTool):
    name = "yersinia"
    bin_name = "yersinia"
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
        result.add("yersinia", "Note", "Yersinia is an interactive layer 2 attack tool. Run manually: yersinia -I", "info")
        return result


class Macchanger(ExternalTool):
    name = "macchanger"
    bin_name = "macchanger"
    accepted_kinds = {"interface"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 30.0,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "macchanger"
        args = [bin_path, "-s", target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"macchanger failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            result.add("macchanger", "MAC info", stripped[:200], "info")

        return result


class Socat(ExternalTool):
    name = "socat"
    bin_name = "socat"
    accepted_kinds = {"ip", "port"}

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
        result.add("socat", "Note", "Socat is a flexible multipurpose relay tool. Run manually: socat", "info")
        return result


class Netmask(ExternalTool):
    name = "netmask"
    bin_name = "netmask"
    accepted_kinds = {"ip"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 30.0,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "netmask"
        args = [bin_path, target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"netmask failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            stripped = line.strip()
            if stripped:
                result.add("netmask", "Mask", stripped[:200], "info")

        return result


class Pwnat(ExternalTool):
    name = "pwnat"
    bin_name = "pwnat"
    accepted_kinds = {"ip"}

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
        result.add("pwnat", "Note", "Pwnat is a NAT traversal tunnel tool. Run manually: pwnat", "info")
        return result
