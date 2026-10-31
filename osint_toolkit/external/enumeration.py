"""Linux enumeration scripts and shellcode tools."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class LinEnum(ExternalTool):
    name = "linenum"
    bin_name = "linenum"
    accepted_kinds = {"system", "file"}

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

        bin_path = shutil.which(cls.bin_name) or "linenum"
        args = [bin_path, target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"linenum failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line and ("sudo" in line or "SUID" in line or "config" in line or "password" in line):
                result.add("linenum", "Finding", line[:160], "found")

        return result


class LinuxSmartEnum(ExternalTool):
    name = "linux-smart-enumeration"
    bin_name = "linux-smart-enumeration"
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

        bin_path = shutil.which(cls.bin_name) or "linux-smart-enumeration"
        args = [bin_path, "-l", "0", target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"linux-smart-enumeration failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line and ("!" in line or "vulnerable" in line or "misconfig" in line):
                result.add("linux-smart-enumeration", "Finding", line[:160], "found")

        return result


class ShellNoob(ExternalTool):
    name = "shellnoob"
    bin_name = "shellnoob"
    accepted_kinds = {"file", "payload"}

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

        bin_path = shutil.which(cls.bin_name) or "shellnoob"
        args = [bin_path, "--to-asm", target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"shellnoob failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line:
                result.add("shellnoob", "Shellcode", line[:160], "found")

        return result
