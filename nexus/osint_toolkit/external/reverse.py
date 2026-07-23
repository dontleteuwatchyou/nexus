"""Ghidra / Radare2 / Rizin / GDB — Reverse Engineering."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class Ghidra(ExternalTool):
    name = "ghidra"
    bin_name = "ghidra"
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

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("ghidra", "Note", "Ghidra is a GUI-based reverse engineering suite. Run manually: ghidra", "info")
        return result


class Radare2(ExternalTool):
    name = "radare2"
    bin_name = "r2"
    accepted_kinds = {"file"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 120.0,
        commands: str = "aaa; afl; izz; iI; iS",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "r2"
        args = [bin_path, "-c", commands, target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"radare2 failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("["):
                result.add("radare2", "Analysis", line[:160], "info")

        return result


class Rizin(ExternalTool):
    name = "rizin"
    bin_name = "rizin"
    accepted_kinds = {"file"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 120.0,
        commands: str = "aaa; afl; izz; iI; iS",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "rizin"
        args = [bin_path, "-c", commands, target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"rizin failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("["):
                result.add("rizin", "Analysis", line[:160], "info")

        return result


class GDB(ExternalTool):
    name = "gdb"
    bin_name = "gdb"
    accepted_kinds = {"file", "pid"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 120.0,
        commands: str = "info files; info functions; info variables; quit",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "gdb"
        args = [bin_path, "-batch", "-ex", commands, target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"gdb failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            if line.strip():
                result.add("gdb", "Output", line[:160], "info")

        return result