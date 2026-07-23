"""Frida / Objection / JADX / APKTool — Mobile app analysis."""

from __future__ import annotations

import json
import shutil

from ..models import ScanResult
from .base import ExternalTool


class Frida(ExternalTool):
    name = "frida"
    bin_name = "frida"
    accepted_kinds = {"package", "process"}

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

        bin_path = shutil.which(cls.bin_name) or "frida"
        args = [bin_path, "-U", "-f", target]

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("frida", "Note", "Frida is a dynamic instrumentation toolkit. Use 'frida -U -f <package>' or Objection for interactive analysis.", "info")
        result.raw["command"] = " ".join(args)
        return result


class Objection(ExternalTool):
    name = "objection"
    bin_name = "objection"
    accepted_kinds = {"package"}

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

        bin_path = shutil.which(cls.bin_name) or "objection"
        args = [bin_path, "--gadget", target, "explore", "-q", "quit"]

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("objection", "Note", "Objection provides interactive runtime exploration. Run manually: objection --gadget <package> explore", "info")
        result.raw["command"] = " ".join(args)
        return result


class JADX(ExternalTool):
    name = "jadx"
    bin_name = "jadx"
    accepted_kinds = {"file"}

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

        bin_path = shutil.which(cls.bin_name) or "jadx"
        args = [bin_path, "-d", "/tmp/jadx_out", target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"jadx failed (rc={rc}): {stderr[:200]}")
            return result

        result.add("jadx", "Output", f"Decompiled to /tmp/jadx_out", "found")
        return result


class APKTool(ExternalTool):
    name = "apktool"
    bin_name = "apktool"
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

        bin_path = shutil.which(cls.bin_name) or "apktool"
        args = [bin_path, "d", target, "-o", "/tmp/apktool_out", "-f"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"apktool failed (rc={rc}): {stderr[:200]}")
            return result

        result.add("apktool", "Output", f"Decoded to /tmp/apktool_out", "found")
        return result


class BytecodeViewer(ExternalTool):
    name = "bytecode-viewer"
    bin_name = "bytecode-viewer"
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
        result.add("bytecode-viewer", "Note", "Bytecode Viewer is a GUI application. Run manually: java -jar bytecode-viewer.jar", "info")
        return result