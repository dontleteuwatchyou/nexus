"""Dirb / Dirsearch / TruffleHog / Gitleaks — Web fuzzing & secret scanning."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class Dirb(ExternalTool):
    name = "dirb"
    bin_name = "dirb"
    accepted_kinds = {"url", "domain"}

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

        bin_path = shutil.which(cls.bin_name) or "dirb"
        args = [
            bin_path,
            target,
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "-r",
        ]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"dirb failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("==>"):
                result.add("dirb", "Discovered", stripped[3:].strip(), "found")
            elif "+" in stripped and "CODE:" in stripped:
                result.add("dirb", "Path", stripped[:200], "info")

        return result


class Dirsearch(ExternalTool):
    name = "dirsearch"
    bin_name = "dirsearch"
    accepted_kinds = {"url", "domain"}

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

        bin_path = shutil.which(cls.bin_name) or "dirsearch"
        args = [
            bin_path,
            "-u", target,
            "-e",
            "--deep-recursive",
            "--max-recursion-depth=2",
        ]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"dirsearch failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if "[" in stripped and ("]" in stripped):
                result.add("dirsearch", "Result", stripped[:200], "info")

        return result


class Trufflehog(ExternalTool):
    name = "trufflehog"
    bin_name = "trufflehog"
    accepted_kinds = {"url", "file"}

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

        bin_path = shutil.which(cls.bin_name) or "trufflehog"
        args = [bin_path, "filesystem", target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"trufflehog failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if "Detected" in stripped or "Secret" in stripped:
                result.add("trufflehog", "Secret", stripped[:200], "found")
            else:
                result.add("trufflehog", "Result", stripped[:200], "info")

        return result


class Gitleaks(ExternalTool):
    name = "gitleaks"
    bin_name = "gitleaks"
    accepted_kinds = {"url", "file"}

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

        bin_path = shutil.which(cls.bin_name) or "gitleaks"
        args = [bin_path, "detect", "-s", target, "-v"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"gitleaks failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if "leak" in stripped.lower() or "secret" in stripped.lower():
                result.add("gitleaks", "Leak", stripped[:200], "found")
            else:
                result.add("gitleaks", "Result", stripped[:200], "info")

        return result
