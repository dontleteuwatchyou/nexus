"""Hashdeep / Hashid / Hashrat / Ssdeep / Rsmangler / Pipal —
Additional hashing & password analysis tools."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class Hashdeep(ExternalTool):
    name = "hashdeep"
    bin_name = "hashdeep"
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

        bin_path = shutil.which(cls.bin_name) or "hashdeep"
        args = [bin_path, "-l", target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"hashdeep failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines()[:200]:
            if line.strip():
                result.add("hashdeep", "Hash", line[:200], "info")

        return result


class Hashid(ExternalTool):
    name = "hashid"
    bin_name = "hashid"
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

        bin_path = shutil.which(cls.bin_name) or "hashid"
        args = [bin_path, target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"hashid failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            if line.strip() and "]" in line:
                result.add("hashid", "Type", line[:160], "found")

        return result


class Hashrat(ExternalTool):
    name = "hashrat"
    bin_name = "hashrat"
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

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("hashrat", "Note", "Hashrat is a hash computation tool. Run manually: hashrat", "info")
        return result


class Ssdeep(ExternalTool):
    name = "ssdeep"
    bin_name = "ssdeep"
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

        bin_path = shutil.which(cls.bin_name) or "ssdeep"
        args = [bin_path, "-l", target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"ssdeep failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines()[:200]:
            if line.strip():
                result.add("ssdeep", "Fuzzy hash", line[:200], "info")

        return result


class Rsmangler(ExternalTool):
    name = "rsmangler"
    bin_name = "rsmangler"
    accepted_kinds = {"wordlist", "file"}

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

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("rsmangler", "Note", "Rsmangler is a wordlist mangler. Run manually: rsmangler", "info")
        return result


class Pipal(ExternalTool):
    name = "pipal"
    bin_name = "pipal"
    accepted_kinds = {"file", "wordlist"}

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

        bin_path = shutil.which(cls.bin_name) or "pipal"
        args = [bin_path, target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"pipal failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("Total") or stripped.startswith("Top") or "passwords" in stripped.lower():
                result.add("pipal", "Statistic", stripped[:200], "found")
            else:
                result.add("pipal", "Result", stripped[:200], "info")

        return result
