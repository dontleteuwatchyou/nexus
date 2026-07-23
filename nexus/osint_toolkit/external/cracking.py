"""Hashcat / John / FCrackZip / Crunch — Password & Hash Cracking."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class Hashcat(ExternalTool):
    name = "hashcat"
    bin_name = "hashcat"
    accepted_kinds = {"hash", "file"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 600.0,
        mode: int = 0,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "hashcat"
        args = [bin_path, "-m", str(mode), target, wordlist, "--force", "--show"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        for line in stdout.splitlines():
            if ":" in line and len(line) > 10:
                result.add("hashcat", "Cracked", line[:160], "error")

        result.add("hashcat", "Status", f"Hashcat completed (rc={rc})", "info")
        return result


class John(ExternalTool):
    name = "john"
    bin_name = "john"
    accepted_kinds = {"hash", "file"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 600.0,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        format: str = "",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "john"
        args = [bin_path, "--wordlist=" + wordlist, target]

        if format:
            args.insert(0, f"--format={format}")

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        for line in stdout.splitlines():
            if "(" in line and ")" in line and ":" in line:
                result.add("john", "Cracked", line[:160], "error")

        result.add("john", "Status", f"John completed (rc={rc})", "info")
        return result


class Fcrackzip(ExternalTool):
    name = "fcrackzip"
    bin_name = "fcrackzip"
    accepted_kinds = {"file"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 300.0,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "fcrackzip"
        args = [bin_path, "-D", "-p", wordlist, target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        for line in stdout.splitlines():
            if "PASSWORD" in line or "password" in line:
                result.add("fcrackzip", "Password", line[:160], "error")

        return result


class Crunch(ExternalTool):
    name = "crunch"
    bin_name = "crunch"
    accepted_kinds = {"wordlist"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 180.0,
        min_len: int = 6,
        max_len: int = 8,
        charset: str = "abcdefghijklmnopqrstuvwxyz0123456789",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "crunch"
        args = [bin_path, str(min_len), str(max_len), charset, "-o", "/tmp/crunch_wordlist.txt"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc == 0:
            result.add("crunch", "Output", "Wordlist generated at /tmp/crunch_wordlist.txt", "found")
        else:
            result.errors.append(f"crunch failed (rc={rc}): {stderr[:200]}")

        return result