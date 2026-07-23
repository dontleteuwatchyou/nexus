"""Hydra / Medusa / Ncrack / Crowbar / Patator — brute force login tools."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class Hydra(ExternalTool):
    name = "hydra"
    bin_name = "hydra"
    accepted_kinds = {"ip", "domain", "url"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 300.0,
                   service: str = "ssh", username: str = "root",
                   wordlist: str = "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
                   **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        bin_path = shutil.which(cls.bin_name) or "hydra"
        args = [bin_path, "-l", username, "-P", wordlist, target, service, "-o", "/tmp/hydra_out.txt", "-q"]
        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]
        if rc != 0 and not stdout.strip():
            result.errors.append(f"hydra failed (rc={rc}): {stderr[:200]}")
            return result
        for line in stdout.splitlines():
            line = line.strip()
            if "password" in line.lower() or "login" in line.lower() or "host" in line.lower():
                if ":" in line and len(line) < 200:
                    result.add("hydra", "Credential", line, "error")
        return result


class Medusa(ExternalTool):
    name = "medusa"
    bin_name = "medusa"
    accepted_kinds = {"ip", "domain"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 300.0,
                   service: str = "ssh", username: str = "root",
                   wordlist: str = "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
                   **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        bin_path = shutil.which(cls.bin_name) or "medusa"
        args = [bin_path, "-h", target, "-u", username, "-P", wordlist, "-M", service, "-q", "-O", "/tmp/medusa_out.txt"]
        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]
        if rc != 0 and not stdout.strip():
            result.errors.append(f"medusa failed (rc={rc}): {stderr[:200]}")
            return result
        for line in stdout.splitlines():
            if "ACCOUNT FOUND" in line or "SUCCESS" in line:
                result.add("medusa", "Credential", line[:160], "error")
        return result


class Ncrack(ExternalTool):
    name = "ncrack"
    bin_name = "ncrack"
    accepted_kinds = {"ip", "domain"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 300.0,
                   service: str = "ssh", wordlist: str = "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
                   **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        bin_path = shutil.which(cls.bin_name) or "ncrack"
        args = [bin_path, f"{service}://{target}", "-P", wordlist, "--verbose"]
        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]
        if rc != 0 and not stdout.strip():
            result.errors.append(f"ncrack failed (rc={rc}): {stderr[:200]}")
            return result
        for line in stdout.splitlines():
            if "password" in line.lower() and ":" in line:
                result.add("ncrack", "Credential", line[:160], "error")
        return result


class Crowbar(ExternalTool):
    name = "crowbar"
    bin_name = "crowbar"
    accepted_kinds = {"ip", "domain"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 300.0,
                   service: str = "ssh", username: str = "root",
                   wordlist: str = "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
                   **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        bin_path = shutil.which(cls.bin_name) or "crowbar"
        args = [bin_path, "-b", service, "-s", target, "-u", username, "-C", wordlist]
        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]
        if rc != 0 and not stdout.strip():
            result.errors.append(f"crowbar failed (rc={rc}): {stderr[:200]}")
            return result
        for line in stdout.splitlines():
            if "found" in line.lower() or "success" in line.lower():
                result.add("crowbar", "Credential", line[:160], "error")
        return result


class Patator(ExternalTool):
    name = "patator"
    bin_name = "patator"
    accepted_kinds = {"ip", "domain", "url"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 300.0,
                   module: str = "ssh_login", **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        bin_path = shutil.which(cls.bin_name) or "patator"
        rc, stdout, stderr = await cls._run_subprocess(
            [bin_path, module, f"host={target}", "--rate-limit=5", "-x", "ignore:fgot=timeout"],
            timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]
        if rc != 0 and not stdout.strip():
            result.errors.append(f"patator failed (rc={rc}): {stderr[:200]}")
        return result