"""Enum4linux / Enum4linux-ng — SMB/AD enumeration."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class Enum4linux(ExternalTool):
    name = "enum4linux"
    bin_name = "enum4linux"
    accepted_kinds = {"ip"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 180.0,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "enum4linux"
        args = [bin_path, "-a", target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"enum4linux failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if any(k in line for k in ["[+]", "User:", "Group:", "Share:", "Password:", "Policy:", "Domain:"]):
                sev = "warn" if "Password" in line else "found"
                result.add("enum4linux", "Finding", line[:160], sev)

        return result


class Enum4linuxNG(ExternalTool):
    name = "enum4linux-ng"
    bin_name = "enum4linux-ng"
    accepted_kinds = {"ip"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 180.0,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "enum4linux-ng"
        args = [bin_path, "-A", target, "-oJ", "/tmp/enum4linux_out.json"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        import json
        import os
        if os.path.exists("/tmp/enum4linux_out.json"):
            try:
                with open("/tmp/enum4linux_out.json") as f:
                    data = json.load(f)
                    for key in ["users", "groups", "shares", "password_policy", "domain_info"]:
                        if key in data:
                            result.add("enum4linux-ng", key.capitalize(), f"{len(data[key])} entries", "found")
            except Exception:
                pass

        if rc != 0 and not stdout.strip():
            result.errors.append(f"enum4linux-ng failed (rc={rc}): {stderr[:200]}")

        return result


class LdapDomainDump(ExternalTool):
    name = "ldapdomaindump"
    bin_name = "ldapdomaindump"
    accepted_kinds = {"ip"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 180.0,
        username: str = "",
        password: str = "",
        domain: str = "",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "ldapdomaindump"
        args = [bin_path, target]

        if username:
            args.extend(["-u", username])
        if password:
            args.extend(["-p", password])

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"ldapdomaindump failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            if "written" in line.lower() or "dumped" in line.lower():
                result.add("ldapdomaindump", "Output", line[:160], "found")

        return result


class Kerbrute(ExternalTool):
    name = "kerbrute"
    bin_name = "kerbrute"
    accepted_kinds = {"ip"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 180.0,
        domain: str = "",
        userlist: str = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "kerbrute"
        args = [
            bin_path,
            "userenum",
            "--dc", target,
            "-d", domain if domain else target,
            userlist,
        ]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"kerbrute failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if "VALID USERNAME" in line or "valid" in line.lower():
                result.add("kerbrute", "Valid User", line[:160], "warn")

        return result