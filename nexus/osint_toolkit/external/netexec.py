"""CrackMapExec / NetExec — SMB/AD enumeration and attack toolkit."""

from __future__ import annotations

import json
import shutil

from ..models import ScanResult
from .base import ExternalTool


class CrackMapExec(ExternalTool):
    name = "crackmapexec"
    bin_name = "crackmapexec"
    accepted_kinds = {"ip"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 300.0,
        protocol: str = "smb",
        username: str = "",
        password: str = "",
        hash: str = "",
        domain: str = "",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "crackmapexec"
        args = [bin_path, protocol, target]

        if username:
            args.extend(["-u", username])
        if password:
            args.extend(["-p", password])
        if hash:
            args.extend(["-H", hash])
        if domain:
            args.extend(["-d", domain])

        args.extend(["--shares", "--sessions", "--disks", "--users", "--groups", "--loggedon-users", "--local-groups", "--pass-pol", "--spider"])

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"crackmapexec failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            low = line.lower()
            if any(k in low for k in ["share", "session", "user", "group", "disk", "policy", "password", "admin", "pwd", "hash"]):
                sev = "warn" if any(k in low for k in ["admin", "pwd", "hash", "password"]) else "found"
                result.add("crackmapexec", protocol.upper(), line[:160], sev)

        return result


class NetExec(ExternalTool):
    name = "netexec"
    bin_name = "netexec"
    accepted_kinds = {"ip"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 300.0,
        protocol: str = "smb",
        username: str = "",
        password: str = "",
        hash: str = "",
        domain: str = "",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "netexec"
        args = [bin_path, protocol, target]

        if username:
            args.extend(["-u", username])
        if password:
            args.extend(["-p", password])
        if hash:
            args.extend(["-H", hash])
        if domain:
            args.extend(["-d", domain])

        args.extend(["--shares", "--sessions", "--disks", "--users", "--groups", "--loggedon-users", "--local-groups", "--pass-pol", "--spider", "--rid-brute"])

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"netexec failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            low = line.lower()
            if any(k in low for k in ["share", "session", "user", "group", "disk", "policy", "password", "admin", "pwd", "hash", "rid"]):
                sev = "warn" if any(k in low for k in ["admin", "pwd", "hash", "password", "rid"]) else "found"
                result.add("netexec", protocol.upper(), line[:160], sev)

        return result