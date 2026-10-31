"""SSL/TLS tools — traffic dump, MITM, multiplexer,
AD CS exploitation, and tunnel proxy."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class Ssldump(ExternalTool):
    name = "ssldump"
    bin_name = "ssldump"
    accepted_kinds = {"interface", "file"}

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

        bin_path = shutil.which(cls.bin_name) or "ssldump"
        args = [bin_path, "-r", target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"ssldump failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line and ("Certificate" in line or "Handshake" in line or "alert" in line):
                result.add("ssldump", "SSL", line[:160], "found")

        return result


class Sslsniff(ExternalTool):
    name = "sslsniff"
    bin_name = "sslsniff"
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
        result.add("sslsniff", "Note", "SSL MITM tool. Interactive use only; run manually: sslsniff", "info")
        return result


class Sslsplit(ExternalTool):
    name = "sslsplit"
    bin_name = "sslsplit"
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
        result.add("sslsplit", "Note", "SSL MITM tool. Interactive use only; run manually: sslsplit", "info")
        return result


class Sslh(ExternalTool):
    name = "sslh"
    bin_name = "sslh"
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
        result.add("sslh", "Note", "SSL/SSH multiplexer. Run manually: sslh", "info")
        return result


class Certipy(ExternalTool):
    name = "certipy"
    bin_name = "certipy"
    accepted_kinds = {"domain", "ip"}

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

        bin_path = shutil.which(cls.bin_name) or "certipy"
        args = [bin_path, "find", "-u", "", "-p", "", "-dc-ip", target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"certipy failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line and ("CA" in line or "Certificate" in line or "Template" in line or "vulnerable" in line):
                result.add("certipy", "AD CS", line[:160], "found")

        return result


class LigoloNgProxy(ExternalTool):
    name = "ligolo-ng-proxy"
    bin_name = "ligolo-ng-proxy"
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
        result.add("ligolo-ng-proxy", "Note", "Ligolo tunnel proxy. Run manually: ligolo-ng-proxy", "info")
        return result
