"""Impacket tools — secretsdump, ntlmrelayx, psexec, wmiexec, etc."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class SecretsDump(ExternalTool):
    name = "secretsdump"
    bin_name = "secretsdump.py"
    accepted_kinds = {"ip", "domain"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 300.0,
        username: str = "",
        password: str = "",
        hash: str = "",
        domain: str = "",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "secretsdump.py"
        auth = ""
        if hash:
            auth = f"-hashes {hash}"
        elif password:
            auth = f"-password {password}"
        else:
            auth = "-no-pass"

        args = [
            bin_path,
            f"{domain}/{username}:{auth}@{target}" if domain else f"{username}:{auth}@{target}",
            "-just-dc",
            "-outputfile", "/tmp/secretsdump_out",
        ]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"secretsdump failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if any(k in line.lower() for k in ["hash:", "ntlm:", "lm:", "aes:", "kerberos:", "credential", "secret"]):
                result.add("secretsdump", "Credential", line[:160], "error")

        return result


class NTLMRelayX(ExternalTool):
    name = "ntlmrelayx"
    bin_name = "ntlmrelayx.py"
    accepted_kinds = {"ip", "domain"}

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

        bin_path = shutil.which(cls.bin_name) or "ntlmrelayx.py"
        args = [bin_path, "-tf", f"targets.txt", "-smb2support", "-socks"]

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("ntlmrelayx", "Note", "Requires target file (targets.txt) with list of IPs. Run manually for relay attacks.", "info")
        result.raw["command"] = " ".join(args)
        return result


class Psexec(ExternalTool):
    name = "psexec"
    bin_name = "psexec.py"
    accepted_kinds = {"ip", "domain"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 120.0,
        username: str = "",
        password: str = "",
        hash: str = "",
        domain: str = "",
        command: str = "cmd.exe",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "psexec.py"
        auth = f"-hashes {hash}" if hash else f"-password {password}" if password else "-no-pass"

        args = [
            bin_path,
            f"{domain}/{username}:{auth}@{target}",
            command,
        ]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"psexec failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            if line.strip():
                result.add("psexec", "Output", line[:160], "info")

        return result


class Wmiexec(ExternalTool):
    name = "wmiexec"
    bin_name = "wmiexec.py"
    accepted_kinds = {"ip", "domain"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 120.0,
        username: str = "",
        password: str = "",
        hash: str = "",
        domain: str = "",
        command: str = "cmd.exe /c whoami",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "wmiexec.py"
        auth = f"-hashes {hash}" if hash else f"-password {password}" if password else "-no-pass"

        args = [
            bin_path,
            f"{domain}/{username}:{auth}@{target}",
            command,
        ]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"wmiexec failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            if line.strip():
                result.add("wmiexec", "Output", line[:160], "info")

        return result