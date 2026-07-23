"""Nmap — network exploration and port scanning."""

from __future__ import annotations

import os
import shutil
import socket

from ..models import ScanResult
from .base import ExternalTool


def _resolve(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return host


def _maybe_pkexec(args: list[str]) -> list[str]:
    if os.geteuid() != 0:
        return ["pkexec"] + args
    return args


class Nmap(ExternalTool):
    name = "nmap"
    bin_name = "nmap"
    accepted_kinds = {"domain", "ip", "url"}

    DEFAULT_PORTS = "top-1000"
    SCRIPTS = "default,vuln,safe"

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 300.0,
        ports: str = DEFAULT_PORTS,
        scripts: str = SCRIPTS,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "nmap"
        target_ip = _resolve(target)
        args = _maybe_pkexec([
            bin_path,
            "-Pn",
            "-sS",
            "-sV",
            f"--script={scripts}",
            f"-p{ports}",
            "--open",
            "-T4",
            target_ip,
        ])

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"nmap failed (rc={rc}): {stderr[:200]}")
            return result

        # Parse nmap output
        lines = stdout.splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Open ports: PORT   STATE SERVICE  VERSION
            if "/tcp" in line and "open" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0]
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else ""
                    version = " ".join(parts[3:]) if len(parts) > 3 else ""
                    result.add("nmap", f"Port {port}", f"{service} {version}".strip(), "found")

            # Script output
            if "|" in line and ("script" in line.lower() or "vuln" in line.lower()):
                result.add("nmap-script", "Script output", line[:160], "warn")

        return result


class Masscan(ExternalTool):
    name = "masscan"
    bin_name = "masscan"
    accepted_kinds = {"ip"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 300.0,
        ports: str = "1-65535",
        rate: int = 1000,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        target_ip = _resolve(target)
        bin_path = shutil.which(cls.bin_name) or "masscan"
        args = _maybe_pkexec([
            bin_path,
            target_ip,
            f"-p{ports}",
            f"--rate={rate}",
            "--open",
            "--banners",
        ])

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"masscan failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("Discovered open port"):
                result.add("masscan", "Open port", line, "found")

        return result