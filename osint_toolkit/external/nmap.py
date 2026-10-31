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
    # pkexec is Linux-only; elsewhere run as-is (elevation handled by the OS).
    if hasattr(os, "geteuid") and os.geteuid() != 0 and shutil.which("pkexec"):
        return ["pkexec"] + args
    return args


def parse_nmap(stdout: str) -> list[dict]:
    """Parse nmap stdout into normalized finding dicts (pure function).

    Open ports are informational; script lines reporting a vulnerability or a
    CVE are promoted to high/medium so real findings reach the vuln report.
    """
    out: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "/tcp" in line and "open" in line:
            parts = line.split()
            if len(parts) >= 2 and "/" in parts[0]:
                port = parts[0]
                service = parts[2] if len(parts) > 2 else ""
                version = " ".join(parts[3:]) if len(parts) > 3 else ""
                out.append({"kind": "port", "severity": "info",
                            "label": f"Port {port}",
                            "detail": f"{service} {version}".strip() or "open"})
                continue
        low = line.lower()
        if "|" in line and ("vulnerable" in low or "cve-" in low or "vuln" in low):
            sev = "high" if "vulnerable" in low else "medium"
            out.append({"kind": "script", "severity": sev,
                        "label": "nmap script",
                        "detail": line.lstrip("|_ ").strip()[:200]})
    return out


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

        for item in parse_nmap(stdout):
            if item["kind"] == "port":
                result.add("nmap", item["label"], item["detail"], "info")
            else:
                result.add("nmap-script", item["label"], item["detail"], item["severity"])
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
