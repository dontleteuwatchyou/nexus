"""Tunneling — Chisel, Ptunnel, Udptunnel, Iodine, Proxychains, Stunnel, Sbd, Dbd."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class Chisel(ExternalTool):
    name = "chisel"
    bin_name = "chisel"
    accepted_kinds = {"ip", "domain"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("chisel", "Note", "Chisel is an interactive TCP/UDP tunnel. Run manually: chisel client target:PORT <remote>:<local>", "info")
        return result


class Ptunnel(ExternalTool):
    name = "ptunnel"
    bin_name = "ptunnel"
    accepted_kinds = {"ip"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("ptunnel", "Note", "Ptunnel is an interactive ICMP tunnel. Run manually: ptunnel -p target -lp <local_port> -da <dest_host> -dp <dest_port>", "info")
        return result


class Udptunnel(ExternalTool):
    name = "udptunnel"
    bin_name = "udptunnel"
    accepted_kinds = {"ip"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("udptunnel", "Note", "Udptunnel is an interactive UDP tunnel. Run manually: udptunnel -s target <args>", "info")
        return result


class Iodine(ExternalTool):
    name = "iodine"
    bin_name = "iodine"
    accepted_kinds = {"domain"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("iodine", "Note", "Iodine is a DNS tunneling tool. Needs root: iodine target TOP_DOMAIN", "info")
        return result


class Proxychains(ExternalTool):
    name = "proxychains"
    bin_name = "proxychains"
    accepted_kinds = {"ip"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 120.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "proxychains"
        args = [bin_path, "nmap", "-sT", "-Pn", target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:3000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"proxychains failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if "open" in line and "port" not in line.lower():
                result.add("proxychains", "Open Port", line[:160], "warn")
            elif "Nmap done" in line or "Interesting ports" in line:
                result.add("proxychains", "Scan", line[:160], "found")

        return result


class Stunnel(ExternalTool):
    name = "stunnel"
    bin_name = "stunnel"
    accepted_kinds = {"ip", "domain"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("stunnel", "Note", "Stunnel is a config-based SSL tunnel. Configure /etc/stunnel/stunnel.conf and run: stunnel", "info")
        return result


class Sbd(ExternalTool):
    name = "sbd"
    bin_name = "sbd"
    accepted_kinds = {"ip"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("sbd", "Note", "Sbd is an interactive backdoor tunnel tool. Run manually: sbd target PORT", "info")
        return result


class Dbd(ExternalTool):
    name = "dbd"
    bin_name = "dbd"
    accepted_kinds = {"ip"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("dbd", "Note", "Dbd is an interactive backdoor/netcat tool. Run manually: dbd target PORT", "info")
        return result
