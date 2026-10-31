"""Kismet / Mdk3 / Cowpatty / Bully / Reaver / Pixiewps / SparrowWifi / SpoofTooph / Rfcat — Wireless extras."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class Kismet(ExternalTool):
    name = "kismet"
    bin_name = "kismet"
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
        result.add("kismet", "Note", "Kismet is an interactive/GUI wireless sniffer. Run manually: sudo kismet", "info")
        return result


class Mdk3(ExternalTool):
    name = "mdk3"
    bin_name = "mdk3"
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
        result.add("mdk3", "Note", "Mdk3 requires root privileges. Run manually: sudo mdk3 <interface> <test_mode> [options]", "warn")
        return result


class Cowpatty(ExternalTool):
    name = "cowpatty"
    bin_name = "cowpatty"
    accepted_kinds = {"file", "interface"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 600.0,
        ssid: str = "",
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        if not ssid:
            result = ScanResult(target=target, module=f"external:{cls.name}")
            result.add("cowpatty", "Error", "SSID is required. Use ssid=<name> parameter.", "error")
            return result

        bin_path = shutil.which(cls.bin_name) or "cowpatty"
        args = [bin_path, "-r", target, "-f", wordlist, "-s", ssid]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"cowpatty failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if "cracked" in line.lower() or "key" in line.lower() or "found" in line.lower():
                result.add("cowpatty", "Key Found", line[:160], "error")
            elif "wpa" in line.lower() or "pmk" in line.lower():
                result.add("cowpatty", "Progress", line[:160], "warn")
            elif line and not line.startswith("["):
                result.add("cowpatty", "Output", line[:160], "info")

        return result


class Bully(ExternalTool):
    name = "bully"
    bin_name = "bully"
    accepted_kinds = {"interface"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 300.0,
        bssid: str = "",
        channel: str = "",
        essid: str = "",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "bully"
        args = [bin_path]

        if bssid:
            args.extend(["-b", bssid])
        if channel:
            args.extend(["-c", channel])
        if essid:
            args.extend(["-e", essid])

        args.append(target)

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"bully failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if "pin" in line.lower() or "wps" in line.lower() or "key" in line.lower():
                result.add("bully", "Result", line[:160], "error" if "key" in line.lower() else "warn")
            elif line and not line.startswith("["):
                result.add("bully", "Progress", line[:160], "info")

        return result


class Reaver(ExternalTool):
    name = "reaver"
    bin_name = "reaver"
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
        result.add("reaver", "Note", "Reaver is interactive and requires root. Run manually: sudo reaver -i <interface> -b <bssid> -vv", "warn")
        return result


class Pixiewps(ExternalTool):
    name = "pixiewps"
    bin_name = "pixiewps"
    accepted_kinds = {"file"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 60.0,
        pke: str = "",
        pkr: str = "",
        e_hash1: str = "",
        e_hash2: str = "",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        if not all([pke, pkr, e_hash1, e_hash2]):
            result = ScanResult(target=target, module=f"external:{cls.name}")
            result.add("pixiewps", "Error", "All parameters required: pke, pkr, e_hash1, e_hash2", "error")
            return result

        bin_path = shutil.which(cls.bin_name) or "pixiewps"
        args = [
            bin_path,
            "--pke", pke,
            "--pkr", pkr,
            "--e-hash1", e_hash1,
            "--e-hash2", e_hash2,
        ]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"pixiewps failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if "pin" in line.lower() or "wps" in line.lower() or "key" in line.lower():
                result.add("pixiewps", "Key", line[:160], "error")
            elif line and not line.startswith("["):
                result.add("pixiewps", "Result", line[:160], "info")

        return result


class SparrowWifi(ExternalTool):
    name = "sparrow-wifi"
    bin_name = "sparrow-wifi"
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
        result.add("sparrow-wifi", "Note", "Sparrow-WiFi is a GUI application. Launch it manually: sparrow-wifi", "info")
        return result


class SpoofTooph(ExternalTool):
    name = "spooftooph"
    bin_name = "spooftooph"
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
        result.add("spooftooph", "Note", "SpoofTooph is interactive. Run manually: sudo spooftooph -i <interface>", "info")
        return result


class Rfcat(ExternalTool):
    name = "rfcat"
    bin_name = "rfcat"
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
        result.add("rfcat", "Note", "RFCat is an interactive RF hacking tool. Run manually with Python: python3 -m rflib", "info")
        return result
