"""Cewl / Metagoofil / Exiftool / Maltego / Dmitry / Linkedin2username / Pompem — OSINT extras."""

from __future__ import annotations

import json
import re
import shutil

from ..models import ScanResult
from .base import ExternalTool


class Cewl(ExternalTool):
    name = "cewl"
    bin_name = "cewl"
    accepted_kinds = {"url"}

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

        bin_path = shutil.which(cls.bin_name) or "cewl"
        args = [bin_path, target, "-d", "2", "-m", "5", "-w", "/tmp/cewl_out.txt"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"cewl failed (rc={rc}): {stderr[:200]}")
            return result

        import os
        if os.path.exists("/tmp/cewl_out.txt"):
            try:
                with open("/tmp/cewl_out.txt") as f:
                    word_count = sum(1 for _ in f)
                result.add("cewl", "Words Collected", str(word_count), "found")
            except Exception:
                pass

        for line in stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("[") and ":" in line:
                result.add("cewl", "Word", line[:160], "info")

        result.add("cewl", "Output", "/tmp/cewl_out.txt", "info")
        return result


class Metagoofil(ExternalTool):
    name = "metagoofil"
    bin_name = "metagoofil"
    accepted_kinds = {"domain"}

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

        bin_path = shutil.which(cls.bin_name) or "metagoofil"
        args = [
            bin_path,
            "-d", target,
            "-t", "pdf,doc,xls,ppt",
            "-o", "/tmp/metagoofil_out",
            "-n", "50",
        ]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"metagoofil failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if any(k in line for k in ("[+]", "File:", "Author:", "Title:", "Creator:")):
                sev = "found" if "[+]" in line else "info"
                result.add("metagoofil", "Metadata", line[:160], sev)

        result.add("metagoofil", "Output", "/tmp/metagoofil_out", "info")
        return result


class Exiftool(ExternalTool):
    name = "exiftool"
    bin_name = "exiftool"
    accepted_kinds = {"file"}

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

        bin_path = shutil.which(cls.bin_name) or "exiftool"
        args = [bin_path, target, "-j"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"exiftool failed (rc={rc}): {stderr[:200]}")
            return result

        try:
            data = json.loads(stdout)
            if isinstance(data, list):
                for entry in data:
                    for key, value in entry.items():
                        if value and str(value).strip():
                            result.add("exiftool", key, str(value)[:160], "found")
            elif isinstance(data, dict):
                for key, value in data.items():
                    if value and str(value).strip():
                        result.add("exiftool", key, str(value)[:160], "found")
        except json.JSONDecodeError:
            for line in stdout.splitlines():
                line = line.strip()
                if line and ":" in line:
                    result.add("exiftool", "Raw", line[:160], "info")

        return result


class Maltego(ExternalTool):
    name = "maltego"
    bin_name = "maltego"
    accepted_kinds = {"domain", "email", "username"}

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
        result.add("maltego", "Note", "Maltego is a GUI application. Launch it manually and create a new graph to start your OSINT investigation.", "info")
        return result


class Dmitry(ExternalTool):
    name = "dmitry"
    bin_name = "dmitry"
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

        bin_path = shutil.which(cls.bin_name) or "dmitry"
        args = [bin_path, "-winsepo", "/tmp/dmitry_out.txt", target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"dmitry failed (rc={rc}): {stderr[:200]}")
            return result

        import os
        if os.path.exists("/tmp/dmitry_out.txt"):
            try:
                with open("/tmp/dmitry_out.txt") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        if any(k in line for k in ("Hostname:", "IP:", "Domain:", "Email:", "Whois:", "BGP:")):
                            result.add("dmitry", line.split(":")[0], line.split(":", 1)[1].strip()[:160], "found")
                        elif line and not line.startswith("#") and not line.startswith("--"):
                            result.add("dmitry", "Info", line[:160], "info")
            except Exception:
                pass

        for line in stdout.splitlines():
            line = line.strip()
            if line and ":" in line and not line.startswith("["):
                result.add("dmitry", "Finding", line[:160], "info")

        return result


class Linkedin2username(ExternalTool):
    name = "linkedin2username"
    bin_name = "linkedin2username"
    accepted_kinds = {"domain", "name"}

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

        bin_path = shutil.which(cls.bin_name) or "linkedin2username"
        args = [bin_path, "-d", target, "-o", "/tmp/linkedin_users.txt"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"linkedin2username failed (rc={rc}): {stderr[:200]}")
            return result

        import os
        if os.path.exists("/tmp/linkedin_users.txt"):
            try:
                with open("/tmp/linkedin_users.txt") as f:
                    usernames = [line.strip() for line in f if line.strip()]
                result.add("linkedin2username", "Usernames Generated", str(len(usernames)), "found")
                for u in usernames[:50]:
                    result.add("linkedin2username", "Username", u, "info")
            except Exception:
                pass

        for line in stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("[") and not line.startswith("("):
                result.add("linkedin2username", "Output", line[:160], "info")

        return result


class Pompem(ExternalTool):
    name = "pompem"
    bin_name = "pompem"
    accepted_kinds = {"keyword"}

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

        bin_path = shutil.which(cls.bin_name) or "pompem"
        args = [bin_path, "--search", target, "--output", "/tmp/pompem_out.txt"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"pompem failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if any(k in line for k in ("[+]", "Exploit:", "CVE", "EDB-ID", "Title:", "Description:")):
                sev = "error" if "CVE" in line or "Exploit" in line else "found"
                result.add("pompem", "Exploit", line[:160], sev)
            elif line and not line.startswith("["):
                result.add("pompem", "Result", line[:160], "info")

        result.add("pompem", "Output", "/tmp/pompem_out.txt", "info")
        return result
