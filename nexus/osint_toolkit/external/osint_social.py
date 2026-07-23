"""Sherlock / Holehe / TheHarvester / Recon-ng / Photon / FinalRecon — OSINT & Social Engineering."""

from __future__ import annotations

import json
import re
import shutil

from ..models import ScanResult
from .base import ExternalTool


class Sherlock(ExternalTool):
    name = "sherlock"
    bin_name = "sherlock"
    accepted_kinds = {"username"}

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

        bin_path = shutil.which(cls.bin_name) or "sherlock"
        args = [bin_path, target, "--output", "/tmp/sherlock_out.json"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        import os
        if os.path.exists("/tmp/sherlock_out.json"):
            try:
                with open("/tmp/sherlock_out.json") as f:
                    data = json.load(f)
                    for site, info in data.items():
                        if info.get("status") == "claimed":
                            url = info.get("url", site)
                            result.add("sherlock", site, url, "found", url=url)
            except Exception:
                pass

        if rc != 0 and not stdout.strip() and not os.path.exists("/tmp/sherlock_out.json"):
            result.errors.append(f"sherlock failed (rc={rc}): {stderr[:200]}")
            return result

        result.add("sherlock", "Summary", f"Check /tmp/sherlock_out.json for full results", "info")
        return result


class Holehe(ExternalTool):
    name = "holehe"
    bin_name = "holehe"
    accepted_kinds = {"email"}

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

        bin_path = shutil.which(cls.bin_name) or "holehe"
        args = [bin_path, target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        # Parse holehe output
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            clean = re.sub(r"\x1b\[[0-9;]*m", "", line)
            if "[+]" in clean:
                result.add("holehe", "Registered", clean.replace("[+]", "").strip()[:160], "warn")
            elif "[-]" in clean:
                result.add("holehe", "Not Registered", clean.replace("[-]", "").strip()[:160], "info")

        return result


class TheHarvester(ExternalTool):
    name = "theHarvester"
    bin_name = "theHarvester"
    accepted_kinds = {"domain", "email", "username"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 300.0,
        sources: str = "all",
        limit: int = 500,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "theHarvester"
        args = [
            bin_path,
            "-d", target,
            "-b", sources,
            "-l", str(limit),
            "-f", "/tmp/theHarvester_out.html",
        ]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"theHarvester failed (rc={rc}): {stderr[:200]}")
            return result

        # Parse output
        for line in stdout.splitlines():
            line = line.strip()
            if any(k in line for k in ["Host:", "IP:", "Email:", "User:", "Subdomain:", "Vhost:"]):
                result.add("theHarvester", line.split(":")[0], line.split(":", 1)[1].strip()[:160], "found")

        result.add("theHarvester", "Summary", f"Check /tmp/theHarvester_out.html for full results", "info")
        return result


class ReconNg(ExternalTool):
    name = "recon-ng"
    bin_name = "recon-ng"
    accepted_kinds = {"domain", "email", "username"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 300.0,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "recon-ng"
        rc, stdout, stderr = await cls._run_subprocess(
            [bin_path, "-r", f"marketplace search", "-w", target],
            timeout=timeout,
        )

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        result.add("recon-ng", "Note", "Recon-ng is interactive. Use recon-ng -r <workspace> to launch.", "info")
        return result


class Photon(ExternalTool):
    name = "photon"
    bin_name = "photon"
    accepted_kinds = {"url", "domain"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 300.0,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "photon"
        args = [bin_path, "-u", target, "-o", "/tmp/photon_out", "--json", "--output", "/tmp/photon_out.json"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"photon failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            if line.strip() and not line.startswith("["):
                result.add("photon", "URL", line.strip()[:160], "found")

        result.add("photon", "Summary", f"Check /tmp/photon_out for full results", "info")
        return result


class FinalRecon(ExternalTool):
    name = "finalrecon"
    bin_name = "finalrecon"
    accepted_kinds = {"url", "domain"}

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

        bin_path = shutil.which(cls.bin_name) or "finalrecon"
        args = [bin_path, target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"finalrecon failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if any(k in line for k in ["[INFO]", "[+]", "[!]", "HTTP", "Title", "IP", "Server", "Technology", "WAF", "SSL"]):
                sev = "warn" if "[!]" in line else "found"
                result.add("finalrecon", "Finding", line[:160], sev)

        return result


class Arjun(ExternalTool):
    name = "arjun"
    bin_name = "arjun"
    accepted_kinds = {"url"}

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

        bin_path = shutil.which(cls.bin_name) or "arjun"
        args = [bin_path, "-u", target, "--passive", "-oJ", "/tmp/arjun_out.json"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"arjun failed (rc={rc}): {stderr[:200]}")
            return result

        import os
        if os.path.exists("/tmp/arjun_out.json"):
            try:
                with open("/tmp/arjun_out.json") as f:
                    data = json.load(f)
                    for param in data.get("params", []):
                        result.add("arjun", "Parameter", param, "found")
            except Exception:
                pass

        return result