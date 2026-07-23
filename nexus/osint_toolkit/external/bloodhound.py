"""BloodHound / BloodHound.py / BloodHound-CE — AD graph analysis."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class BloodHound(ExternalTool):
    name = "bloodhound"
    bin_name = "bloodhound"
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

        bin_path = shutil.which(cls.bin_name) or "bloodhound"
        args = [bin_path]

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("bloodhound", "Note", "BloodHound is a GUI application. Use bloodhound-python / SharpHound for data collection.", "info")
        result.raw["command"] = " ".join(args)
        return result


class BloodHoundPython(ExternalTool):
    name = "bloodhound-python"
    bin_name = "bloodhound-python"
    accepted_kinds = {"ip"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 300.0,
        username: str = "",
        password: str = "",
        domain: str = "",
        collection: str = "all",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        if not username or not password or not domain:
            result = ScanResult(target=target, module=f"external:{cls.name}")
            result.add("bloodhound-python", "Skipped",
                       "Requires -u username -p password -d domain (AD only)", "info")
            return result

        bin_path = shutil.which(cls.bin_name) or "bloodhound-python"
        args = [
            bin_path,
            "-u", username,
            "-p", password,
            "-d", domain,
            "-ns", target,
            "-c", collection,
            "--zip",
        ]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"bloodhound-python failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line:
                if "done" in line.lower() or "completed" in line.lower():
                    result.add("bloodhound-python", "Status", line, "found")
                elif "error" in line.lower() or "fail" in line.lower():
                    result.add("bloodhound-python", "Error", line, "error")
                else:
                    result.add("bloodhound-python", "Progress", line[:160], "info")

        return result