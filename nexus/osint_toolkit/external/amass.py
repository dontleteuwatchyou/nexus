"""Amass — subdomain enumeration."""

from __future__ import annotations

import json
import shutil

from ..models import ScanResult
from .base import ExternalTool


class Amass(ExternalTool):
    name = "amass"
    bin_name = "amass"
    accepted_kinds = {"domain"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 300.0,
        passive: bool = True,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "amass"
        args = [bin_path, "enum", "-d", target, "-json", ".amass_output.json"]

        if passive:
            args.append("-passive")

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        # Parse JSON output file
        import os
        json_file = ".amass_output.json"
        if os.path.exists(json_file):
            with open(json_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        name = data.get("name", "")
                        if name:
                            result.add("amass", "Subdomain", name, "found")
                    except json.JSONDecodeError:
                        continue
            os.remove(json_file)

        if rc != 0 and not stdout.strip():
            result.errors.append(f"amass failed (rc={rc}): {stderr[:200]}")

        return result