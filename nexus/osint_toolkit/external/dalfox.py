"""Dalfox — XSS scanner."""

from __future__ import annotations

import json
import shutil

from ..models import ScanResult
from .base import ExternalTool


class Dalfox(ExternalTool):
    name = "dalfox"
    bin_name = "dalfox"
    accepted_kinds = {"url"}

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

        bin_path = shutil.which(cls.bin_name) or "dalfox"
        args = [
            bin_path,
            "url", target,
            "--json",
            "--silence",
            "--skip-bav",
        ]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"dalfox failed (rc={rc}): {stderr[:200]}")
            return result

        try:
            data = json.loads(stdout)
            for issue in data.get("issues", []):
                param = issue.get("parameter", "")
                payload = issue.get("payload", "")
                ptype = issue.get("type", "XSS")
                result.add("dalfox", f"{ptype} in {param}", payload[:160], "error")
        except json.JSONDecodeError:
            for line in stdout.splitlines():
                if "XSS" in line or "VULN" in line:
                    result.add("dalfox", "Finding", line[:160], "error")

        return result