"""Naabu — fast port scanner."""

from __future__ import annotations

import json
import shutil

from ..models import ScanResult
from .base import ExternalTool


class Naabu(ExternalTool):
    name = "naabu"
    bin_name = "naabu"
    accepted_kinds = {"domain", "ip", "url"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 180.0,
        ports: str = "1000",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "naabu"
        args = [
            bin_path,
            "-host", target,
            "-tp", ports,
            "-j",
            "-silent",
        ]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"naabu failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                port = data.get("port", 0)
                protocol = data.get("protocol", "tcp")
                result.add("naabu", f"Port {port}/{protocol}", "Open", "found")
            except json.JSONDecodeError:
                continue

        return result