"""Nuclei — vulnerability scanner based on templates."""

from __future__ import annotations

import json
import shutil

from ..models import ScanResult
from .base import ExternalTool


class Nuclei(ExternalTool):
    name = "nuclei"
    bin_name = "nuclei"
    accepted_kinds = {"domain", "ip", "url"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 300.0,
        severity: str = "critical,high,medium,low,info",
        tags: str | None = None,
        templates: str | None = None,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "nuclei"
        args = [
            bin_path,
            "-u", target,
            "-silent",
            "-jsonl",
            "-severity", severity,
        ]

        if tags:
            args.extend(["-tags", tags])
        if templates:
            args.extend(["-t", templates])

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"nuclei failed (rc={rc}): {stderr[:200]}")
            return result

        # Parse JSONL output
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                finding = json.loads(line)
                template = finding.get("template", "unknown")
                severity = finding.get("info", {}).get("severity", "info")
                name = finding.get("info", {}).get("name", template)
                matched = finding.get("matched-at", target)
                desc = finding.get("info", {}).get("description", "")[:200]

                sev_map = {"critical": "error", "high": "error", "medium": "warn", "low": "warn", "info": "info"}
                sev = sev_map.get(severity.lower(), "info")

                result.add("nuclei", f"[{severity.upper()}] {name}", f"{matched} — {desc}", sev)
            except json.JSONDecodeError:
                continue

        return result