"""SQLMap — automatic SQL injection tool."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class SQLMap(ExternalTool):
    name = "sqlmap"
    bin_name = "sqlmap"
    accepted_kinds = {"url"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 600.0,
        batch: bool = True,
        risk: int = 1,
        level: int = 1,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "sqlmap"
        args = [
            bin_path,
            "-u", target,
            f"--risk={risk}",
            f"--level={level}",
            "--crawl=1",
            "--forms",
            "--threads=5",
        ]

        if batch:
            args.append("--batch")

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"sqlmap failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if any(k in line.lower() for k in ["injectable", "vulnerable", "parameter:", "type:", "payload:", "dbms:"]):
                sev = "error" if "injectable" in line.lower() else "warn"
                result.add("sqlmap", "Finding", line[:160], sev)

        return result