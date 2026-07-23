"""DNSx — DNS toolkit."""

from __future__ import annotations

import json
import shutil

from ..models import ScanResult
from .base import ExternalTool


class DNSx(ExternalTool):
    name = "dnsx"
    bin_name = "dnsx"
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

        bin_path = shutil.which(cls.bin_name) or "dnsx"
        args = [bin_path, "-l", target, "-all", "-j", "-silent"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"dnsx failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host", target)
                a = data.get("a", [])
                aaaa = data.get("aaaa", [])
                mx = data.get("mx", [])
                ns = data.get("ns", [])
                txt = data.get("txt", [])
                cname = data.get("cname", [])

                if a:
                    result.add("dnsx", "A Records", ", ".join(a), "found")
                if aaaa:
                    result.add("dnsx", "AAAA Records", ", ".join(aaaa), "found")
                if mx:
                    result.add("dnsx", "MX Records", ", ".join(mx), "found")
                if ns:
                    result.add("dnsx", "NS Records", ", ".join(ns), "found")
                if txt:
                    result.add("dnsx", "TXT Records", ", ".join(txt), "info")
                if cname:
                    result.add("dnsx", "CNAME", ", ".join(cname), "found")
            except json.JSONDecodeError:
                continue

        return result


class Puredns(ExternalTool):
    name = "puredns"
    bin_name = "puredns"
    accepted_kinds = {"domain"}

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

        bin_path = shutil.which(cls.bin_name) or "puredns"
        # Use stdin resolve mode — passes target domain via input_data
        args = [bin_path, "resolve", "-q"]
        input_data = target.encode()

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout, input_data=input_data)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"puredns failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line and "." in line:
                result.add("puredns", "Subdomain", line, "found")

        return result