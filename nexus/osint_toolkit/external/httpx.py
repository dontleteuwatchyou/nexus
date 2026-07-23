"""HTTPX — fast HTTP toolkit."""

from __future__ import annotations

import json
import shutil

from ..models import ScanResult
from .base import ExternalTool


class HTTPX(ExternalTool):
    name = "httpx"
    bin_name = "httpx"
    accepted_kinds = {"domain", "ip", "url"}

    @classmethod
    def _find_bin(cls) -> str | None:
        for name in ("httpx-pd", "httpx"):
            p = shutil.which(name)
            if p:
                return p
        return None

    @classmethod
    def is_installed(cls) -> bool:
        return cls._find_bin() is not None

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 120.0,
        follow_redirects: bool = True,
        tech_detect: bool = True,
        **kwargs,
    ) -> ScanResult:
        bin_path = cls._find_bin()
        if not bin_path:
            return cls._not_installed_result(target)

        if "httpx-pd" in bin_path:
            args = [bin_path, "-u", target, "-j", "-silent"]
            if follow_redirects:
                args.append("-fr")
            if tech_detect:
                args.append("-td")
            args.extend(["-title", "-sc", "-server"])
        else:
            args = [bin_path, "-u", target, "-j", "-silent"]
            args.extend(["-title", "-sc", "-server"])

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"httpx failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                url = data.get("url", "")
                status = data.get("status_code", 0)
                title = data.get("title", "")
                tech = data.get("tech", [])
                server = data.get("webserver", "")
                cdn = data.get("cdn", "")
                tls = data.get("tls", {})

                sev = "found" if 200 <= status < 400 else "warn"
                result.add("httpx", f"HTTP {status}", f"{url} — {title}", sev, url=url)

                if tech:
                    result.add("httpx", "Technologies", ", ".join(tech), "info")
                if server:
                    result.add("httpx", "Server", server, "info")
                if cdn:
                    result.add("httpx", "CDN", cdn, "info")
                if tls:
                    result.add("httpx", "TLS", str(tls), "info")
            except json.JSONDecodeError:
                continue

        return result