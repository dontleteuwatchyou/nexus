"""WPScan — WordPress vulnerability scanner."""

from __future__ import annotations

import json
import shutil

from ..models import ScanResult
from .base import ExternalTool


class WPScan(ExternalTool):
    name = "wpscan"
    bin_name = "wpscan"
    accepted_kinds = {"url", "domain"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 300.0,
        api_token: str | None = None,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "wpscan"
        args = [
            bin_path,
            "--url", target,
            "--format", "json",
            "--no-banner",
            "--enumerate", "vp,vt,u",
        ]

        if api_token:
            args.extend(["--api-token", api_token])

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"wpscan failed (rc={rc}): {stderr[:200]}")
            return result

        try:
            data = json.loads(stdout)
            # Version
            if "version" in data:
                v = data["version"]
                result.add("wpscan", "WordPress Version", f"{v.get('number', '?')} ({v.get('status', '?')})", "warn")

            # Plugins
            for plugin, info in data.get("plugins", {}).items():
                status = "vulnerable" if info.get("vulnerabilities") else "ok"
                sev = "error" if status == "vulnerable" else "found"
                vulns = len(info.get("vulnerabilities", []))
                result.add("wpscan", f"Plugin: {plugin}", f"{status} ({vulns} vulns)", sev)

            # Themes
            for theme, info in data.get("themes", {}).items():
                status = "vulnerable" if info.get("vulnerabilities") else "ok"
                sev = "error" if status == "vulnerable" else "found"
                vulns = len(info.get("vulnerabilities", []))
                result.add("wpscan", f"Theme: {theme}", f"{status} ({vulns} vulns)", sev)

            # Users
            for user in data.get("users", []):
                result.add("wpscan", "User", f"{user.get('username', '?')} (id: {user.get('id', '?')})", "info")

        except json.JSONDecodeError:
            pass

        return result