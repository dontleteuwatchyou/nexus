"""BurpSuite / ZAP / Caido / Nikto / Wapiti / Skipfish — Web App Scanning."""

from __future__ import annotations

import json
import shutil

from ..models import ScanResult
from .base import ExternalTool


class BurpSuite(ExternalTool):
    name = "burpsuite"
    bin_name = "burpsuite"
    accepted_kinds = {"url"}

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

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("burpsuite", "Note", "Burp Suite is a GUI application. Use the Community/Pro edition for scanning.", "info")
        return result


class ZAP(ExternalTool):
    name = "zaproxy"
    bin_name = "zaproxy"
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

        bin_path = shutil.which(cls.bin_name) or "zaproxy"
        args = [
            bin_path,
            "-cmd",
            "-quickurl", target,
            "-quickout", "/tmp/zap_report.html",
            "-quickprogress",
        ]

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("zaproxy", "Note", "ZAP scan started. Check /tmp/zap_report.html for results.", "info")
        result.raw["command"] = " ".join(args)
        return result


class Caido(ExternalTool):
    name = "caido"
    bin_name = "caido"
    accepted_kinds = {"url"}

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

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("caido", "Note", "Caido is a GUI application. Run manually: caido", "info")
        return result


class Nikto(ExternalTool):
    name = "nikto"
    bin_name = "nikto"
    accepted_kinds = {"url", "domain", "ip"}

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

        bin_path = shutil.which(cls.bin_name) or "nikto"
        args = [bin_path, "-h", target, "-Format", "json", "-output", "/tmp/nikto_out.json"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"nikto failed (rc={rc}): {stderr[:200]}")
            return result

        import os
        if os.path.exists("/tmp/nikto_out.json"):
            try:
                with open("/tmp/nikto_out.json") as f:
                    data = json.load(f)
                    for vuln in data.get("vulnerabilities", [])[:30]:
                        result.add("nikto", f"OSVDB-{vuln.get('OSVDB', '?')}", vuln.get("msg", "")[:160], "warn")
            except Exception:
                pass

        return result


class Wapiti(ExternalTool):
    name = "wapiti"
    bin_name = "wapiti"
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

        bin_path = shutil.which(cls.bin_name) or "wapiti"
        args = [bin_path, "-u", target, "-f", "json", "-o", "/tmp/wapiti_out"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"wapiti failed (rc={rc}): {stderr[:200]}")
            return result

        import os
        if os.path.exists("/tmp/wapiti_out.json"):
            try:
                with open("/tmp/wapiti_out.json") as f:
                    data = json.load(f)
                    for vuln in data.get("vulnerabilities", [])[:30]:
                        result.add("wapiti", vuln.get("name", "Vuln"), vuln.get("description", "")[:160], "warn")
            except Exception:
                pass

        return result


class Skipfish(ExternalTool):
    name = "skipfish"
    bin_name = "skipfish"
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

        bin_path = shutil.which(cls.bin_name) or "skipfish"
        args = [bin_path, "-o", "/tmp/skipfish_out", target]

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("skipfish", "Note", "Skipfish is a web app scanner. Run manually with output directory.", "info")
        result.raw["command"] = " ".join(args)
        return result