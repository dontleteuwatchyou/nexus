"""Web reconnaissance — Wafw00f, WhatWeb, WFuzz, Httrack, Davtest, Cadaver,
Commix, Padbuster, Slowhttptest, Siege, Joomscan, Subjack, Sublist3r,
SpiderFoot, WCVS, Raven."""

from __future__ import annotations

import json
import os
import shutil

from ..models import ScanResult
from .base import ExternalTool


class Wafw00f(ExternalTool):
    name = "wafw00f"
    bin_name = "wafw00f"
    accepted_kinds = {"url", "domain"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 120.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "wafw00f"
        args = [bin_path, target, "-o", "-", "-f", "json"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:3000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"wafw00f failed (rc={rc}): {stderr[:200]}")
            return result

        try:
            data = json.loads(stdout)
            if isinstance(data, list):
                for entry in data:
                    detected = entry.get("detected", False)
                    waf_name = entry.get("name", "Unknown")
                    manufacturer = entry.get("manufacturer", "")
                    if detected:
                        result.add("wafw00f", "WAF Detected", f"{waf_name} ({manufacturer})", "warn")
                    else:
                        result.add("wafw00f", "No WAF", f"No WAF detected at {target}", "info")
        except (json.JSONDecodeError, Exception):
            pass

        return result


class WhatWeb(ExternalTool):
    name = "whatweb"
    bin_name = "whatweb"
    accepted_kinds = {"url", "domain"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 120.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "whatweb"
        args = [bin_path, target, "--log-json=/tmp/whatweb.json", "--quiet"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:3000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"whatweb failed (rc={rc}): {stderr[:200]}")
            return result

        import os
        if os.path.exists("/tmp/whatweb.json"):
            try:
                with open("/tmp/whatweb.json") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    for entry in data:
                        if isinstance(entry, dict):
                            for plugin, info in entry.items():
                                if plugin in ("target", "http_status", "http_headers", "ip", "country", "port", "protocol"):
                                    continue
                                version = ""
                                certainty = ""
                                if isinstance(info, dict):
                                    version = info.get("version", "")
                                    certainty = info.get("certainty", "")
                                val = f"{plugin}"
                                if version:
                                    val += f" v{version}"
                                if certainty:
                                    val += f" (certainty: {certainty}%)"
                                result.add("whatweb", "Tech", val, "found")
            except Exception:
                pass

        return result


class WFuzz(ExternalTool):
    name = "wfuzz"
    bin_name = "wfuzz"
    accepted_kinds = {"url", "domain"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 300.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "wfuzz"

        # PF"https://{target if not target.startswith('http') else target}/FUZZ"
        url = f"https://{target}/FUZZ" if not target.startswith("http") else f"{target}/FUZZ"
        args = [
            bin_path, "-w", "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
            "--hc", "404", url,
        ]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:3000]

        # Filter out known Python 3.14 deprecation noise from stderr
        clean_stderr = "\n".join(
            l for l in stderr.splitlines()
            if "UserWarning" not in l and "DeprecationWarning" not in l
        )

        if rc != 0 and not stdout.strip():
            if clean_stderr:
                result.errors.append(f"wfuzz failed (rc={rc}): {clean_stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line and "Target:" not in line and "Total requests:" not in line and "ID" not in line:
                parts = line.split()
                if len(parts) >= 6:
                    code = parts[2] if len(parts) > 2 else ""
                    payload = parts[-1] if parts else ""
                    if code and payload:
                        sev = "warn" if code.startswith("2") else "found"
                        result.add("wfuzz", f"HTTP {code}", payload[:160], sev)

        return result


class Httrack(ExternalTool):
    name = "httrack"
    bin_name = "httrack"
    accepted_kinds = {"url"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("httrack", "Note", "HTTrack is an interactive website copier. Run manually: httrack target -O /tmp/httrack_out", "info")
        return result


class Davtest(ExternalTool):
    name = "davtest"
    bin_name = "davtest"
    accepted_kinds = {"url", "domain"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 120.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "davtest"
        args = [bin_path, "-url", target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:3000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"davtest failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if "SUCCEED" in line or "succeed" in line.lower():
                result.add("davtest", "WebDAV", line[:160], "warn")
            elif "FAIL" in line or "fail" in line.lower():
                result.add("davtest", "WebDAV", line[:160], "info")

        return result


class Cadaver(ExternalTool):
    name = "cadaver"
    bin_name = "cadaver"
    accepted_kinds = {"url"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("cadaver", "Note", "Cadaver is an interactive WebDAV client. Run manually: cadaver target", "info")
        return result


class Commix(ExternalTool):
    name = "commix"
    bin_name = "commix"
    accepted_kinds = {"url"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 300.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "commix"
        args = [bin_path, "--url", target, "--batch"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:3000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"commix failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if "vulnerable" in line.lower() or "injection" in line.lower():
                result.add("commix", "Command Injection", line[:160], "error")
            elif "[+]" in line and "info" in line.lower():
                result.add("commix", "Info", line[:160], "found")

        return result


class Padbuster(ExternalTool):
    name = "padbuster"
    bin_name = "padbuster"
    accepted_kinds = {"url"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("padbuster", "Note", "Padbuster is a manual padding oracle attack tool. Run manually: padbuster target encrypted_sample block_size", "info")
        return result


class Slowhttptest(ExternalTool):
    name = "slowhttptest"
    bin_name = "slowhttptest"
    accepted_kinds = {"url", "domain"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 120.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "slowhttptest"
        args = [bin_path, "-c", "1000", "-H", "-i", "10", "-r", "200", "-t", "GET", "-u", target, "-l", "30"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:3000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"slowhttptest failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if "slow" in line.lower() or "timeout" in line.lower() or "connections" in line.lower():
                result.add("slowhttptest", "DoS Test", line[:160], "warn")

        result.add("slowhttptest", "Note", "Slow HTTP DoS test completed. Review output above for server behavior.", "info")

        return result


class Siege(ExternalTool):
    name = "siege"
    bin_name = "siege"
    accepted_kinds = {"url"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 120.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "siege"
        args = [bin_path, "-b", "-t30s", target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:3000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"siege failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if "Availability" in line or "Elapsed" in line or "Transaction" in line or "Resp" in line:
                result.add("siege", "Load Test", line[:160], "found")

        return result


class Joomscan(ExternalTool):
    name = "joomscan"
    bin_name = "joomscan"
    accepted_kinds = {"url"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 300.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "joomscan"
        args = [bin_path, "-u", target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:3000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"joomscan failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if "[+]" in line or "[!]" in line or "[*]" in line:
                sev = "warn" if "[!]" in line else "found"
                result.add("joomscan", "Joomla", line[:160], sev)

        return result


class Subjack(ExternalTool):
    name = "subjack"
    bin_name = "subjack"
    accepted_kinds = {"domain"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 120.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "subjack"
        cfg = "/usr/share/subjack/fingerprints.json"
        args = [bin_path, "-d", target, "-c", cfg, "-t", "50", "-ssl", "-v"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:3000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"subjack failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line and "is vulnerable" in line.lower() or "vulnerable" in line.lower():
                result.add("subjack", "Takeover", line[:160], "error")
            elif line and "not vulnerable" in line.lower():
                result.add("subjack", "Not Vulnerable", line[:160], "info")

        return result


class Sublist3r(ExternalTool):
    name = "sublist3r"
    bin_name = "sublist3r"
    accepted_kinds = {"domain"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 180.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "sublist3r"
        args = [bin_path, "-d", target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:3000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"sublist3r failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("[-]") and not line.startswith("[!]") and not line.startswith("[*]"):
                if "." in line and target.replace(".", "") in line.replace(".", ""):
                    result.add("sublist3r", "Subdomain", line[:160], "found")

        return result


class SpiderFoot(ExternalTool):
    name = "spiderfoot"
    bin_name = "spiderfoot"
    accepted_kinds = {"domain", "email", "username"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 300.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "spiderfoot"
        # Use -u all (use-case all modules) instead of -t all (event types)
        # and -o json for structured output; avoid -q (hides errors too)
        args = [bin_path, "-s", target, "-u", "all", "-o", "json"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:3000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"spiderfoot failed (rc={rc}): {stderr[:200]}")
            return result

        # Parse JSON lines output
        for line in stdout.splitlines()[:200]:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                event_type = item.get("type", "")
                data = item.get("data", "")
                module = item.get("module", "spiderfoot")
                if data:
                    result.add("spiderfoot", f"{module}:{event_type}", str(data)[:160], "found")
            except (json.JSONDecodeError, TypeError):
                # Fallback: raw line
                if "|" in line or "[+]" in line:
                    result.add("spiderfoot", "OSINT", line[:160], "found")

        return result


class WCVS(ExternalTool):
    name = "wcvs"
    bin_name = "wcvs"
    accepted_kinds = {"url", "domain"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 300.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "wcvs"
        args = [bin_path, "-t", target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:3000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"wcvs failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line and ("vuln" in line.lower() or "cve" in line.lower() or "warning" in line.lower()):
                result.add("wcvs", "Vulnerability", line[:160], "warn")

        return result


class Raven(ExternalTool):
    name = "raven"
    bin_name = "raven"
    accepted_kinds = {"url", "domain"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 180.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "raven"
        args = [bin_path, target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:3000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"raven failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line and ("[" in line or "]" in line):
                result.add("raven", "Recon", line[:160], "found")

        return result
