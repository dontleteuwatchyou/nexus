"""Passive fingerprinting — p0f, sslyze, sslscan, responder, dsniff, etc."""

from __future__ import annotations

import json
import os
import shutil

from ..models import ScanResult
from .base import ExternalTool


class P0f(ExternalTool):
    name = "p0f"
    bin_name = "p0f"
    accepted_kinds = {"interface", "file"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("p0f", "Note", "Passive OS fingerprinting. Needs root: p0f -i <interface>", "info")
        return result


class Sslyze(ExternalTool):
    name = "sslyze"
    bin_name = "sslyze"
    accepted_kinds = {"domain", "ip"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 180.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        import tempfile
        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        tmp.close()
        bin_path = shutil.which(cls.bin_name) or "sslyze"
        args = [
            bin_path, target,
            "--tlsv1_3", "--tlsv1_2", "--tlsv1_1", "--tlsv1",
            "--heartbleed", "--compression", "--reneg", "--fallback", "--robot",
            "--certinfo", "--http_headers",
            "--json_out", tmp.name,
        ]
        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:3000]
        if rc != 0 and not stdout.strip():
            result.errors.append(f"sslyze failed (rc={rc}): {stderr[:200]}")
            return result
        try:
            with open(tmp.name) as f:
                data = json.load(f)
            for server in data.get("server_scan_results", []):
                for scan_cmd, cmd_result in server.get("scan_commands", {}).items():
                    if cmd_result.get("result") == "completed":
                        for vuln, vdata in cmd_result.items():
                            if isinstance(vdata, dict) and vdata.get("result") == "vulnerable":
                                result.add("sslyze", f"{scan_cmd}", f"{vuln}: VULNERABLE", "error")
                            elif isinstance(vdata, dict) and vdata.get("result") == "accepted":
                                result.add("sslyze", f"{scan_cmd}", f"{vuln}: accepted", "found")
        except Exception:
            for line in stdout.splitlines():
                line = line.strip()
                if any(k in line for k in ["TLS", "certificate", "cipher"]):
                    result.add("sslyze", "SSL", line[:160], "found")
        try:
            os.unlink(tmp.name)
        except Exception:
            pass
        return result


class Sslscan(ExternalTool):
    name = "sslscan"
    bin_name = "sslscan"
    accepted_kinds = {"domain", "ip"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 120.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        bin_path = shutil.which(cls.bin_name) or "sslscan"
        args = [bin_path, "--no-colour", target]
        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:3000]
        if rc != 0 and not stdout.strip():
            result.errors.append(f"sslscan failed (rc={rc}): {stderr[:200]}")
            return result
        for line in stdout.splitlines():
            line = line.strip()
            if "accepted" in line.lower() or "rejected" in line.lower() or "vulnerable" in line.lower():
                sev = "error" if "rejected" in line.lower() else "found"
                result.add("sslscan", "Cipher", line[:160], sev)
        return result


class Responder(ExternalTool):
    name = "responder"
    bin_name = "responder"
    accepted_kinds = {"interface"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("responder", "Note", "LLMNR/NBT-NS/mDNS poisoner. Needs root: responder -I <interface> -wrf", "info")
        return result


class Dsniff(ExternalTool):
    name = "dsniff"
    bin_name = "dsniff"
    accepted_kinds = {"interface"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("dsniff", "Note", "Network sniffer suite (dsniff, filesnarf, urlsnarf). Needs root.", "info")
        return result


class Tcpflow(ExternalTool):
    name = "tcpflow"
    bin_name = "tcpflow"
    accepted_kinds = {"interface", "file"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("tcpflow", "Note", "TCP flow recorder. Needs root: tcpflow -i <interface> -o /tmp/", "info")
        return result


class Tcpreplay(ExternalTool):
    name = "tcpreplay"
    bin_name = "tcpreplay"
    accepted_kinds = {"file", "interface"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("tcpreplay", "Note", "Replay pcap files. Usage: tcpreplay -i <iface> <file.pcap>", "info")
        return result


class Wireshark(ExternalTool):
    name = "wireshark"
    bin_name = "wireshark"
    accepted_kinds = {"interface", "file"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 30.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("wireshark", "Note", "GUI packet analyzer. Also: tshark for CLI.", "info")
        return result


class Tshark(ExternalTool):
    name = "tshark"
    bin_name = "tshark"
    accepted_kinds = {"interface", "file"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0,
                   filter: str = "http or dns", max_packets: int = 100,
                   **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        bin_path = shutil.which(cls.bin_name) or "tshark"
        args = [bin_path, "-r", target, "-Y", filter, "-c", str(max_packets), "-T", "fields",
                "-e", "frame.protocols", "-e", "ip.src", "-e", "ip.dst", "-e", "http.host"]
        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:3000]
        for line in stdout.splitlines()[:50]:
            if line.strip():
                result.add("tshark", "Packet", line[:160], "found")
        return result


class Zeek(ExternalTool):
    name = "zeek"
    bin_name = "zeek"
    accepted_kinds = {"interface", "file"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 120.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        bin_path = shutil.which(cls.bin_name) or "zeek"
        args = [bin_path, "-r", target, "local", "Log::default_writer=Log::WRITER_ASCII"]
        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]
        result.add("zeek", "Note", "Zeek network analysis engine. Logs written to current dir.", "info")
        return result


class Mitm6(ExternalTool):
    name = "mitm6"
    bin_name = "mitm6"
    accepted_kinds = {"interface"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("mitm6", "Note", "IPv6 MITM framework. Needs root: mitm6 -i <interface> -d <domain>", "info")
        return result


class Sniffjoke(ExternalTool):
    name = "sniffjoke"
    bin_name = "sniffjoke"
    accepted_kinds = {"interface"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("sniffjoke", "Note", "Traffic obfuscation tool. Usage: sniffjoke", "info")
        return result


class Suricata(ExternalTool):
    name = "suricata"
    bin_name = "suricata"
    accepted_kinds = {"interface", "file"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 120.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("suricata", "Note", "IDS/IPS engine. Usage: suricata -r <pcap> or -i <iface>", "info")
        return result