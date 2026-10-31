"""Network extras — arp-scan, dnschef, dnstracer, dnsmap, dnswalk, tcpdump, whois, etc."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class ArpScan(ExternalTool):
    name = "arp-scan"
    bin_name = "arp-scan"
    accepted_kinds = {"ip", "interface"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        bin_path = shutil.which(cls.bin_name) or "arp-scan"
        args = [bin_path, target, "--localnet"]
        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]
        if rc != 0 and not stdout.strip():
            result.errors.append(f"arp-scan failed (rc={rc}): {stderr[:200]}")
            return result
        for line in stdout.splitlines():
            line = line.strip()
            if line and "\t" in line:
                parts = line.split("\t")
                if len(parts) >= 2:
                    result.add("arp-scan", "Device", f"{parts[0]}  →  {parts[1]}", "found")
        return result


class ArpSpoof(ExternalTool):
    name = "arpspoof"
    bin_name = "arpspoof"
    accepted_kinds = {"interface", "ip"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("arpspoof", "Note", "Interactive ARP spoofing tool. Needs root. Run manually: sudo arpspoof -i <interface> -t <target> <gateway>", "warn")
        return result


class DnsSpoof(ExternalTool):
    name = "dnsspoof"
    bin_name = "dnsspoof"
    accepted_kinds = {"interface", "file"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("dnsspoof", "Note", "Interactive DNS spoofing tool. Run manually: sudo dnsspoof -i <interface> [-f <hosts_file>]", "warn")
        return result


class UrlSnarf(ExternalTool):
    name = "urlsnarf"
    bin_name = "urlsnarf"
    accepted_kinds = {"interface"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("urlsnarf", "Note", "HTTP URL sniffer. Needs root. Run manually: sudo urlsnarf -i <interface>", "warn")
        return result


class MailSnarf(ExternalTool):
    name = "mailsnarf"
    bin_name = "mailsnarf"
    accepted_kinds = {"interface"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("mailsnarf", "Note", "Interactive email sniffer. Run manually: sudo mailsnarf -i <interface>", "warn")
        return result


class FileSnarf(ExternalTool):
    name = "filesnarf"
    bin_name = "filesnarf"
    accepted_kinds = {"interface"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("filesnarf", "Note", "Interactive file sniffer. Run manually: sudo filesnarf -i <interface>", "warn")
        return result


class MsgSnarf(ExternalTool):
    name = "msgsnarf"
    bin_name = "msgsnarf"
    accepted_kinds = {"interface"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("msgsnarf", "Note", "Interactive message sniffer. Run manually: sudo msgsnarf -i <interface>", "warn")
        return result


class Webmitm(ExternalTool):
    name = "webmitm"
    bin_name = "webmitm"
    accepted_kinds = {"interface"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("webmitm", "Note", "Interactive web MITM tool. Run manually: sudo webmitm -i <interface>", "warn")
        return result


class Sshmitm(ExternalTool):
    name = "sshmitm"
    bin_name = "sshmitm"
    accepted_kinds = {"interface"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("sshmitm", "Note", "Interactive SSH MITM tool. Run manually: sudo sshmitm -i <interface>", "warn")
        return result


class Dnschef(ExternalTool):
    name = "dnschef"
    bin_name = "dnschef"
    accepted_kinds = {"interface", "ip"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        bin_path = shutil.which(cls.bin_name) or "dnschef"
        args = [bin_path, "--fakeip", target, "--interface", "0.0.0.0", "-q"]
        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]
        if rc != 0 and not stdout.strip():
            result.errors.append(f"dnschef failed (rc={rc}): {stderr[:200]}")
            return result
        for line in stdout.splitlines():
            line = line.strip()
            if line:
                result.add("dnschef", "Output", line[:160], "info")
        return result


class Dnstracer(ExternalTool):
    name = "dnstracer"
    bin_name = "dnstracer"
    accepted_kinds = {"domain"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        bin_path = shutil.which(cls.bin_name) or "dnstracer"
        args = [bin_path, target]
        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]
        if rc != 0 and not stdout.strip():
            result.errors.append(f"dnstracer failed (rc={rc}): {stderr[:200]}")
            return result
        for line in stdout.splitlines():
            line = line.strip()
            if line:
                result.add("dnstracer", "Hop", line[:160], "found")
        return result


class Dnsmap(ExternalTool):
    name = "dnsmap"
    bin_name = "dnsmap"
    accepted_kinds = {"domain"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 180.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        bin_path = shutil.which(cls.bin_name) or "dnsmap"
        args = [bin_path, target, "-r", "/tmp/dnsmap_out"]
        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]
        if rc != 0 and not stdout.strip():
            result.errors.append(f"dnsmap failed (rc={rc}): {stderr[:200]}")
            return result
        for line in stdout.splitlines():
            line = line.strip()
            if line and ("IP" in line or ":" in line):
                result.add("dnsmap", "Record", line[:160], "found")
        return result


class Dnswalk(ExternalTool):
    name = "dnswalk"
    bin_name = "dnswalk"
    accepted_kinds = {"domain"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 120.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        bin_path = shutil.which(cls.bin_name) or "dnswalk"
        args = [bin_path, f"{target}."]
        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]
        if rc != 0 and not stdout.strip():
            result.errors.append(f"dnswalk failed (rc={rc}): {stderr[:200]}")
            return result
        for line in stdout.splitlines():
            line = line.strip()
            if line and "FAIL" in line:
                result.add("dnswalk", "Warning", line[:160], "warn")
            elif line:
                result.add("dnswalk", "Record", line[:160], "info")
        return result


class Ncat(ExternalTool):
    name = "ncat"
    bin_name = "ncat"
    accepted_kinds = {"ip", "port"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("ncat", "Note", "Versatile networking tool (Netcat with SSL). Run manually: ncat -v <host> <port>", "info")
        return result


class Netcat(ExternalTool):
    name = "netcat"
    bin_name = "netcat"
    accepted_kinds = {"ip", "port"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("netcat", "Note", "Networking tool. Run manually: nc -v <host> <port>", "info")
        return result


class Nping(ExternalTool):
    name = "nping"
    bin_name = "nping"
    accepted_kinds = {"ip", "domain"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        bin_path = shutil.which(cls.bin_name) or "nping"
        args = [bin_path, target, "-c", "5"]
        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]
        if rc != 0 and not stdout.strip():
            result.errors.append(f"nping failed (rc={rc}): {stderr[:200]}")
            return result
        for line in stdout.splitlines():
            line = line.strip()
            if line and ("RTT" in line or "max" in line or "rcvd" in line or "SENT" in line or "RCVD" in line):
                result.add("nping", "Probe", line[:160], "found")
        return result


class Hping3(ExternalTool):
    name = "hping3"
    bin_name = "hping3"
    accepted_kinds = {"ip"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        bin_path = shutil.which(cls.bin_name) or "hping3"
        args = [bin_path, target, "-c", "3", "-S"]
        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]
        if rc != 0 and not stdout.strip():
            result.errors.append(f"hping3 failed (rc={rc}): {stderr[:200]}")
            return result
        for line in stdout.splitlines():
            line = line.strip()
            if line and ("len" in line or "flags" in line or "hop" in line):
                result.add("hping3", "Response", line[:160], "found")
        return result


class Tcpdump(ExternalTool):
    name = "tcpdump"
    bin_name = "tcpdump"
    accepted_kinds = {"interface", "file"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        # If target looks like a file path, read the capture
        if any(target.endswith(ext) for ext in [".pcap", ".pcapng", ".cap"]):
            bin_path = shutil.which(cls.bin_name) or "tcpdump"
            args = [bin_path, "-r", target]
            rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
            result = ScanResult(target=target, module=f"external:{cls.name}")
            result.raw["return_code"] = rc
            result.raw["stdout"] = stdout[:30000]
            result.raw["stderr"] = stderr[:3000]
            if rc != 0 and not stdout.strip():
                result.errors.append(f"tcpdump failed (rc={rc}): {stderr[:200]}")
                return result
            for line in stdout.splitlines()[:200]:
                line = line.strip()
                if line:
                    result.add("tcpdump", "Packet", line[:160], "info")
            return result
        # Live capture — needs root / interactive
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("tcpdump", "Note", "Live packet capture needs root. Run manually: sudo tcpdump -i <interface>", "warn")
        return result


class Whois(ExternalTool):
    name = "whois"
    bin_name = "whois"
    accepted_kinds = {"domain", "ip"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        bin_path = shutil.which(cls.bin_name) or "whois"
        args = [bin_path, target]
        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:3000]
        if rc != 0 and not stdout.strip():
            result.errors.append(f"whois failed (rc={rc}): {stderr[:200]}")
            return result
        for line in stdout.splitlines():
            line = line.strip()
            low = line.lower()
            if low.startswith("registrar:"):
                result.add("whois", "Registrar", line.split(":", 1)[1].strip()[:160], "found")
            elif low.startswith("name server:"):
                result.add("whois", "Name Server", line.split(":", 1)[1].strip()[:160], "found")
            elif "creation date" in low or "created" in low:
                result.add("whois", "Creation Date", line.split(":", 1)[1].strip()[:160], "found")
        return result
