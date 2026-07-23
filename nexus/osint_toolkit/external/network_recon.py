"""Network recon tools — massdns, dnsrecon, dnsenum, fierce, netdiscover, etc."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class Massdns(ExternalTool):
    name = "massdns"
    bin_name = "massdns"
    accepted_kinds = {"domain"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 180.0,
                   wordlist: str = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
                   **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        bin_path = shutil.which(cls.bin_name) or "massdns"
        args = [bin_path, "-r", "/etc/resolv.conf", "-t", "A", "-o", "S", "-w", "/tmp/massdns_out.txt", wordlist]
        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]
        if rc != 0 and not stdout.strip():
            result.errors.append(f"massdns failed (rc={rc}): {stderr[:200]}")
            return result
        for line in stdout.splitlines()[:100]:
            if "." in line:
                result.add("massdns", "DNS Record", line[:160], "found")
        return result


class Dnsrecon(ExternalTool):
    name = "dnsrecon"
    bin_name = "dnsrecon"
    accepted_kinds = {"domain"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 180.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        bin_path = shutil.which(cls.bin_name) or "dnsrecon"
        args = [bin_path, "-d", target, "-t", "std", "--json", "/tmp/dnsrecon_out.json"]
        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]
        if rc != 0 and not stdout.strip():
            result.errors.append(f"dnsrecon failed (rc={rc}): {stderr[:200]}")
            return result
        for line in stdout.splitlines():
            line = line.strip()
            if any(k in line for k in ["[+]", "A", "AAAA", "MX", "NS", "CNAME", "SOA", "TXT", "SRV"]):
                result.add("dnsrecon", "Record", line[:160], "found")
        return result


class Dnsenum(ExternalTool):
    name = "dnsenum"
    bin_name = "dnsenum"
    accepted_kinds = {"domain"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 180.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        bin_path = shutil.which(cls.bin_name) or "dnsenum"
        args = [bin_path, target, "--noreverse", "-o", "/tmp/dnsenum_out.xml"]
        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]
        if rc != 0 and not stdout.strip():
            result.errors.append(f"dnsenum failed (rc={rc}): {stderr[:200]}")
            return result
        for line in stdout.splitlines():
            line = line.strip()
            if any(k in line for k in ["Host:", "Name Server", "Mail Server"]):
                result.add("dnsenum", line.split(":")[0], line.split(":", 1)[1].strip()[:160], "found")
        return result


class Fierce(ExternalTool):
    name = "fierce"
    bin_name = "fierce"
    accepted_kinds = {"domain"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 180.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        bin_path = shutil.which(cls.bin_name) or "fierce"
        args = [bin_path, "--domain", target]
        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]
        if rc != 0 and not stdout.strip():
            result.errors.append(f"fierce failed (rc={rc}): {stderr[:200]}")
            return result
        for line in stdout.splitlines():
            line = line.strip()
            if any(k in line for k in ["Found", "Host", "IP", "DNS"]) and line.startswith((" ", "\t")):
                result.add("fierce", "Finding", line[:160], "found")
        return result


class Netdiscover(ExternalTool):
    name = "netdiscover"
    bin_name = "netdiscover"
    accepted_kinds = {"ip", "interface"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("netdiscover", "Note", "Interactive ARP scanner. Needs root. Run: netdiscover -r <subnet>", "info")
        return result


class Nbtscan(ExternalTool):
    name = "nbtscan"
    bin_name = "nbtscan"
    accepted_kinds = {"ip"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        bin_path = shutil.which(cls.bin_name) or "nbtscan"
        args = [bin_path, target]
        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]
        if rc != 0 and not stdout.strip():
            result.errors.append(f"nbtscan failed (rc={rc}): {stderr[:200]}")
            return result
        for line in stdout.splitlines():
            if line.strip() and "<unknown>" not in line:
                result.add("nbtscan", "NetBIOS", line[:160], "found")
        return result


class Onesixone(ExternalTool):
    name = "onesixtyone"
    bin_name = "onesixtyone"
    accepted_kinds = {"ip"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 120.0,
                   wordlist: str = "/usr/share/seclists/Discovery/SNMP/wordlist-common.txt",
                   **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        bin_path = shutil.which(cls.bin_name) or "onesixtyone"
        args = [bin_path, "-c", wordlist, target]
        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]
        if rc != 0 and not stdout.strip():
            result.errors.append(f"onesixtyone failed (rc={rc}): {stderr[:200]}")
            return result
        for line in stdout.splitlines():
            if "[" in line and "]" in line:
                result.add("onesixtyone", "SNMP", line[:160], "warn")
        return result


class Braa(ExternalTool):
    name = "braa"
    bin_name = "braa"
    accepted_kinds = {"ip"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0,
                   community: str = "public", oid: str = ".1.3.6.1.2.1.1.1.0",
                   **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        bin_path = shutil.which(cls.bin_name) or "braa"
        args = [bin_path, f"{community}@{target}:{oid}"]
        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]
        if rc != 0 and not stdout.strip():
            result.errors.append(f"braa failed (rc={rc}): {stderr[:200]}")
            return result
        for line in stdout.splitlines():
            if line.strip() and ":" in line:
                result.add("braa", "SNMP OID", line[:160], "found")
        return result


class Snmpcheck(ExternalTool):
    name = "snmpcheck"
    bin_name = "snmpcheck"
    accepted_kinds = {"ip"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, community: str = "public", **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        bin_path = shutil.which(cls.bin_name) or "snmpcheck"
        args = [bin_path, "-t", target, "-c", community]
        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]
        if rc != 0 and not stdout.strip():
            result.errors.append(f"snmpcheck failed (rc={rc}): {stderr[:200]}")
            return result
        for line in stdout.splitlines():
            if line.strip() and ":" in line:
                result.add("snmpcheck", "Info", line[:160], "found")
        return result


class Fping(ExternalTool):
    name = "fping"
    bin_name = "fping"
    accepted_kinds = {"ip"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        bin_path = shutil.which(cls.bin_name) or "fping"
        args = [bin_path, "-a", "-g", target, "-q"]
        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]
        for line in stdout.splitlines():
            if line.strip():
                result.add("fping", "Alive", line[:160], "found")
        return result


class Ikescan(ExternalTool):
    name = "ike-scan"
    bin_name = "ike-scan"
    accepted_kinds = {"ip"}

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 120.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)
        bin_path = shutil.which(cls.bin_name) or "ike-scan"
        args = [bin_path, target, "--showbackoff"]
        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)
        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]
        if rc != 0 and not stdout.strip():
            result.errors.append(f"ike-scan failed (rc={rc}): {stderr[:200]}")
            return result
        for line in stdout.splitlines():
            if "SA" in line or "Vendor" in line or "transform" in line:
                result.add("ike-scan", "ISAKMP", line[:160], "found")
        return result