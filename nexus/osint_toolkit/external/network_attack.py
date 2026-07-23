"""DHCP / VoIP attacks, port scanners, Oracle / S3 / SCTP scanners,
SMTP user enumeration, email-to-phone, and AWS IAM enumeration."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class Dhcpig(ExternalTool):
    name = "dhcpig"
    bin_name = "dhcpig"
    accepted_kinds = {"interface"}

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
        result.add("dhcpig", "Note", "DHCP exhaustion attack tool. Run manually: dhcpig", "info")
        return result


class Iaxflood(ExternalTool):
    name = "iaxflood"
    bin_name = "iaxflood"
    accepted_kinds = {"ip", "domain"}

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
        result.add("iaxflood", "Note", "VoIP flood tool. Run manually: iaxflood", "info")
        return result


class Unicornscan(ExternalTool):
    name = "unicornscan"
    bin_name = "unicornscan"
    accepted_kinds = {"ip", "domain"}

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

        bin_path = shutil.which(cls.bin_name) or "unicornscan"
        args = [bin_path, f"{target}:1-1000"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"unicornscan failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line and ("open" in line or "tcp" in line or "udp" in line):
                result.add("unicornscan", "Port", line[:160], "found")

        return result


class Oscanner(ExternalTool):
    name = "oscanner"
    bin_name = "oscanner"
    accepted_kinds = {"ip", "domain"}

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

        bin_path = shutil.which(cls.bin_name) or "oscanner"
        args = [bin_path, "-s", target, "-P", "1521"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"oscanner failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line and ("Oracle" in line or "SID" in line or "open" in line):
                result.add("oscanner", "Oracle", line[:160], "found")

        return result


class S3scanner(ExternalTool):
    name = "s3scanner"
    bin_name = "s3scanner"
    accepted_kinds = {"domain", "keyword"}

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

        bin_path = shutil.which(cls.bin_name) or "s3scanner"
        args = [bin_path, "-bucket", target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"s3scanner failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line and ("found" in line or "public" in line or "exists" in line):
                result.add("s3scanner", "S3 Bucket", line[:160], "found")

        return result


class Sctpscan(ExternalTool):
    name = "sctpscan"
    bin_name = "sctpscan"
    accepted_kinds = {"ip", "domain"}

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

        bin_path = shutil.which(cls.bin_name) or "sctpscan"
        args = [bin_path, target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"sctpscan failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line:
                result.add("sctpscan", "SCTP", line[:160], "found")

        return result


class SmtpUserEnum(ExternalTool):
    name = "smtp-user-enum"
    bin_name = "smtp-user-enum"
    accepted_kinds = {"ip", "domain"}

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

        bin_path = shutil.which(cls.bin_name) or "smtp-user-enum"
        args = [
            bin_path, "-M", "VRFY",
            "-U", "/usr/share/seclists/Usernames/Names/names.txt",
            "-t", target,
        ]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"smtp-user-enum failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line and ("exists" in line or "found" in line or "252" in line):
                result.add("smtp-user-enum", "User", line[:160], "found")

        return result


class Emails2phonenumber(ExternalTool):
    name = "emails2phonenumber"
    bin_name = "emails2phonenumber"
    accepted_kinds = {"email"}

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

        bin_path = shutil.which(cls.bin_name) or "emails2phonenumber"
        args = [bin_path, "-e", target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:30000]
        result.raw["stderr"] = stderr[:3000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"emails2phonenumber failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line and ("phone" in line or "@" in line or "+" in line):
                result.add("emails2phonenumber", "Info", line[:160], "found")

        return result


class EnumerateIam(ExternalTool):
    name = "enumerate-iam"
    bin_name = "enumerate-iam"
    accepted_kinds = {"aws", "keyword"}

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
        result.add("enumerate-iam", "Note", "AWS IAM enumeration tool. Run manually: enumerate-iam", "info")
        return result
