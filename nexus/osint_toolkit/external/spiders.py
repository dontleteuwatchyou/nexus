"""Gospider / Hakrawler / Kiterunner — Web crawling & API recon."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class GoSpider(ExternalTool):
    name = "gospider"
    bin_name = "gospider"
    accepted_kinds = {"url", "domain"}

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

        bin_path = shutil.which(cls.bin_name) or "gospider"
        url = target if target.startswith("http") else f"https://{target}"
        args = [
            bin_path,
            "-s", url,
            "--sitemap",
            "--robots",
            "-a",
            "-w",
            "-r",
        ]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"gospider failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if "[url]" in line or "[link]" in line:
                result.add("gospider", "URL", line.split("]")[-1].strip()[:160], "found")
            elif "[js]" in line:
                result.add("gospider", "JS", line.split("]")[-1].strip()[:160], "info")
            elif "[form]" in line:
                result.add("gospider", "Form", line.split("]")[-1].strip()[:160], "warn")

        return result


class Hakrawler(ExternalTool):
    name = "hakrawler"
    bin_name = "hakrawler"
    accepted_kinds = {"url", "domain"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 180.0,
        depth: int = 2,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "hakrawler"
        hak_url = target if target.startswith("http") else f"https://{target}"
        args = [
            bin_path,
            "-d", str(depth),
            "-json",
            "-s",
        ]
        input_data = hak_url.encode()

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout, input_data=input_data)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"hakrawler failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("http"):
                result.add("hakrawler", "URL", line, "found")

        return result


class Kiterunner(ExternalTool):
    name = "kiterunner"
    bin_name = "kiterunner"
    accepted_kinds = {"url", "domain"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 300.0,
        wordlist: str = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "kiterunner"
        args = [
            bin_path,
            "brute", target,
            "-w", wordlist,
        ]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"kiterunner failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if line and "200" in line or "201" in line or "403" in line:
                result.add("kiterunner", "Route", line[:160], "found")

        return result