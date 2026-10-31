"""Scalpel / Foremost / Recoverdm / Recoverjpeg / ScroungeNtfs / Testdisk /
Magicrescue / Safecopy / Myrescue / Pasco / Rifiuti / Reglookup / Regripper /
Vinetto / Undbx / MacRobber / Missidentify / Pdfid / PdfParser —
Additional forensics & file recovery tools."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class Scalpel(ExternalTool):
    name = "scalpel"
    bin_name = "scalpel"
    accepted_kinds = {"file", "disk"}

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

        bin_path = shutil.which(cls.bin_name) or "scalpel"
        args = [bin_path, target, "-o", "/tmp/scalpel_out"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"scalpel failed (rc={rc}): {stderr[:200]}")
            return result

        result.add("scalpel", "Output", "Carved files written to /tmp/scalpel_out", "found")
        for line in stdout.splitlines():
            if "Carved" in line or "files" in line.lower():
                result.add("scalpel", "Summary", line[:160], "info")

        return result


class Foremost(ExternalTool):
    name = "foremost"
    bin_name = "foremost"
    accepted_kinds = {"file", "disk"}

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

        bin_path = shutil.which(cls.bin_name) or "foremost"
        args = [bin_path, "-t", "all", "-i", target, "-o", "/tmp/foremost_out"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"foremost failed (rc={rc}): {stderr[:200]}")
            return result

        result.add("foremost", "Output", "Carved files written to /tmp/foremost_out", "found")
        for line in stdout.splitlines():
            if line.strip() and ("FILES" in line or ":" in line):
                result.add("foremost", "Result", line[:160], "info")

        return result


class Recoverdm(ExternalTool):
    name = "recoverdm"
    bin_name = "recoverdm"
    accepted_kinds = {"disk", "file"}

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

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("recoverdm", "Note", "Recoverdm is a low-level data recovery tool. Run manually: recoverdm", "info")
        return result


class Recoverjpeg(ExternalTool):
    name = "recoverjpeg"
    bin_name = "recoverjpeg"
    accepted_kinds = {"file", "disk"}

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

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("recoverjpeg", "Note", "Recoverjpeg is an interactive JPEG recovery tool. Run manually: recoverjpeg", "info")
        return result


class ScroungeNtfs(ExternalTool):
    name = "scrounge-ntfs"
    bin_name = "scrounge-ntfs"
    accepted_kinds = {"disk", "file"}

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

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("scrounge-ntfs", "Note", "ScroungeNtfs is an NTFS data recovery tool. Run manually: scrounge-ntfs", "info")
        return result


class Testdisk(ExternalTool):
    name = "testdisk"
    bin_name = "testdisk"
    accepted_kinds = {"disk", "file"}

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

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("testdisk", "Note", "Testdisk is an interactive disk recovery tool. Run manually: testdisk /dev/sdX", "info")
        return result


class Magicrescue(ExternalTool):
    name = "magicrescue"
    bin_name = "magicrescue"
    accepted_kinds = {"disk", "file"}

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

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("magicrescue", "Note", "Magicrescue is a file recovery tool. Run manually: magicrescue", "info")
        return result


class Safecopy(ExternalTool):
    name = "safecopy"
    bin_name = "safecopy"
    accepted_kinds = {"disk", "file"}

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

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("safecopy", "Note", "Safecopy performs safe data recovery from damaged media. Run manually: safecopy", "info")
        return result


class Myrescue(ExternalTool):
    name = "myrescue"
    bin_name = "myrescue"
    accepted_kinds = {"disk", "file"}

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

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("myrescue", "Note", "Myrescue recovers data from damaged hard drives. Run manually: myrescue", "info")
        return result


class Pasco(ExternalTool):
    name = "pasco"
    bin_name = "pasco"
    accepted_kinds = {"file"}

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

        bin_path = shutil.which(cls.bin_name) or "pasco"
        args = [bin_path, target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"pasco failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines()[:100]:
            if line.strip():
                result.add("pasco", "Cache entry", line[:200], "info")

        return result


class Rifiuti(ExternalTool):
    name = "rifiuti"
    bin_name = "rifiuti"
    accepted_kinds = {"file"}

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

        bin_path = shutil.which(cls.bin_name) or "rifiuti"
        args = [bin_path, target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"rifiuti failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines()[:100]:
            if line.strip():
                result.add("rifiuti", "Recycle bin entry", line[:200], "info")

        return result


class Reglookup(ExternalTool):
    name = "reglookup"
    bin_name = "reglookup"
    accepted_kinds = {"file"}

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

        bin_path = shutil.which(cls.bin_name) or "reglookup"
        args = [bin_path, target, "-o", "/tmp/reg_out.txt"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"reglookup failed (rc={rc}): {stderr[:200]}")
            return result

        result.add("reglookup", "Output", "Registry parsed to /tmp/reg_out.txt", "found")
        for line in stdout.splitlines()[:50]:
            if line.strip():
                result.add("reglookup", "Key", line[:200], "info")

        return result


class Regripper(ExternalTool):
    name = "regripper"
    bin_name = "regripper"
    accepted_kinds = {"file"}

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
        result.add("regripper", "Note", "Regripper is a CLI registry analysis tool. Run manually: regripper", "info")
        return result


class Vinetto(ExternalTool):
    name = "vinetto"
    bin_name = "vinetto"
    accepted_kinds = {"file"}

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

        bin_path = shutil.which(cls.bin_name) or "vinetto"
        args = [bin_path, target, "-o", "/tmp/vinetto_out"]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"vinetto failed (rc={rc}): {stderr[:200]}")
            return result

        result.add("vinetto", "Output", "Thumbs.db data extracted to /tmp/vinetto_out", "found")
        for line in stdout.splitlines()[:50]:
            if line.strip():
                result.add("vinetto", "Entry", line[:160], "info")

        return result


class Undbx(ExternalTool):
    name = "undbx"
    bin_name = "undbx"
    accepted_kinds = {"file"}

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

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("undbx", "Note", "Undbx recovers Outlook Express mailbox data. Run manually: undbx", "info")
        return result


class MacRobber(ExternalTool):
    name = "mac-robber"
    bin_name = "mac-robber"
    accepted_kinds = {"disk", "file"}

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

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("mac-robber", "Note", "MacRobber collects MAC times for forensic analysis. Run manually: mac-robber", "info")
        return result


class Missidentify(ExternalTool):
    name = "missidentify"
    bin_name = "missidentify"
    accepted_kinds = {"file"}

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
        result.add("missidentify", "Note", "Missidentify identifies file types. Run manually: missidentify target", "info")
        return result


class Pdfid(ExternalTool):
    name = "pdfid"
    bin_name = "pdfid"
    accepted_kinds = {"file"}

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

        bin_path = shutil.which(cls.bin_name) or "pdfid"
        args = [bin_path, target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"pdfid failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines():
            if "PDF Header" in line or "obj" in line or "stream" in line:
                result.add("pdfid", "Indicator", line[:160], "found")

        return result


class PdfParser(ExternalTool):
    name = "pdf-parser"
    bin_name = "pdf-parser"
    accepted_kinds = {"file"}

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

        bin_path = shutil.which(cls.bin_name) or "pdf-parser"
        args = [bin_path, target]

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"pdf-parser failed (rc={rc}): {stderr[:200]}")
            return result

        for line in stdout.splitlines()[:100]:
            if line.strip():
                result.add("pdf-parser", "Object", line[:200], "info")

        return result
