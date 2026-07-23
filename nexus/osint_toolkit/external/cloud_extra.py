"""Docker — Container engine."""

from __future__ import annotations

import shutil

from ..models import ScanResult
from .base import ExternalTool


class Docker(ExternalTool):
    name = "docker"
    bin_name = "docker"
    accepted_kinds = {"keyword", "file"}

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

        bin_path = shutil.which(cls.bin_name) or "docker"
        result = ScanResult(target=target, module=f"external:{cls.name}")

        args_ps = [bin_path, "ps", "-a"]
        rc, stdout, stderr = await cls._run_subprocess(args_ps, timeout=timeout)
        result.raw["containers_stdout"] = stdout[:20000]
        result.raw["containers_stderr"] = stderr[:4000]
        if rc != 0:
            result.errors.append(f"docker ps -a failed (rc={rc}): {stderr[:200]}")
        else:
            for line in stdout.splitlines():
                line = line.strip()
                if line and not line.startswith("CONTAINER"):
                    result.add("docker", "Container", line[:200], "info")

        args_images = [bin_path, "images"]
        rc2, stdout2, stderr2 = await cls._run_subprocess(args_images, timeout=timeout)
        result.raw["images_stdout"] = stdout2[:20000]
        result.raw["images_stderr"] = stderr2[:4000]
        if rc2 != 0:
            result.errors.append(f"docker images failed (rc={rc2}): {stderr2[:200]}")
        else:
            for line in stdout2.splitlines():
                line = line.strip()
                if line and not line.startswith("REPOSITORY"):
                    result.add("docker", "Image", line[:200], "info")

        return result
