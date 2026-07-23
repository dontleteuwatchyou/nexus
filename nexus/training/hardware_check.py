#!/usr/bin/env python3
"""Report whether a host is ready for Nexus inference or QLoRA training."""

from __future__ import annotations

import json
import os
import platform
import shutil
from pathlib import Path


def memory_gib() -> float:
    if Path("/proc/meminfo").exists():
        line = Path("/proc/meminfo").read_text().splitlines()[0]
        return int(line.split()[1]) / 1024 / 1024
    return 0.0


def report() -> dict:
    result = {
        "os": platform.platform(),
        "cpu_threads": os.cpu_count() or 1,
        "ram_gib": round(memory_gib(), 1),
        "disk_free_gib": round(shutil.disk_usage(Path.home()).free / 1024**3, 1),
        "cuda": False,
        "gpu": None,
        "vram_gib": 0.0,
    }
    try:
        import torch

        result["cuda"] = torch.cuda.is_available()
        if result["cuda"]:
            result["gpu"] = torch.cuda.get_device_name(0)
            result["vram_gib"] = round(
                torch.cuda.get_device_properties(0).total_memory / 1024**3, 1
            )
    except ImportError:
        pass
    result["core_ready"] = result["ram_gib"] >= 4
    result["local_4b_ready"] = result["ram_gib"] >= 8
    result["qlora_4b_ready"] = result["cuda"] and result["vram_gib"] >= 10
    result["qlora_8b_ready"] = result["cuda"] and result["vram_gib"] >= 16
    return result


if __name__ == "__main__":
    print(json.dumps(report(), indent=2, ensure_ascii=False))
