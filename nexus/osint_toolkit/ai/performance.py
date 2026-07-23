"""Hardware-aware runtime profiles for Nexus AI.

The detector intentionally relies on the standard library and ``nvidia-smi``.
It remains useful before the optional training stack (PyTorch, CUDA bindings)
is installed and never sends hardware information over the network.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from functools import lru_cache


@dataclass(frozen=True)
class HardwareInfo:
    cpu_threads: int
    ram_gib: float
    gpu_name: str | None = None
    vram_gib: float = 0.0

    @property
    def has_cuda_gpu(self) -> bool:
        return bool(self.gpu_name and self.vram_gib >= 2)


@dataclass(frozen=True)
class AIProfile:
    name: str
    description: str
    model: str | None
    context_size: int
    max_tokens: int
    cpu_threads: int
    gpu_layers: int = 0

    @property
    def uses_model(self) -> bool:
        return self.model is not None


def _ram_gib() -> float:
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        return round(pages * page_size / 1024**3, 1)
    except (AttributeError, OSError, ValueError):
        return 0.0


def _nvidia_gpu() -> tuple[str | None, float]:
    binary = shutil.which("nvidia-smi")
    if not binary:
        return None, 0.0
    try:
        result = subprocess.run(
            [
                binary,
                "--query-gpu=name,memory.total",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            check=False,
            text=True,
            timeout=3,
        )
        first = result.stdout.splitlines()[0]
        name, memory_mib = (part.strip() for part in first.rsplit(",", 1))
        return name, round(float(memory_mib) / 1024, 1)
    except (IndexError, OSError, subprocess.SubprocessError, ValueError):
        return None, 0.0


@lru_cache(maxsize=1)
def detect_hardware() -> HardwareInfo:
    """Return a conservative local hardware snapshot."""
    gpu_name, vram_gib = _nvidia_gpu()
    return HardwareInfo(
        cpu_threads=max(1, os.cpu_count() or 1),
        ram_gib=_ram_gib(),
        gpu_name=gpu_name,
        vram_gib=vram_gib,
    )


def available_profiles(hardware: HardwareInfo) -> dict[str, AIProfile]:
    threads = max(1, min(hardware.cpu_threads, 12))
    return {
        "core": AIProfile(
            "core", "Routage déterministe, aucun modèle requis", None, 0, 0, threads
        ),
        "lite": AIProfile(
            "lite",
            "Petit modèle pour machines à mémoire limitée",
            "ggml-org/Qwen3-0.6B-GGUF:Q4_0",
            2048,
            128,
            min(threads, 4),
        ),
        "compact": AIProfile(
            "compact",
            "Assistant local léger pour CPU courant",
            "ggml-org/Qwen3-1.7B-GGUF:Q4_K_M",
            3072,
            180,
            min(threads, 8),
        ),
        "balanced": AIProfile(
            "balanced",
            "Équilibre qualité, mémoire et vitesse",
            "Qwen/Qwen3-4B-GGUF:Q4_K_M",
            4096,
            256,
            threads,
            999 if hardware.has_cuda_gpu else 0,
        ),
        "performance": AIProfile(
            "performance",
            "Qualité supérieure avec accélération GPU",
            "Qwen/Qwen3-8B-GGUF:Q4_K_M",
            8192,
            384,
            threads,
            999,
        ),
    }


def select_profile(
    hardware: HardwareInfo | None = None, requested: str | None = None
) -> AIProfile:
    """Choose a safe profile, while allowing an explicit valid override."""
    hardware = hardware or detect_hardware()
    profiles = available_profiles(hardware)
    requested = (requested or os.getenv("NEXUS_AI_PROFILE", "auto")).strip().lower()
    if requested != "auto":
        if requested not in profiles:
            choices = ", ".join(("auto", *profiles))
            raise ValueError(f"Profil IA inconnu: {requested}. Choix: {choices}")
        return profiles[requested]

    if hardware.has_cuda_gpu and hardware.vram_gib >= 10 and hardware.ram_gib >= 12:
        return profiles["performance"]
    if hardware.has_cuda_gpu and hardware.vram_gib >= 5 and hardware.ram_gib >= 8:
        return profiles["balanced"]
    if hardware.ram_gib and hardware.ram_gib < 3:
        return profiles["core"]
    if hardware.ram_gib and hardware.ram_gib < 6:
        return profiles["lite"]
    if hardware.ram_gib and hardware.ram_gib < 10:
        return profiles["compact"]
    if hardware.cpu_threads <= 4:
        return profiles["compact"]
    return profiles["balanced"]


def runtime_report(requested: str | None = None) -> dict:
    hardware = detect_hardware()
    effective_request = requested or os.getenv("NEXUS_AI_PROFILE", "auto")
    profile = select_profile(hardware, effective_request)
    return {
        "platform": platform.platform(),
        "hardware": asdict(hardware),
        "profile": asdict(profile),
        "selection": "manual" if effective_request != "auto" else "automatic",
    }


def _command_output(args: list[str], timeout: float = 2.0) -> str:
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def collect_live_metrics(
    container: str = "nexus-ai-local", port: int = 8080
) -> dict[str, object]:
    """Collect one non-throwing snapshot for the TUI and terminal monitor."""
    metrics: dict[str, object] = {
        "server": "offline",
        "container": "stopped",
        "cpu": "—",
        "ram": "—",
        "gpu": "—",
        "vram": "—",
        "temperature": "—",
        "power": "—",
    }
    try:
        request = urllib.request.Request(f"http://127.0.0.1:{port}/health")
        with urllib.request.urlopen(request, timeout=0.5) as response:
            if response.status == 200:
                metrics["server"] = "ready"
    except (OSError, urllib.error.URLError):
        pass

    inspect = _command_output(
        ["docker", "inspect", "--format", "{{.State.Running}}", container]
    )
    if inspect == "true":
        metrics["container"] = "running"
        raw = _command_output(
            ["docker", "stats", "--no-stream", "--format", "{{json .}}", container],
            timeout=3,
        )
        try:
            stats = json.loads(raw)
            metrics["cpu"] = stats.get("CPUPerc", "—")
            metrics["ram"] = stats.get("MemUsage", "—")
        except (json.JSONDecodeError, TypeError):
            pass

    gpu = _command_output(
        [
            "nvidia-smi",
            "--query-gpu=utilization.gpu,memory.used,memory.total,"
            "temperature.gpu,power.draw",
            "--format=csv,noheader,nounits",
        ]
    )
    if gpu:
        try:
            utilisation, used, total, temperature, power = (
                part.strip() for part in gpu.splitlines()[0].split(",")
            )
            metrics["gpu"] = f"{utilisation}%"
            metrics["vram"] = f"{used}/{total} MiB"
            metrics["temperature"] = f"{temperature}°C"
            metrics["power"] = f"{power} W"
        except ValueError:
            pass
    return metrics


def format_live_metrics(metrics: dict[str, object], markup: bool = False) -> str:
    ready = metrics["server"] == "ready"
    if markup:
        status = "[#4ade80]READY[/]" if ready else "[#ef4444]OFFLINE[/]"
        return (
            f"[bold #f59e0b]NEXUS AI[/] {status}  "
            f"[dim]CPU[/] {metrics['cpu']}  [dim]RAM[/] {metrics['ram']}  "
            f"[dim]GPU[/] {metrics['gpu']}  [dim]VRAM[/] {metrics['vram']}  "
            f"[dim]TEMP[/] {metrics['temperature']}  [dim]POWER[/] {metrics['power']}"
        )
    status = "READY" if ready else "OFFLINE"
    return (
        f"NEXUS AI {status} | CPU {metrics['cpu']} | RAM {metrics['ram']} | "
        f"GPU {metrics['gpu']} | VRAM {metrics['vram']} | "
        f"TEMP {metrics['temperature']} | POWER {metrics['power']}"
    )


def watch_metrics(interval: float = 2.0) -> None:
    """Render live inference resources until interrupted."""
    try:
        while True:
            print("\033[2J\033[H" + format_live_metrics(collect_live_metrics()))
            print("Ctrl+C pour quitter")
            time.sleep(max(0.5, interval))
    except KeyboardInterrupt:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect Nexus AI adaptive runtime")
    parser.add_argument(
        "--profile",
        default=os.getenv("NEXUS_AI_PROFILE", "auto"),
        help="auto, core, lite, compact, balanced or performance",
    )
    parser.add_argument("--values", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--watch", action="store_true", help="monitor resources live")
    parser.add_argument("--interval", type=float, default=2.0)
    args = parser.parse_args()
    if args.watch:
        watch_metrics(args.interval)
        return
    report = runtime_report(args.profile)
    profile = report["profile"]
    hardware = report["hardware"]
    if args.values:
        for value in (
            profile["name"],
            profile["model"] or "",
            profile["context_size"],
            profile["max_tokens"],
            profile["cpu_threads"],
            profile["gpu_layers"],
            hardware["gpu_name"] or "",
            hardware["vram_gib"],
        ):
            print(value)
        return
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
