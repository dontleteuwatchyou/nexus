"""Tests for hardware-adaptive Nexus AI profiles."""

from osint_toolkit.ai import (
    HardwareInfo,
    collect_live_metrics,
    format_live_metrics,
    select_profile,
)


def test_tiny_machine_falls_back_to_core():
    hardware = HardwareInfo(cpu_threads=2, ram_gib=2.0)
    assert select_profile(hardware).name == "core"


def test_low_memory_machine_uses_lite_model():
    hardware = HardwareInfo(cpu_threads=4, ram_gib=4.0)
    profile = select_profile(hardware)
    assert profile.name == "lite"
    assert "0.6B" in (profile.model or "")


def test_regular_cpu_machine_uses_balanced_model():
    hardware = HardwareInfo(cpu_threads=12, ram_gib=16.0)
    profile = select_profile(hardware)
    assert profile.name == "balanced"
    assert profile.gpu_layers == 0


def test_gpu_machine_uses_performance_profile():
    hardware = HardwareInfo(
        cpu_threads=16,
        ram_gib=32.0,
        gpu_name="NVIDIA GeForce RTX 4070 Ti",
        vram_gib=12.0,
    )
    profile = select_profile(hardware)
    assert profile.name == "performance"
    assert profile.gpu_layers > 0
    assert profile.context_size >= 8192


def test_explicit_profile_override_wins():
    hardware = HardwareInfo(cpu_threads=2, ram_gib=2.0)
    assert select_profile(hardware, "compact").name == "compact"


def test_live_metrics_are_safe_when_server_is_absent():
    metrics = collect_live_metrics(container="nexus-test-container-that-does-not-exist")
    rendered = format_live_metrics(metrics)
    assert metrics["server"] in {"offline", "ready"}
    assert "CPU" in rendered
    assert "VRAM" in rendered
