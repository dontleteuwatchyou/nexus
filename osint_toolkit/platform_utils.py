"""Cross-platform helpers.

The toolkit runs on Linux (its native habitat — Kali/Athena/etc.), on macOS
and on Windows. Anything that differs between those — how an executable is
found on PATH, how privilege is escalated, where per-user data lives, which
package manager installs a tool — lives here so the rest of the codebase stays
OS-agnostic.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

IS_WINDOWS = os.name == "nt" or sys.platform.startswith("win")
IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

# A short, human label used in reports / banners.
OS_LABEL = "Windows" if IS_WINDOWS else "macOS" if IS_MACOS else "Linux" if IS_LINUX else sys.platform


def which(name: str, extra_candidates: list[str] | None = None) -> str | None:
    """Locate an executable on PATH, cross-platform.

    ``shutil.which`` already honours ``PATHEXT`` on Windows (so ``which("nmap")``
    finds ``nmap.exe``), but many security tools ship under alternate names
    (``netexec`` / ``nxc``) or as ``.bat`` / ``.cmd`` / ``.py`` shims. We try
    the canonical name, any supplied aliases, and — on Windows — a few explicit
    extensions as a safety net.
    """
    candidates = [name, *(extra_candidates or [])]
    for cand in candidates:
        hit = shutil.which(cand)
        if hit:
            return hit
    if IS_WINDOWS:
        for cand in candidates:
            for ext in (".exe", ".bat", ".cmd", ".ps1", ".py"):
                hit = shutil.which(cand + ext)
                if hit:
                    return hit
    return None


def privilege_prefix() -> list[str]:
    """Command prefix to run something with elevated privileges.

    Linux prefers ``pkexec`` (graphical prompt) then ``sudo``; macOS uses
    ``sudo``; Windows has no inline equivalent (elevation happens per-process
    via UAC), so we return an empty prefix and let the caller warn.
    """
    if IS_WINDOWS:
        return []
    for tool in ("pkexec", "sudo"):
        if shutil.which(tool):
            return [tool]
    return []


def is_admin() -> bool:
    """Best-effort check for administrative / root privileges."""
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:
        return False


def data_dir(app: str = "osint-toolkit") -> Path:
    """Per-user data directory (tools, output), following OS conventions.

    Kept backward-compatible with the historical ``~/.osint-toolkit`` layout on
    Linux/macOS so existing installs keep working; on Windows we use
    ``%LOCALAPPDATA%`` and fall back to the home directory.
    """
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            return Path(base) / app
        return Path.home() / app
    return Path.home() / f".{app}"


def python_executable() -> str:
    """Path to the current Python interpreter (for spawning helper installs)."""
    return sys.executable or ("python" if IS_WINDOWS else "python3")


def detect_package_manager() -> str | None:
    """Return the name of the system package manager available, if any."""
    managers = (
        ["winget", "choco", "scoop"] if IS_WINDOWS
        else ["brew", "port"] if IS_MACOS
        else ["apt", "apt-get", "pacman", "dnf", "yum", "zypper", "apk"]
    )
    for m in managers:
        if shutil.which(m):
            return m
    return None


def install_commands(*, apt: str | None = None, pacman: str | None = None,
                     brew: str | None = None, pip: str | None = None,
                     pipx: str | None = None, go: str | None = None,
                     winget: str | None = None, scoop: str | None = None,
                     generic: str | None = None) -> list[str]:
    """Build an ordered list of install command suggestions for THIS OS.

    Each argument is the *package/module spec* for that installer (not the full
    command). Only the relevant ones for the current platform are emitted, most
    convenient first. ``pip``/``pipx``/``go`` are cross-platform and always
    appended when provided.
    """
    out: list[str] = []
    if IS_WINDOWS:
        if winget:
            out.append(f"winget install {winget}")
        if scoop:
            out.append(f"scoop install {scoop}")
    elif IS_MACOS:
        if brew:
            out.append(f"brew install {brew}")
    else:
        if apt:
            out.append(f"sudo apt install {apt}")
        if pacman:
            out.append(f"sudo pacman -S {pacman}")
    if pipx:
        out.append(f"pipx install {pipx}")
    if pip:
        out.append(f"{python_executable()} -m pip install --user {pip}")
    if go:
        out.append(f"go install {go}")
    if generic:
        out.append(generic)
    return out


def platform_summary() -> dict:
    return {
        "os": OS_LABEL,
        "platform": sys.platform,
        "python": sys.version.split()[0],
        "admin": is_admin(),
        "package_manager": detect_package_manager(),
        "privilege_prefix": " ".join(privilege_prefix()) or "(none)",
    }
