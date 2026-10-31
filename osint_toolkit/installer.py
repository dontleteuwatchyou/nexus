"""Cross-platform dependency & tool installer.

Two jobs, both working identically on Linux, macOS and Windows:

* **Python deps** — install the project's own requirements (``--install-deps``).
* **External tools** — auto-install the wrappers that CAN be installed without
  a system package manager: pip packages and git-cloned helpers
  (``--install-tools``). Tools that need a system package (nmap, nikto, ...) are
  not silently ``sudo``-installed; we print the OS-appropriate command instead.

Nothing here runs with elevated privileges on its own.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from . import platform_utils
from .external import ALL_TOOLS, find_tool

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _run(cmd: list[str], timeout: float = 600.0) -> tuple[int, str]:
    print("    $ " + " ".join(cmd))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except FileNotFoundError as e:
        return -1, f"command not found: {e}"
    except subprocess.TimeoutExpired:
        return -1, f"timed out after {timeout:.0f}s"
    except Exception as e:  # noqa: BLE001
        return -1, str(e)


# ── Python dependencies ───────────────────────────────────────────

def install_python_deps(dry_run: bool = False) -> bool:
    """Install requirements.txt with sensible fallbacks across environments."""
    py = platform_utils.python_executable()
    req = PROJECT_ROOT / "requirements.txt"
    if not req.exists():
        print(f"  ✗ requirements.txt not found at {req}")
        return False
    attempts = [
        [py, "-m", "pip", "install", "-r", str(req)],
        [py, "-m", "pip", "install", "--user", "-r", str(req)],
        [py, "-m", "pip", "install", "--break-system-packages", "-r", str(req)],
    ]
    if dry_run:
        for a in attempts:
            print("    (dry-run) " + " ".join(a))
        return True
    for cmd in attempts:
        code, out = _run(cmd)
        if code == 0:
            print("  ✓ Python dependencies installed")
            return True
        print("  … retrying with a different pip strategy")
    print("  ✗ Could not install Python dependencies")
    print(out[-500:])
    return False


# ── External tools ────────────────────────────────────────────────

def is_auto_installable(tool_cls) -> bool:
    return bool(tool_cls.pip_package or tool_cls.repo_url)


def plan_tool(tool_cls) -> list[list[str]]:
    """Return the command(s) that would install *tool_cls* (no execution)."""
    py = platform_utils.python_executable()
    if tool_cls.pip_package:
        return [[py, "-m", "pip", "install", "--user", tool_cls.pip_package]]
    if tool_cls.repo_url:
        d = tool_cls.install_dir()
        cmds = [["git", "clone", "--depth", "1", tool_cls.repo_url, str(d)]]
        if tool_cls.script_path or tool_cls.script_candidates:
            cmds.append([py, "-m", "pip", "install", "-r", str(d / "requirements.txt")])
        return cmds
    return []


def install_tool(tool_cls, dry_run: bool = False) -> bool:
    name = tool_cls.name
    if tool_cls.is_installed():
        print(f"  ✓ {name} already installed")
        return True
    if not is_auto_installable(tool_cls):
        print(f"  ⚠ {name} needs a system package — not auto-installed:")
        for line in tool_cls.install_hint().splitlines():
            print(f"      {line}")
        return False
    cmds = plan_tool(tool_cls)
    if dry_run:
        for c in cmds:
            print("    (dry-run) " + " ".join(c))
        return True
    # pip packages: try --user, then --break-system-packages
    if tool_cls.pip_package:
        py = platform_utils.python_executable()
        for flag in (["--user"], ["--break-system-packages"]):
            code, out = _run([py, "-m", "pip", "install", *flag, tool_cls.pip_package])
            if code == 0:
                print(f"  ✓ {name} installed")
                return True
        print(f"  ✗ {name} failed to install")
        return False
    # repo tools
    ok = True
    for c in cmds:
        if c[0] == "git" and tool_cls.install_dir().exists():
            print(f"  ✓ {name} already cloned")
            continue
        code, out = _run(c)
        ok = ok and code == 0
    print(f"  {'✓' if ok else '✗'} {name}")
    return ok


def resolve_targets(spec: str) -> list:
    """Turn a --install-tools spec into a list of tool classes.

    Accepts "all" (every auto-installable tool), "pip" (pip packages only), or a
    comma-separated list of tool names.
    """
    spec = (spec or "").strip().lower()
    if spec in ("all", "auto"):
        return [t for t in ALL_TOOLS if is_auto_installable(t)]
    if spec == "pip":
        return [t for t in ALL_TOOLS if t.pip_package]
    out = []
    for name in (n.strip() for n in spec.split(",") if n.strip()):
        tc = find_tool(name)
        if tc:
            out.append(tc)
        else:
            print(f"  ⚠ unknown tool: {name}")
    return out


def install_tools(spec: str, dry_run: bool = False) -> None:
    targets = resolve_targets(spec)
    if not targets:
        print("  Nothing to install.")
        return
    print(f"  Installing {len(targets)} tool(s) on {platform_utils.OS_LABEL}…")
    ok = sum(1 for t in targets if install_tool(t, dry_run=dry_run))
    print(f"\n  Done: {ok}/{len(targets)} succeeded"
          + (" (dry-run)" if dry_run else ""))
