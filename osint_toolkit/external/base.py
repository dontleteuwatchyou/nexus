"""Base class for external OSINT tool wrappers.

Each subclass wraps a third-party tool (git repo or pip package) and
exposes a unified async `scan()` returning a ScanResult.

The wrappers do not bundle the tools — they detect whether the tool is
installed and tell the user how to install it if not.
"""

from __future__ import annotations

import asyncio
import importlib
import os
from pathlib import Path

from .. import platform_utils
from ..models import ScanResult

TOOLS_DIR = platform_utils.data_dir() / "tools"
TOOLS_DIR.mkdir(parents=True, exist_ok=True)


class ExternalTool:
    """Subclass and override the class attributes + methods."""

    name: str = ""                # Display name
    pip_package: str | None = None  # e.g. "toutatis"
    repo_url: str | None = None   # git clone URL
    bin_name: str | None = None   # executable name on PATH
    bin_candidates: list[str] = []  # alternate executable names (e.g. nxc for netexec)
    script_path: str | None = None  # main script relative to install_dir (legacy)
    script_candidates: list[str] = []  # ordered list of candidate entry-point filenames
    accepted_kinds: set[str] = set()

    @classmethod
    def install_dir(cls) -> Path:
        return TOOLS_DIR / cls.name.lower().replace(" ", "_").replace(".", "")

    @classmethod
    def find_script(cls) -> Path | None:
        """Locate the entry-point script for git-cloned tools."""
        d = cls.install_dir()
        if not d.exists():
            return None
        # Try explicit candidates first
        candidates = list(cls.script_candidates)
        if cls.script_path:
            candidates.insert(0, cls.script_path)
        for c in candidates:
            p = d / c
            if p.exists():
                return p
        # Fallback: any .py file in the install dir (top-level)
        py_files = sorted(d.glob("*.py"))
        if py_files:
            # Prefer files matching the tool name
            normalized = cls.name.lower().replace(".", "").replace(" ", "")
            for p in py_files:
                if normalized in p.stem.lower().replace(".", "").replace("_", ""):
                    return p
            return py_files[0]
        return None

    @classmethod
    def install_status(cls) -> dict:
        """Return a diagnostic dict: where we looked, what we found."""
        status = {"name": cls.name, "installed": False, "method": None,
                   "checks": []}

        # 1. PATH binary
        if cls.bin_name:
            path = platform_utils.which(cls.bin_name, cls.bin_candidates)
            status["checks"].append({
                "type": "PATH binary", "target": cls.bin_name,
                "found": path or False,
            })
            if path:
                status["installed"] = True
                status["method"] = f"on PATH at {path}"
                return status

        # 2. pip package import
        if cls.pip_package:
            mod_name = cls.pip_package.replace("-", "_")
            found = False
            try:
                spec = importlib.util.find_spec(mod_name)
                found = spec is not None
                origin = getattr(spec, "origin", None) if spec else None
            except (ImportError, ValueError):
                origin = None
            status["checks"].append({
                "type": "Python import", "target": mod_name,
                "found": origin or found,
            })
            if found:
                status["installed"] = True
                status["method"] = f"importable as `{mod_name}`"
                return status

        # 3. Git-cloned + script present
        if cls.repo_url:
            d = cls.install_dir()
            status["checks"].append({
                "type": "Install dir", "target": str(d),
                "found": d.exists(),
            })
            if d.exists():
                script = cls.find_script()
                status["checks"].append({
                    "type": "Entry script",
                    "target": ", ".join(cls.script_candidates or [cls.script_path or "(any *.py)"]),
                    "found": str(script) if script else False,
                })
                if script is not None:
                    status["installed"] = True
                    status["method"] = f"script at {script}"
                    return status

        return status

    @classmethod
    def is_installed(cls) -> bool:
        return cls.install_status()["installed"]

    @classmethod
    def install_hint(cls) -> str:
        py = platform_utils.python_executable()
        if cls.pip_package:
            return (
                f"Try in order:\n"
                f"      pipx install {cls.pip_package}\n"
                f"      {py} -m pip install --user {cls.pip_package}\n"
                f"      {py} -m pip install --break-system-packages {cls.pip_package}\n"
                f"   If pip succeeds but the tool is still not detected, the active\n"
                f"   Python (3.13+/3.14) may be unsupported — retry with python3.11/3.12."
            )
        if cls.repo_url:
            return (f"git clone {cls.repo_url} {cls.install_dir()}"
                    + (f" && {py} -m pip install -r {cls.install_dir()}/requirements.txt"
                       if cls.script_path or cls.script_candidates else ""))
        if cls.bin_name:
            cmds = platform_utils.install_commands(
                apt=cls.bin_name, pacman=cls.bin_name, brew=cls.bin_name,
                winget=cls.bin_name, scoop=cls.bin_name,
            )
            pm = platform_utils.detect_package_manager()
            header = f"'{cls.bin_name}' not found on PATH. Install via your package manager"
            if cmds:
                return header + ":\n      " + "\n      ".join(cmds)
            return header + f" ({pm or 'none detected'})."
        return "See tool documentation."

    @classmethod
    async def _run_subprocess(cls, args: list[str], *,
                               timeout: float = 60.0,
                               cwd: Path | None = None,
                               input_data: bytes | None = None) -> tuple[int, str, str]:
        # Build environment — explicitly add cwd to PYTHONPATH so cloned
        # tools that use absolute imports (e.g. `from Core.Support import X`)
        # can find their sibling packages.
        env = {**os.environ, "PYTHONUNBUFFERED": "1",
                "NO_COLOR": "1", "TERM": "dumb"}
        if cwd:
            existing_pp = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = (
                str(cwd) + (os.pathsep + existing_pp if existing_pp else "")
            )
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.PIPE if input_data else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(cwd) if cwd else None,
                env=env,
            )
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(input=input_data),
                timeout=timeout,
            )
            return (proc.returncode or 0,
                    stdout_b.decode("utf-8", errors="replace"),
                    stderr_b.decode("utf-8", errors="replace"))
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return (-1, "", f"Tool timed out after {timeout}s")
        except FileNotFoundError as e:
            return (-1, "", f"Command not found: {e}")
        except Exception as e:
            return (-1, "", f"Subprocess error: {e}")

    @classmethod
    def _not_installed_result(cls, target: str) -> ScanResult:
        r = ScanResult(target=target, module=f"external:{cls.name}")
        r.add("install", "Status", f"{cls.name} not installed", "warn")
        r.add("install", "How to install", cls.install_hint(), "info")
        if cls.repo_url:
            r.add("install", "Repository", cls.repo_url, "info", url=cls.repo_url)
        # Diagnostic: show what we checked
        status = cls.install_status()
        for chk in status["checks"]:
            label = f"checked {chk['type']}"
            found = chk["found"]
            value = f"{chk['target']}  →  " + ("✓ found" if found else "✗ not found")
            r.add("diagnostic", label, value, "info" if found else "warn")
        return r

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 60.0, **kwargs) -> ScanResult:
        raise NotImplementedError
