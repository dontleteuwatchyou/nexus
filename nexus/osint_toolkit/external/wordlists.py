"""Wordlist management module — browse, search, and manage seclists."""

from __future__ import annotations

from pathlib import Path

from ..models import ScanResult
from .base import ExternalTool


SECLISTS = Path("/usr/share/seclists")


class Wordlists(ExternalTool):
    name = "Wordlists"
    accepted_kinds = {"wordlist"}

    @classmethod
    def is_installed(cls) -> bool:
        return SECLISTS.exists()

    @classmethod
    def install_status(cls) -> dict:
        return {
            "name": cls.name,
            "installed": SECLISTS.exists(),
            "method": f"seclists at {SECLISTS}" if SECLISTS.exists() else None,
            "checks": [
                {"type": "directory", "target": str(SECLISTS), "found": SECLISTS.exists()},
            ],
        }

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 30.0,
        **kwargs,
    ) -> ScanResult:
        result = ScanResult(target=target, module=f"external:{cls.name}")

        if not SECLISTS.exists():
            result.add("wordlists", "Status", "Seclists not found at /usr/share/seclists", "error")
            return result

        target_lower = target.lower()

        # List all wordlist files
        files = list(SECLISTS.rglob("*"))
        wordlist_files = [f for f in files if f.is_file() and f.suffix in ("", ".txt", ".lst")]

        if target_lower in ("list", "ls", "all"):
            result.add("wordlists", "Root", str(SECLISTS), "info")
            for cat in sorted(set(f.parent.relative_to(SECLISTS).as_posix() for f in wordlist_files)):
                count = sum(1 for f in wordlist_files if cat in f.parent.relative_to(SECLISTS).as_posix())
                result.add("wordlists", cat, f"{count} files", "found")
            return result

        # Search for target term in wordlist paths
        matching = [f for f in wordlist_files if target_lower in f.stem.lower() or target_lower in f.parent.as_posix().lower()]

        if not matching:
            result.add("wordlists", "Search", f"No wordlists matching '{target}'", "info")
            return result

        result.add("wordlists", "Search", f"Found {len(matching)} wordlists matching '{target}'", "found")
        for f in matching[:20]:
            size_kb = f.stat().st_size / 1024
            result.add("wordlists", f.stem, f"{f.parent.relative_to(SECLISTS)} ({size_kb:.1f} KB)", "info")

        return result