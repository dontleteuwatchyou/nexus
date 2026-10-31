"""Typed result containers.

Each module returns a dataclass (frozen) instead of an ad-hoc dict so
downstream code (TUI, CLI renderer, JSON export, correlator) can rely
on attribute access and type hints.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def _now() -> str:
    # timezone-aware UTC; datetime.utcnow() is deprecated as of Python 3.12
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass
class Finding:
    """One atomic piece of intel from one source."""
    source: str
    label: str
    value: Any
    severity: str = "info"  # info | found | warn | error
    url: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    """Aggregate of findings for one target + module."""
    target: str
    module: str
    timestamp: str = field(default_factory=_now)
    findings: list[Finding] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)  # raw source payloads
    errors: list[str] = field(default_factory=list)

    def add(self, source: str, label: str, value: Any,
            severity: str = "info", url: str | None = None) -> None:
        self.findings.append(Finding(source, label, value, severity, url))

    def by_source(self, source: str) -> list[Finding]:
        return [f for f in self.findings if f.source == source]

    def by_severity(self, severity: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def as_dict(self) -> dict:
        return {
            "target": self.target,
            "module": self.module,
            "timestamp": self.timestamp,
            "findings": [f.as_dict() for f in self.findings],
            "raw": self.raw,
            "errors": self.errors,
        }


# ── Severity taxonomy ─────────────────────────────────────────────
# Canonical, tester-facing severities, highest first. The codebase also uses
# legacy labels ("found"/"warn"/"error"/"info"); the helpers below understand
# both so old and new modules sort and report together.
SEVERITY_LEVELS = ("critical", "high", "medium", "low", "info")

# Severities that represent a security-relevant finding collected into the
# vulnerability report. "found"/"info" are OSINT data, not vulnerabilities.
VULN_SEVERITIES = ("critical", "high", "medium", "low")

_SEVERITY_RANK = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
    # legacy aliases
    "warn": 2, "error": 4, "err": 4, "found": 4, "ok": 4, "": 4,
}


def severity_rank(sev: str) -> int:
    """Lower is more severe. Unknown labels rank as info (4)."""
    return _SEVERITY_RANK.get((sev or "").lower(), 4)


def normalize_severity(sev: str) -> str:
    """Map any severity label (new or legacy) to a canonical level.

    critical/high/medium/low pass through; the legacy pentest "warn" flag
    becomes "medium"; everything else (OSINT hits, info, tool errors) becomes
    "info" so it stays out of the vulnerability report.
    """
    s = (sev or "").lower()
    if s in ("critical", "high", "medium", "low"):
        return s
    if s == "warn":
        return "medium"
    return "info"
