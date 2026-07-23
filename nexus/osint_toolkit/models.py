"""Typed result containers.

Each module returns a dataclass (frozen) instead of an ad-hoc dict so
downstream code (TUI, CLI renderer, JSON export, correlator) can rely
on attribute access and type hints.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
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
