"""Vulnerability report aggregation.

Collects security-relevant findings across every scanned module, normalises
their severities onto one canonical scale (critical > high > medium > low),
and renders a ranked report — on the console, as plain text, and embedded in
the HTML export.

Detection-only: this layer *reports* what the scan found. It classifies and
prioritises; it never exploits.
"""

from __future__ import annotations

from . import i18n
from .models import VULN_SEVERITIES, ScanResult, normalize_severity, severity_rank

# style-key, display-label per canonical level
_LEVEL_META = {
    "critical": ("crit", "CRITICAL"),
    "high":     ("high", "HIGH"),
    "medium":   ("medium", "MEDIUM"),
    "low":      ("low", "LOW"),
}


def _split_key(key: str) -> tuple[str, str, str]:
    parts = key.split(":", 2)
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return "osint", parts[0], parts[1]
    return "scan", key, ""


def collect(results: dict[str, ScanResult]) -> list[dict]:
    """Flatten, normalize, de-duplicate and rank vulnerability rows.

    Identical findings reported by more than one module are merged into one
    row that records every source (cross-tool corroboration), so a full scan
    yields a single prioritised list instead of the same issue repeated once
    per tool.
    """
    merged: dict[tuple, dict] = {}
    for key, r in results.items():
        cat, mod, _val = _split_key(key)
        source = f"{cat}/{mod}"
        for f in r.findings:
            lvl = normalize_severity(f.severity)
            if lvl not in VULN_SEVERITIES:
                continue
            dkey = (lvl, str(f.label), str(f.value))
            if dkey in merged:
                row = merged[dkey]
                row["sources"].add(source)
                if not row["url"] and f.url:
                    row["url"] = f.url
                continue
            merged[dkey] = {
                "severity": lvl,
                "rank": severity_rank(lvl),
                "category": cat,
                "module": mod,
                "source": f.source,
                "label": f.label,
                "detail": str(f.value),
                "url": f.url,
                "target": r.target,
                "sources": {source},
            }
    rows = list(merged.values())
    for row in rows:
        row["sources"] = sorted(row["sources"])
        row["corroborated"] = len(row["sources"]) > 1
    rows.sort(key=lambda x: (x["rank"], x["category"], x["module"], x["label"]))
    return rows


def counts(rows: list[dict]) -> dict[str, int]:
    c = {lvl: 0 for lvl in VULN_SEVERITIES}
    for row in rows:
        c[row["severity"]] += 1
    return c


def print_console(results: dict[str, ScanResult]) -> None:
    """Render the ranked vulnerability report with Rich."""
    from rich import box
    from rich.markup import escape
    from rich.table import Table

    from .render import console

    rows = collect(results)
    c = counts(rows)
    console.print()
    console.rule(f"[brand]{i18n.t('report.title')}[/brand]")
    summary = "   ".join(
        f"[{_LEVEL_META[lvl][0]}]● {c[lvl]} {i18n.t('sev.' + lvl)}[/{_LEVEL_META[lvl][0]}]"
        for lvl in VULN_SEVERITIES
    )
    console.print(summary)
    console.print()
    if not rows:
        console.print(f"  [ok]{i18n.t('report.none')}[/ok]")
        return
    t = Table(box=box.SIMPLE_HEAD, border_style="rule",
              header_style="accent", padding=(0, 1))
    t.add_column("Sev", no_wrap=True)
    t.add_column("Module", style="info", no_wrap=True)
    t.add_column("Finding", style="label")
    t.add_column("Detail", style="value", overflow="fold")
    for row in rows:
        style = _LEVEL_META[row["severity"]][0]
        sev_cell = f"[{style}]{i18n.t('sev.' + row['severity']).upper()}[/{style}]"
        detail = escape(row["detail"])
        if row["url"]:
            detail += f"  [muted]→ {escape(str(row['url']))}[/muted]"
        if row.get("corroborated"):
            detail += f"  [muted](×{len(row['sources'])} sources)[/muted]"
        t.add_row(sev_cell, f"{row['category']}/{row['module']}",
                  escape(str(row["label"])), detail)
    console.print(t)


def to_text(results: dict[str, ScanResult], target: str) -> str:
    """Plain-text vulnerability report."""
    rows = collect(results)
    c = counts(rows)
    out = [
        "=" * 70,
        f"VULNERABILITY REPORT — {target}",
        "=" * 70,
        "Summary: " + "   ".join(f"{c[lvl]} {lvl}" for lvl in VULN_SEVERITIES),
    ]
    if not rows:
        out.append("")
        out.append("No security-relevant findings reported.")
        return "\n".join(out)
    cur = None
    for row in rows:
        if row["severity"] != cur:
            cur = row["severity"]
            out.append("")
            out.append(f"── {cur.upper()} ──")
        line = f"  • [{row['category']}/{row['module']}] {row['label']}: {row['detail']}"
        if row["url"]:
            line += f"  → {row['url']}"
        if row.get("corroborated"):
            line += f"  [corroborated ×{len(row['sources'])}: {', '.join(row['sources'])}]"
        out.append(line)
    out.append("")
    return "\n".join(out)
