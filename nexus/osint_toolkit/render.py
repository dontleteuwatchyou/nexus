"""Rich rendering helpers — banners, tables, panels, progress.

Centralised so CLI and TUI share the same visual language.
"""

from __future__ import annotations

from rich import box
from rich.console import Console, Group
from rich.markup import escape
from rich.panel import Panel
from rich.progress import (BarColumn, Progress, SpinnerColumn, TextColumn,
                            TimeElapsedColumn)
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from .models import Finding, ScanResult


THEME = Theme({
    "brand":     "bold #fb923c",   # orange — primary
    "accent":    "bold #fdba74",   # lighter orange
    "ok":        "bold #fbbf24",   # gold — hits / found
    "warn":      "bold #fb923c",   # orange — flags
    "err":       "bold #ef4444",   # red — errors
    "info":      "#a3a3a3",        # gray — info
    "muted":     "dim #525252",    # darker gray
    "label":     "bold #f5f5f5",   # bright label
    "value":     "#e5e5e5",        # values
    "bar":       "#fb923c",        # progress orange
    "rule":      "#2a2a2a",        # dark gray rule
})

console = Console(theme=THEME, highlight=False)


BANNER = r"""[brand]
   ███████╗ ███████╗ ██╗ ███╗   ██╗ ████████╗
   ██╔═══██╗██╔════╝ ██║ ████╗  ██║ ╚══██╔══╝
   ██║   ██║███████╗ ██║ ██╔██╗ ██║    ██║
   ██║   ██║╚════██║ ██║ ██║╚██╗██║    ██║
   ╚██████╔╝███████║ ██║ ██║ ╚████║    ██║
    ╚═════╝ ╚══════╝ ╚═╝ ╚═╝  ╚═══╝    ╚═╝[/brand]
            [accent]toolkit[/accent] [muted]· intelligence framework[/muted]"""


def banner(version: str = "3.0") -> None:
    console.print(BANNER)
    console.print(Panel.fit(
        f"[accent]v{version}[/accent]  [muted]·[/muted]  "
        f"[ok]100% open sources[/ok]  [muted]·[/muted]  "
        f"[info]no API keys required[/info]",
        border_style="rule",
        padding=(0, 2),
    ))
    console.print()


def section(title: str, sub: str | None = None) -> None:
    text = Text()
    text.append("  ▸ ", style="brand")
    text.append(title, style="label")
    if sub:
        text.append(f"   {sub}", style="muted")
    console.print()
    console.print(text)
    console.print(Rule(style="rule"))


def kv_table(title: str, rows: list[tuple[str, str]], cols: tuple[str, str] = ("Field", "Value")) -> Table:
    t = Table(
        title=title,
        title_style="label",
        title_justify="left",
        box=box.SIMPLE_HEAD,
        border_style="rule",
        header_style="accent",
        padding=(0, 1),
        show_lines=False,
    )
    t.add_column(cols[0], style="info", no_wrap=True)
    t.add_column(cols[1], style="value", overflow="fold")
    for k, v in rows:
        if v is None or v == "":
            continue
        t.add_row(k, str(v))
    return t


def findings_table(result: ScanResult, *, show_source: bool = True) -> Table | None:
    if not result.findings:
        return None
    t = Table(
        box=box.SIMPLE_HEAD,
        border_style="rule",
        header_style="accent",
        padding=(0, 1),
        show_lines=False,
    )
    if show_source:
        t.add_column("Source", style="info", no_wrap=True)
    t.add_column("Field", style="label")
    t.add_column("Value", style="value", overflow="fold")
    for f in result.findings:
        style = {"found": "ok", "warn": "warn", "error": "err"}.get(f.severity, "value")
        value_text = Text(str(f.value), style=style)
        if show_source:
            t.add_row(f.source, f.label, value_text)
        else:
            t.add_row(f.label, value_text)
    return t


def severity_summary(result: ScanResult) -> Panel:
    n_ok    = len(result.by_severity("found"))
    n_warn  = len(result.by_severity("warn"))
    n_info  = len(result.by_severity("info"))
    n_err   = len(result.errors)
    body = (
        f"[ok]● {n_ok} found[/ok]   "
        f"[warn]● {n_warn} flags[/warn]   "
        f"[info]● {n_info} info[/info]   "
        f"[err]● {n_err} errors[/err]"
    )
    return Panel(body, border_style="rule", padding=(0, 2))


def progress_bar() -> Progress:
    return Progress(
        SpinnerColumn(spinner_name="dots", style="brand"),
        TextColumn("[accent]{task.description}"),
        BarColumn(complete_style="bar", finished_style="ok", bar_width=30),
        TextColumn("[muted]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )


def quick_progress(desc: str) -> Progress:
    return Progress(
        SpinnerColumn(spinner_name="dots", style="brand"),
        TextColumn("[accent]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )


def full_scan_summary(results: dict[str, ScanResult]) -> None:
    """Print a compact roll-up of a full scan so the operator doesn't have
    to scroll through every module.

    Aggregates severity counts, lists the modules that produced flags
    (warn), and notes empty / errored / not-installed modules.
    """
    n_found = n_warn = n_info = n_err = 0
    with_hits = 0
    empty = 0
    notable: list[tuple[str, int, int]] = []   # (module, warn, found)
    errored: list[str] = []
    not_installed: list[str] = []

    for key, r in results.items():
        parts = key.split(":", 2)
        cat, mod = (parts[0], parts[1]) if len(parts) >= 2 else ("?", key)
        label = f"{cat}:{mod}"
        w = len(r.by_severity("warn"))
        f_ = len(r.by_severity("found"))
        i = len(r.by_severity("info"))
        n_warn += w
        n_found += f_
        n_info += i
        n_err += len(r.errors)
        if r.findings:
            with_hits += 1
        else:
            empty += 1
        if w:
            notable.append((label, w, f_))
        if r.errors:
            errored.append(label)
        if any(fd.source == "install" for fd in r.findings):
            not_installed.append(label)

    console.print()
    console.print(Rule("[brand]Full scan summary[/brand]", style="rule"))

    totals = (
        f"[label]{len(results)}[/label] modules run   "
        f"[info]{with_hits} with data · {empty} empty[/info]\n"
        f"[ok]● {n_found} found[/ok]   [warn]● {n_warn} flags[/warn]   "
        f"[info]● {n_info} info[/info]   [err]● {n_err} errors[/err]"
    )
    console.print(Panel(totals, border_style="rule", padding=(0, 2)))

    if notable:
        notable.sort(key=lambda x: x[1], reverse=True)
        t = Table(title="Flags by module", title_style="label",
                  title_justify="left", box=box.SIMPLE_HEAD,
                  border_style="rule", header_style="accent", padding=(0, 1))
        t.add_column("Module", style="warn", no_wrap=True)
        t.add_column("Flags", style="warn", justify="right")
        t.add_column("Found", style="ok", justify="right")
        for label, w, f_ in notable:
            t.add_row(escape(label), str(w), str(f_))
        console.print(t)

    if not_installed:
        console.print(f"  [muted]not installed:[/muted] {escape(', '.join(sorted(set(not_installed))))}")
    if errored:
        console.print(f"  [err]errored:[/err] {escape(', '.join(sorted(set(errored))))}")
    console.print()


def render_result(result: ScanResult) -> None:
    """Render a ScanResult to console with sections per source."""
    by_src: dict[str, list[Finding]] = {}
    for f in result.findings:
        by_src.setdefault(f.source, []).append(f)

    if not by_src:
        console.print(Panel(
            "[muted]Aucune donnée trouvée.[/muted]",
            border_style="rule",
        ))
        return

    for src, findings in by_src.items():
        rows = []
        for f in findings:
            severity_style = {
                "found": "ok",
                "warn":  "warn",
                "error": "err",
                "info":  "value",
            }.get(f.severity, "value")
            # Escape: values come from external tool output and may contain
            # Rich markup like [/ok] that would otherwise be parsed away.
            value_str = escape(str(f.value))
            if f.url:
                value_str = f"{value_str}  [muted]→ {escape(str(f.url))}[/muted]"
            rows.append((escape(str(f.label)),
                         f"[{severity_style}]{value_str}[/{severity_style}]"))
        console.print(kv_table(escape(str(src)), rows))
        console.print()

    console.print(severity_summary(result))
    if result.errors:
        for e in result.errors:
            console.print(f"  [err]✗[/err] [muted]{e}[/muted]")
