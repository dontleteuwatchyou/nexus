"""CLI entry point — supports OSINT, pentest and external modules.

Examples:
  nexus                                 # launch TUI
  nexus --chat                          # launch Nexus AI in the TUI
  nexus test@gmail.com                  # auto-detect OSINT module
  nexus -m domain example.com
  nexus -c pentest -m ports example.com
  nexus -c pentest -m fingerprint https://example.com --save-html
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .correlate import detect_target_type, scan_chained, scan_full, scan_one
from .models import ScanResult
from .render import (banner, console, full_scan_summary, progress_bar,
                     quick_progress, render_result, section)


OUTPUT_DIR = Path.home() / ".osint-toolkit" / "output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def _timestamp() -> str:
    """Filesystem-safe UTC timestamp (timezone-aware)."""
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _save_json(results: dict[str, ScanResult], target: str) -> Path:
    ts = _timestamp()
    safe = "".join(c if c.isalnum() else "_" for c in target)[:40]
    path = OUTPUT_DIR / f"scan_{safe}_{ts}.json"
    data = {k: r.as_dict() for k, r in results.items()}
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return path


def _save_html(results: dict[str, ScanResult], target: str) -> Path:
    ts = _timestamp()
    safe = "".join(c if c.isalnum() else "_" for c in target)[:40]
    path = OUTPUT_DIR / f"scan_{safe}_{ts}.html"

    sections_html = []
    for key, r in results.items():
        parts = key.split(":", 2)
        if len(parts) == 3:
            cat, mod, val = parts
        else:
            cat, mod, val = "osint", parts[0], parts[1]

        cat_color = "#fb923c" if cat == "osint" else "#dc2626"
        rows_html = ""
        by_src: dict[str, list] = {}
        for f in r.findings:
            by_src.setdefault(f.source, []).append(f)
        for src, findings in by_src.items():
            rows_html += f'<h3 class="src">◆ {src}</h3><dl>'
            for f in findings:
                sev = f.severity
                val_disp = str(f.value)
                if f.url:
                    val_disp = f'<a href="{f.url}" target="_blank">{val_disp}</a>'
                rows_html += (
                    f'<dt class="sev-{sev}">{f.label}</dt>'
                    f'<dd class="sev-{sev}">{val_disp}</dd>'
                )
            rows_html += "</dl>"
        sections_html.append(
            f'<section>'
            f'<h2><span class="badge" style="background:{cat_color};">{cat}</span> '
            f'<span class="mod">{mod}</span> {val}</h2>{rows_html}'
            f'</section>'
        )

    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>OSINT — {target}</title>
<style>
:root {{
  --bg: #0a0a0a; --panel: #141414; --rule: #2a2a2a;
  --text: #e5e5e5; --muted: #737373; --label: #fdba74;
  --brand: #fb923c; --pentest: #dc2626;
  --ok: #fbbf24; --warn: #fb923c; --err: #ef4444; --info: #a3a3a3;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  background: var(--bg); color: var(--text); padding: 2rem 5vw;
  font-family: 'JetBrains Mono', 'SF Mono', ui-monospace, Menlo, monospace;
  line-height: 1.55; min-height: 100vh;
}}
header h1 {{ font-size: 2.4rem; color: var(--brand); letter-spacing: -0.02em; }}
header .meta {{ color: var(--muted); margin-top: 0.4rem; font-size: 0.85rem; }}
section {{
  background: var(--panel); border: 1px solid var(--rule);
  border-radius: 12px; padding: 1.5rem 1.8rem; margin: 1.5rem 0;
}}
section h2 {{
  color: var(--text); margin-bottom: 1rem;
  border-bottom: 1px dashed var(--rule); padding-bottom: 0.7rem;
  display: flex; align-items: center; gap: 0.8rem; flex-wrap: wrap;
}}
.badge {{
  display: inline-block; color: #0a0a0a;
  padding: 2px 10px; border-radius: 4px; font-size: 0.7rem;
  text-transform: uppercase; letter-spacing: 0.1em; font-weight: bold;
}}
.mod {{
  color: var(--label); font-size: 0.85rem;
  text-transform: lowercase; letter-spacing: 0.04em;
}}
.src {{
  color: var(--label); font-size: 0.9rem; margin: 1.2rem 0 0.5rem;
  text-transform: uppercase; letter-spacing: 0.08em;
}}
dl {{
  display: grid; grid-template-columns: minmax(180px, 240px) 1fr;
  gap: 0.3rem 1.5rem; font-size: 0.85rem;
}}
dt {{ color: var(--muted); text-align: right; padding-right: 0.5rem; }}
dd {{ color: var(--text); word-break: break-word; }}
.sev-found > * , dd.sev-found {{ color: var(--ok); }}
.sev-warn > *  , dd.sev-warn  {{ color: var(--warn); }}
.sev-error > * , dd.sev-error {{ color: var(--err); }}
.sev-info > *  , dd.sev-info  {{ color: var(--text); }}
a {{ color: var(--brand); text-decoration: none; border-bottom: 1px dotted; }}
a:hover {{ border-bottom-style: solid; color: var(--ok); }}
footer {{ color: var(--muted); margin-top: 2rem; font-size: 0.8rem; text-align: center; }}
</style></head><body>
<header>
  <h1>◆ OSINT + Recon Report</h1>
  <p class="meta">Target: <strong>{target}</strong> &nbsp;·&nbsp; Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
</header>
{''.join(sections_html)}
<footer>OSINT Toolkit v4.0</footer>
</body></html>"""
    path.write_text(html, encoding="utf-8")
    return path


async def _run_cli(args: argparse.Namespace) -> None:
    target = args.target
    category = args.category or "osint"
    module = args.module
    deep = args.deep
    fullscan = args.fullscan

    # For fullscan: if -c was NOT passed, run all; otherwise scope to given category
    fullscan_category = None if args.category is None else category

    silent = args.json  # --json implies clean stdout
    if not args.quiet and not silent:
        banner("4.0")

    if fullscan:
        cat_label = {"osint": "OSINT", "pentest": "PENTEST",
                     "external": "EXTERNAL"}.get(fullscan_category or "", "ALL")
        section(f"Full scanning  {target}", f"{cat_label} — all applicable modules")
        if silent:
            results = await scan_full(target, timeout=args.timeout, category=fullscan_category)
        else:
            with progress_bar() as _prog:
                _task = _prog.add_task("starting…", total=None)

                def _full_cb(key, result, done, total):
                    _prog.update(_task, total=total, completed=done,
                                 description=key)

                results = await scan_full(target, timeout=args.timeout,
                                          category=fullscan_category,
                                          progress_cb=_full_cb)
        if args.save_json:
            p = _save_json(results, target)
            console.print(f"\n  [ok]✓[/ok] JSON saved → [info]{p}[/info]")
        if args.save_html:
            p = _save_html(results, target)
            console.print(f"  [ok]✓[/ok] HTML report saved → [info]{p}[/info]")
        if args.json:
            out = {k: r.as_dict() for k, r in results.items()}
            print(json.dumps(out, indent=2, default=str, ensure_ascii=False))
            return
        for key, result in results.items():
            if not result.findings and not result.errors:
                continue  # skip empty modules to keep full-scan output readable
            parts = key.split(":", 2)
            if len(parts) == 3:
                cat, mod, val = parts
            else:
                cat, mod, val = "osint", parts[0], parts[1]
            section(f"{cat.upper()}  ·  {mod}  ·  {val}")
            render_result(result)
        full_scan_summary(results)
        return

    if category == "osint":
        if module == "auto":
            typ = detect_target_type(target)
            if typ == "unknown":
                console.print(f"[err]✗ Could not detect target type:[/err] {target}")
                sys.exit(2)
        else:
            typ = module

        if not silent:
            section(f"Scanning  {target}",
                    f"OSINT · {typ}{'  · deep'  if deep else ''}")

        if deep and module == "auto":
            if silent:
                results = await scan_chained(target, depth=1, timeout=args.timeout)
            else:
                with quick_progress("Chained scan"):
                    results = await scan_chained(target, depth=1, timeout=args.timeout)
        else:
            if silent:
                res = await scan_one(target, category="osint", module=typ,
                                      timeout=args.timeout)
            else:
                with quick_progress(f"Running {typ} module"):
                    res = await scan_one(target, category="osint", module=typ,
                                          timeout=args.timeout)
            results = {f"osint:{typ}:{target}": res}

    else:  # pentest or external
        if not module:
            console.print(f"[err]✗ {category} mode requires --module[/err]")
            sys.exit(2)
        if not silent:
            section(f"Probing  {target}", f"{category.upper()} · {module}")
            with progress_bar() as _prog:
                _task = _prog.add_task(module, total=None)

                def _mod_cb(done, total):
                    _prog.update(_task, total=total, completed=done)

                res = await scan_one(target, category=category, module=module,
                                      timeout=args.timeout, progress_cb=_mod_cb)
        else:
            res = await scan_one(target, category=category, module=module,
                                  timeout=args.timeout)
        results = {f"{category}:{module}:{target}": res}

    if args.json:
        out = {k: r.as_dict() for k, r in results.items()}
        print(json.dumps(out, indent=2, default=str, ensure_ascii=False))
        return

    for key, result in results.items():
        parts = key.split(":", 2)
        if len(parts) == 3:
            cat, mod, val = parts
        else:
            cat, mod, val = "osint", parts[0], parts[1]
        section(f"{cat.upper()}  ·  {mod}  ·  {val}")
        render_result(result)

    if args.save_json:
        p = _save_json(results, target)
        console.print(f"\n  [ok]✓[/ok] JSON saved → [info]{p}[/info]")
    if args.save_html:
        p = _save_html(results, target)
        console.print(f"  [ok]✓[/ok] HTML report saved → [info]{p}[/info]")

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="nexus",
        description="Nexus Toolkit v4 — OSINT + pentest + external (nexus)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  nexus                                          # launch TUI
  nexus --chat                                   # launch Nexus AI in the TUI
  nexus test@gmail.com                           # auto OSINT
  nexus -m domain example.com
  nexus -c pentest -m ports example.com
  nexus -c pentest -m subdomains example.com
  nexus -c pentest -m fingerprint https://example.com --save-html
  nexus -c external -m nmap scanme.nmap.org
  nexus --fullscan example.com --save-html --save-json   # full scan (all cats)
  nexus -c pentest --fullscan example.com                # full pentest scan only
""",
    )
    parser.add_argument("target", nargs="?",
                         help="Target: email, username, domain, IP, phone, URL")
    parser.add_argument("-c", "--category",
                         choices=["osint", "pentest", "external"],
                         help="Module category (default: osint for normal scan, all for --fullscan)")
    parser.add_argument("-m", "--module", default="auto",
                         help=(
                             "Module name. OSINT: auto, email, username, domain, ip, "
                             "phone, web, social, breach, github. PENTEST: ports, "
                             "subdomains, fingerprint, ssl, dirs, cors, open-redirect, "
                             "spring, js, s3, headers, dns-sec, graphql. EXTERNAL: sherlock, holehe, theharvester, "
                             "nmap, masscan, naabu, assetfinder, subfinder, amass, httpx, "
                             "nuclei, ffuf, gobuster, feroxbuster, dalfox, sqlmap, nikto, "
                             "wapiti, skipfish, wpscan, gospider, hakrawler, kiterunner, "
                             "gau, katana, crackmapexec, netexec, enum4linux, kerbrute, "
                             "bloodhound-python, secretsdump, psexec, wmiexec, "
                             "hashcat, john, fcrackzip, aircrack-ng, wifite, "
                             "prowler, pacu, volatility3, bulk_extractor, binwalk, "
                             "frida, objection, jadx, apktool, radare2, rizin, gdb, "
                             "metasploit, msfvenom, havoc, mrholmes, toutatis, zehef, "
                             "dataprofiler, bettercap, arjun, photon, finalrecon, "
                             "theharvester, recon-ng"
                         ))
    parser.add_argument("-f", "--fullscan", action="store_true",
                         help="Run ALL applicable OSINT + PENTEST + EXTERNAL modules")
    parser.add_argument("-d", "--deep", action="store_true",
                         help="Chained OSINT scan (auto module only)")
    parser.add_argument("--timeout", type=float, default=30.0,
                         help="Per-source timeout (default 30s)")
    parser.add_argument("--json", action="store_true",
                         help="Output raw JSON to stdout")
    parser.add_argument("--save-json", action="store_true",
                         help="Persist JSON to ~/.osint-toolkit/output/")
    parser.add_argument("--save-html", action="store_true",
                         help="Persist styled HTML report")
    parser.add_argument("-q", "--quiet", action="store_true", help="No banner")
    parser.add_argument("--tui", action="store_true", help="Force TUI mode")
    parser.add_argument("--chat", action="store_true",
                         help="Lancer Nexus AI dans la TUI")
    parser.add_argument("--list-modules", action="store_true",
                         help="List available modules and exit")
    parser.add_argument("--check-tools", action="store_true",
                         help="Diagnose external tool detection and exit")
    parser.add_argument("--version", action="version", version="Nexus Toolkit 4.0")
    args = parser.parse_args()

    if args.check_tools:
        from .external import ALL_TOOLS
        console.print()
        console.print("[brand]External tool detection report[/brand]")
        console.print(f"[muted]Python interpreter: {sys.executable}[/muted]")
        console.print(f"[muted]sys.path[0]: {sys.path[0] if sys.path else '?'}[/muted]")
        console.print()
        for t in ALL_TOOLS:
            status = t.install_status()
            ok = "[ok]✓ INSTALLED[/ok]" if status["installed"] else "[err]✗ NOT INSTALLED[/err]"
            console.print(f"[accent]{t.name}[/accent]  {ok}")
            if status["installed"]:
                console.print(f"  [info]method:[/info] {status['method']}")
            console.print(f"  [info]install dir:[/info] {t.install_dir()}")
            console.print(f"  [info]accepts:[/info] {', '.join(sorted(t.accepted_kinds)) or '(any)'}")
            if status["checks"]:
                console.print("  [info]checks:[/info]")
                for chk in status["checks"]:
                    marker = "[ok]✓[/ok]" if chk["found"] else "[err]✗[/err]"
                    target = chk["target"]
                    found = chk["found"]
                    found_str = f"  found: {found}" if found else ""
                    console.print(f"    {marker} {chk['type']:<14} target: {target}{found_str}")
            if not status["installed"]:
                console.print(f"  [warn]install:[/warn] {t.install_hint()}")
            console.print()
        return

    if args.list_modules:
        from .correlate import OSINT_MODULES, PENTEST_MODULES
        from .external import ALL_TOOLS
        console.print()
        console.print("[brand]OSINT modules:[/brand]")
        for m in OSINT_MODULES:
            console.print(f"  [info]{m}[/info]")
        console.print()
        console.print("[warn]PENTEST modules:[/warn]")
        for m in PENTEST_MODULES:
            console.print(f"  [info]{m}[/info]")
        console.print()
        console.print("[accent]EXTERNAL tools:[/accent]")
        for t in ALL_TOOLS:
            status = "[ok]✓ installed[/ok]" if t.is_installed() else "[err]✗ not installed[/err]"
            console.print(f"  [info]{t.name.lower():<14}[/info] {status}  [muted]({', '.join(sorted(t.accepted_kinds))})[/muted]")
        return

    if args.chat:
        from .tui import run as run_tui
        run_tui()
        return

    if args.tui or not args.target:
        from .tui import run as run_tui
        run_tui()
        return

    try:
        asyncio.run(_run_cli(args))
    except KeyboardInterrupt:
        console.print("\n[warn]Interrupted.[/warn]")
        sys.exit(130)


if __name__ == "__main__":
    main()
