#!/usr/bin/env python3
"""Consolide tous les résultats PENTEST JSON en un rapport complet."""
import json
from pathlib import Path
from collections import defaultdict

OUTPUT_DIR = Path.home() / ".osint-toolkit" / "output"
REPORT_DIR = Path("/home/seclists/DISK2 (JMS DELETE)/Perso/Project/osint-toolkit-v4")

json_files = sorted(OUTPUT_DIR.glob("scan_*.json"))
json_files = [f for f in json_files if "shscomputer" not in f.name]

targets_findings = {}

for jf in json_files:
    data = json.loads(jf.read_text())
    for key, result in data.items():
        target = result.get("target", key)
        if target not in targets_findings:
            targets_findings[target] = []
        targets_findings[target].append(result)

# Analyse consolidée
summary = defaultdict(lambda: {
    "found": 0, "warn": 0, "info": 0, "errors": 0,
    "tech_stack": set(), "cms": set(), "ssl_protocols": set(),
    "security_grade": None, "missing_headers": [],
    "dirs_found": [], "js_secrets": [],
    "sourcemaps": [], "cors_issues": [],
    "spring_exposure": False, "cert_issues": [],
})

KEY_FINDINGS = []

for target, results in targets_findings.items():
    s = summary[target]
    for r in results:
        mod = r.get("module", "")
        s["errors"] += len(r.get("errors", []))
        for f in r.get("findings", []):
            src = f.get("source", "")
            label = f.get("label", "")
            value = f.get("value", "")
            sev = f.get("severity", "")

            if sev == "found":
                s["found"] += 1
            elif sev == "warn":
                s["warn"] += 1
            elif sev == "info":
                s["info"] += 1

            if label == "Stack":
                s["tech_stack"].add(str(value))
            if label == "Generator":
                s["cms"].add(str(value))
            if label == "Protocol":
                s["ssl_protocols"].add(str(value))
            if label == "Security grade":
                s["security_grade"] = str(value)
            if "Missing" in str(value):
                s["missing_headers"].append(label)
            if src == "paths" and sev == "warn":
                s["dirs_found"].append(f"{label} ({value})")
            if src == "secrets":
                s["js_secrets"].append(f"{label}: {str(value)[:80]}")
            if src == "sourcemaps" and sev == "warn":
                s["sourcemaps"].append(str(value))
            if src == "cors" and "wildcard" in str(value).lower():
                s["cors_issues"].append(str(value))
            if "actuator" in str(label).lower() and "secrets" in str(value).lower():
                s["spring_exposure"] = True
            if label == "SAN" and "reject" in str(value).lower():
                s["cert_issues"].append(str(value))

    # Extraire les warnings notables
    if s["warn"] > 0:
        notable = []
        if s["dirs_found"]:
            critical = [d for d in s["dirs_found"] if any(k in d.lower() for k in [".env", ".git", ".htaccess", ".netrc", ".npmrc", ".pypirc", ".svn", "dockerfile", "actuator/env", "backup", "admin", "phpinfo", "debug", "swagger", "graphql"])]
            if critical:
                notable.append(f"{len(critical)} paths sensibles (ex: {critical[0][:50]})")
        if s["sourcemaps"]:
            notable.append(f"{len(s['sourcemaps'])} source map(s) exposée(s)")
        if s["js_secrets"]:
            notable.append(f"{len(s['js_secrets'])} secret(s)/endpoint(s) dans JS")
        if s["missing_headers"]:
            notable.append(f"{len(s['missing_headers'])} header(s) sécurité manquant(s)")
        if s["spring_exposure"]:
            notable.append("Spring Actuator env exposé")
        if s["cert_issues"]:
            notable.append("Problème certificat TLS")
        if notable:
            KEY_FINDINGS.append((target, s["warn"], s["security_grade"], "; ".join(notable)))

# ── Rapport ──
lines = []
lines.append("=" * 100)
lines.append("  RAPPORT CONSOLIDÉ — PENTEST Fullscan Gouvernement Belge")
lines.append(f"  {len(targets_findings)} sites scannés | {len(json_files)} fichiers JSON analysés")
lines.append("=" * 100)

# Tableau récapitulatif
lines.append("")
lines.append("  RÉCAPITULATIF PAR SITE")
lines.append("-" * 100)
lines.append(f"  {'SITE':<45} {'Warn':>5} {'Found':>6} {'Grade':>8} {'Tech Stack':<30}")
lines.append("-" * 100)

for target in sorted(targets_findings.keys()):
    s = summary[target]
    tech = ", ".join(sorted(s["tech_stack"])[:3]) or "-"
    grade = s["security_grade"] or "-"
    name = target[:44]
    lines.append(f"  {name:<45} {s['warn']:>5} {s['found']:>6} {grade:>8} {tech:<30}")

lines.append("-" * 100)

# Top warnings
lines.append("")
lines.append("=" * 100)
lines.append("  TOP SITES — Plus d'avertissements (warnings)")
lines.append("=" * 100)
KEY_FINDINGS.sort(key=lambda x: -x[1])
for i, (target, warns, grade, details) in enumerate(KEY_FINDINGS[:20], 1):
    lines.append(f"  {i:>2}. {target:<50} Warn: {warns:<4} Grade: {grade or '-':<8}")
    lines.append(f"      → {details}")

# Statistiques globales
total_warns = sum(s["warn"] for s in summary.values())
total_found = sum(s["found"] for s in summary.values())
total_errors = sum(s["errors"] for s in summary.values())
sites_with_dirs = sum(1 for s in summary.values() if s["dirs_found"])

lines.append("")
lines.append("=" * 100)
lines.append("  STATISTIQUES GLOBALES")
lines.append("=" * 100)
lines.append(f"  Sites scannés:              {len(targets_findings)}")
lines.append(f"  Warnings totaux:             {total_warns}")
lines.append(f"  Findings totaux:             {total_found}")
lines.append(f"  Total erreurs:               {total_errors}")
lines.append(f"  Sites avec paths exposés:    {sites_with_dirs}")
lines.append(f"  Sites avec source maps:      {sum(1 for s in summary.values() if s['sourcemaps'])}")
lines.append(f"  Sites avec secrets JS:       {sum(1 for s in summary.values() if s['js_secrets'])}")
lines.append(f"  Sites grade A:               {sum(1 for s in summary.values() if s['security_grade'] and s['security_grade'].startswith('A'))}")
lines.append(f"  Sites grade B:               {sum(1 for s in summary.values() if s['security_grade'] and s['security_grade'].startswith('B'))}")
lines.append(f"  Sites grade C:               {sum(1 for s in summary.values() if s['security_grade'] and s['security_grade'].startswith('C'))}")
lines.append(f"  Sites grade D/F:             {sum(1 for s in summary.values() if s['security_grade'] and s['security_grade'][0] in 'DF')}")
lines.append(f"  Sites Spring Actuator:       {sum(1 for s in summary.values() if s['spring_exposure'])}")

# Détails des paths exposés par site
lines.append("")
lines.append("=" * 100)
lines.append("  DÉTAIL — Paths sensibles exposés")
lines.append("=" * 100)
for target in sorted(targets_findings.keys()):
    s = summary[target]
    if s["dirs_found"]:
        lines.append(f"  ▶ {target}")
        for d in s["dirs_found"][:15]:
            lines.append(f"      {d}")
        if len(s["dirs_found"]) > 15:
            lines.append(f"      ... et {len(s['dirs_found']) - 15} autres")

# Détail source maps
lines.append("")
lines.append("=" * 100)
lines.append("  DÉTAIL — Source Maps exposées (code source récupérable)")
lines.append("=" * 100)
for target in sorted(targets_findings.keys()):
    s = summary[target]
    if s["sourcemaps"]:
        lines.append(f"  ▶ {target}")
        for sm in s["sourcemaps"][:5]:
            lines.append(f"      {sm}")

# Détail secrets JS
lines.append("")
lines.append("=" * 100)
lines.append("  DÉTAIL — Secrets / tokens trouvés dans JS")
lines.append("=" * 100)
for target in sorted(targets_findings.keys()):
    s = summary[target]
    if s["js_secrets"]:
        lines.append(f"  ▶ {target}")
        for sec in s["js_secrets"][:10]:
            lines.append(f"      {sec}")

report_text = "\n".join(lines)
report_path = REPORT_DIR / "rapport_consolide_pentest_belgium.txt"
report_path.write_text(report_text)
print(report_text)
print(f"\n[Rapport sauvegardé → {report_path}]")
