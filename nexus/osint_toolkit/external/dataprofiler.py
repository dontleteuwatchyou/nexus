"""DataProfiler — Capital One's dataset profiler with PII detection.

Repo:    https://github.com/capitalone/DataProfiler
Install: managed in a dedicated venv at ~/.osint-toolkit/tools/dataprofiler/venv/
         because the library pulls heavy deps (TF, scikit-learn).

Use case in OSINT: you obtained a leaked dataset (CSV/JSON/Parquet/Avro/
Excel/Pickle/plain text) and want to know what's in it — columns,
data types, statistics, and **automatically detected PII / sensitive
data** (emails, phone numbers, SSNs, IPs, credit cards, addresses...).

Input: a local file path. The wrapper runs DataProfiler's Profiler in
the venv subprocess and emits JSON, which is parsed back into findings.
If DataProfiler's neural data-labeler isn't available (missing TF /
model), a regex-based PII fallback runs on the extracted samples.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..models import ScanResult
from .base import ExternalTool


# Inline Python program that runs inside the DataProfiler venv.
# Reads the file, profiles it, and prints a compact JSON report.
PROFILE_SCRIPT = r"""
import json, sys, traceback
try:
    from dataprofiler import Data, Profiler, ProfilerOptions
except ImportError as e:
    print(json.dumps({"error": f"dataprofiler not importable: {e}"}))
    sys.exit(1)

path = sys.argv[1]
try:
    data = Data(path)
    opts = ProfilerOptions()
    # Speed up: skip slow correlation matrix on big files
    try:
        opts.set({"structured_options.correlation.is_enabled": False})
    except Exception:
        pass
    profile = Profiler(data, options=opts)
    report = profile.report(report_options={"output_format": "compact"})
    print(json.dumps(report, default=str))
except Exception as e:
    print(json.dumps({"error": str(e), "trace": traceback.format_exc()[-1500:]}))
    sys.exit(2)
"""


# ── PII regex fallbacks ───────────────────────────────────────────
# Run these against extracted samples when DataProfiler's data_labeler
# isn't available (no TF / no model).

PII_PATTERNS: dict[str, re.Pattern] = {
    "EMAIL":          re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$"),
    # Phone must start with + OR match specific groupings (avoids matching SSN/IP/CC)
    "PHONE":          re.compile(
        r"^\+\d[\d\s\-\.\(\)/]{6,18}$"             # international: +1-555-...
        r"|^\(\d{3}\)\s?\d{3}[\s\-]?\d{4}$"         # US: (555) 555-1234
        r"|^\d{3}[\s\-\.]\d{3}[\s\-\.]\d{4}$"       # XXX-XXX-XXXX
    ),
    "SSN_US":         re.compile(r"^\d{3}[\s\-]?\d{2}[\s\-]?\d{4}$"),
    # Credit card: 13-19 digits with at least 13 digits total
    "CREDIT_CARD":    re.compile(r"^\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{1,7}$"),
    "IPV4":           re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$"),
    "IPV6":           re.compile(r"^[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){2,7}$"),
    "MAC":            re.compile(r"^(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$"),
    "UUID":           re.compile(r"^[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}$"),
    "URL":            re.compile(r"^https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$"),
    "IBAN":           re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$"),
    "BITCOIN_ADDR":   re.compile(r"^(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$"),
    "DATE":           re.compile(r"^\d{4}[/\-.]\d{1,2}[/\-.]\d{1,2}$|^\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}$"),
    "JWT":            re.compile(r"^eyJ[A-Za-z0-9_=\-]+\.eyJ[A-Za-z0-9_=\-]+\.[A-Za-z0-9_=\-+/]+$"),
}

# Patterns that only make sense for string columns (skip for numeric cols)
STRING_ONLY_LABELS = {"EMAIL", "URL", "ADDRESS", "FULL_NAME", "USERNAME",
                       "PASSWORD", "CITY", "COUNTRY", "IBAN", "BITCOIN_ADDR",
                       "JWT", "UUID", "MAC"}


NAME_HEURISTICS: list[tuple[str, re.Pattern]] = [
    ("EMAIL",        re.compile(r"e?\-?mail", re.I)),
    ("PHONE",        re.compile(r"(?:phone|mobile|cell|\btel\b)", re.I)),
    ("SSN_US",       re.compile(r"\bssn\b|social.*security", re.I)),
    ("CREDIT_CARD",  re.compile(r"(?:credit|\bcard\b|\bcc\b|\bpan\b|visa|mastercard)", re.I)),
    ("ADDRESS",      re.compile(r"\baddr(?:ess)?\b|street", re.I)),
    ("FULL_NAME",    re.compile(r"\b(?:full[_\s]?name|first[_\s]?name|last[_\s]?name|surname)\b", re.I)),
    ("IPV4",         re.compile(r"\bip(?:v4|_address|address)?\b", re.I)),
    ("PASSWORD",     re.compile(r"(?:passw(?:or)?d|pwd|pass[_\s]?hash)", re.I)),
    # Require username/login/handle as a full word — avoid matching "user_id"
    ("USERNAME",     re.compile(r"\b(?:username|login|handle|nickname)\b", re.I)),
    ("DOB",          re.compile(r"(?:dob|date[_\s]?of[_\s]?birth|birthdate)", re.I)),
    ("COUNTRY",      re.compile(r"\bcountry\b|nationality", re.I)),
    ("CITY",         re.compile(r"\bcity\b|town", re.I)),
    ("POSTAL_CODE",  re.compile(r"(?:zip|postal[_\s]?code|postcode)", re.I)),
    ("IBAN",         re.compile(r"\biban\b|bank[_\s]?account", re.I)),
]


def _extract_samples(col: dict) -> list[str]:
    """Pull out sample values from a DataProfiler column report.

    The compact format stringifies the samples list — we re-parse it.
    """
    stats = col.get("statistics") or {}
    samples = col.get("samples") or stats.get("sample") or stats.get("samples")
    if isinstance(samples, list):
        return [str(s) for s in samples[:20] if s is not None]
    if isinstance(samples, str):
        return [m for m in re.findall(r"'([^']*)'", samples)][:20] or \
                [m for m in re.findall(r'"([^"]*)"', samples)][:20]
    return []


def _detect_pii(col_name: str, samples: list[str], dtype: str) -> set[str]:
    """Return set of detected PII labels for a column."""
    labels: set[str] = set()
    is_numeric = dtype in ("int", "float")

    # Column-name signal (skip string-only labels on numeric cols)
    for label, pat in NAME_HEURISTICS:
        if pat.search(col_name):
            if is_numeric and label in STRING_ONLY_LABELS:
                continue
            labels.add(label)

    # Sample-value signal: each value gets ONE best-fit label
    # (avoids tagging "123-45-6789" as both SSN and PHONE)
    if samples:
        # Priority order — most specific first
        priority = ["EMAIL", "URL", "JWT", "IBAN", "BITCOIN_ADDR", "UUID",
                     "MAC", "IPV6", "IPV4", "SSN_US", "CREDIT_CARD",
                     "PHONE", "DATE"]
        score: dict[str, int] = {}
        for s in samples:
            s = s.strip()
            if not s:
                continue
            # Find the first (most specific) match
            for label in priority:
                pat = PII_PATTERNS.get(label)
                if pat and pat.match(s):
                    score[label] = score.get(label, 0) + 1
                    break
        # Need ≥50 % match rate to flag
        for label, n in score.items():
            if n / max(len(samples), 1) >= 0.5:
                if is_numeric and label in STRING_ONLY_LABELS:
                    continue
                labels.add(label)

    return labels


class DataProfiler(ExternalTool):
    name = "DataProfiler"
    repo_url = "https://github.com/capitalone/DataProfiler.git"
    accepted_kinds = {"file"}

    @classmethod
    def _venv_python(cls) -> Path:
        return cls.install_dir() / "venv" / "bin" / "python"

    @classmethod
    def install_status(cls) -> dict:
        """Override: DataProfiler uses a dedicated venv, not PATH/pip/script."""
        venv_py = cls._venv_python()
        d = cls.install_dir()
        checks = [
            {"type": "Install dir",  "target": str(d),       "found": d.exists()},
            {"type": "venv python",  "target": str(venv_py), "found": venv_py.exists()},
        ]
        # Probe the venv python for the dataprofiler package
        if venv_py.exists():
            import subprocess
            try:
                r = subprocess.run(
                    [str(venv_py), "-c", "import dataprofiler; print(dataprofiler.__file__)"],
                    capture_output=True, text=True, timeout=10,
                )
                checks.append({
                    "type": "venv import",
                    "target": "dataprofiler",
                    "found": r.stdout.strip() if r.returncode == 0 else False,
                })
            except Exception as e:
                checks.append({
                    "type": "venv import",
                    "target": "dataprofiler",
                    "found": f"error: {e}",
                })
        installed = venv_py.exists()
        return {
            "name": cls.name,
            "installed": installed,
            "method": f"venv python at {venv_py}" if installed else None,
            "checks": checks,
        }

    @classmethod
    def is_installed(cls) -> bool:
        return cls._venv_python().exists()

    @classmethod
    def install_hint(cls) -> str:
        d = cls.install_dir()
        return (
            f"git clone {cls.repo_url} {d}  &&  "
            f"cd {d}  &&  "
            f"python3 -m venv venv  &&  "
            f"source venv/bin/activate  &&  "
            f"pip install -U pip setuptools wheel  &&  "
            f"pip install -r requirements.txt"
        )

    @classmethod
    async def scan(cls, target: str, *, timeout: float = 300.0,
                    **kwargs) -> ScanResult:
        result = ScanResult(target=target, module=f"external:{cls.name}")

        if not cls.is_installed():
            return cls._not_installed_result(target)

        path = Path(target).expanduser().resolve()
        if not path.exists():
            result.add("input", "Status", f"File not found: {path}", "error")
            result.errors.append(f"No such file: {path}")
            return result
        if not path.is_file():
            result.add("input", "Status", f"Not a regular file: {path}", "error")
            result.errors.append(f"Not a file: {path}")
            return result

        result.add("input", "File", str(path), "info")
        try:
            size_mb = path.stat().st_size / 1024 / 1024
            result.add("input", "Size", f"{size_mb:.2f} MB", "info")
        except Exception:
            pass

        rc, stdout, stderr = await cls._run_subprocess(
            [str(cls._venv_python()), "-c", PROFILE_SCRIPT, str(path)],
            timeout=timeout,
        )
        result.raw["return_code"] = rc
        result.raw["stderr"] = stderr[:4000]

        if rc != 0 and not stdout.strip().startswith("{"):
            result.errors.append(
                f"DataProfiler failed (rc={rc}): {stderr[:300] or 'no stderr'}"
            )
            return result

        # Parse JSON — find the last JSON object in stdout
        report = None
        for line in reversed(stdout.splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    report = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue
        if report is None:
            result.errors.append("Could not parse DataProfiler JSON output")
            result.raw["stdout_tail"] = stdout[-2000:]
            return result

        if "error" in report:
            result.add("dataprofiler", "Error", report["error"], "error")
            if "trace" in report:
                result.raw["trace"] = report["trace"]
            return result

        result.raw["report"] = report

        # ── Global stats ──
        global_stats = report.get("global_stats", {}) or {}
        if global_stats:
            for k in ("samples_used", "row_count", "column_count",
                       "row_has_null_ratio", "row_is_null_ratio",
                       "unique_row_ratio", "duplicate_row_count",
                       "file_type", "encoding"):
                v = global_stats.get(k)
                if v is not None:
                    result.add("global", k, str(v), "info")

        # ── Per-column ──
        data_stats = report.get("data_stats") or []
        if data_stats:
            result.add("columns", "Total columns", str(len(data_stats)), "info")

        sensitive_hits: dict[str, list[str]] = {}
        used_labeler = False

        for col in data_stats or []:
            col_name = col.get("column_name") or col.get("name") or "?"
            dtype = col.get("data_type", "?")
            cat = col.get("categorical", False)
            stats = col.get("statistics", {}) or {}
            unique = stats.get("unique_count") or stats.get("unique")
            null_count = stats.get("null_count")

            value = f"{dtype}"
            if cat:
                value += " · categorical"
            if unique is not None:
                value += f" · {unique} unique"
            if null_count:
                value += f" · {null_count} nulls"
            result.add("columns", col_name, value, "info")

            # Sample preview
            samples = _extract_samples(col)
            if samples:
                preview = [s[:40] for s in samples[:3] if s]
                if preview:
                    result.add(f"sample · {col_name}", "examples",
                                " | ".join(preview), "info")

            # Try DataProfiler's labeler first
            col_labels: set[str] = set()
            labels_raw = col.get("data_label") or col.get("data_label_probabilities")
            if labels_raw:
                used_labeler = True
                if isinstance(labels_raw, dict):
                    sorted_lbl = sorted(labels_raw.items(),
                                          key=lambda x: -float(x[1] or 0))
                    top_label, top_prob = sorted_lbl[0]
                    if top_label and top_label.upper() not in ("UNKNOWN", "BACKGROUND") \
                            and float(top_prob or 0) > 0.5:
                        col_labels.add(top_label.upper())
                elif isinstance(labels_raw, str):
                    if labels_raw.upper() not in ("UNKNOWN", "BACKGROUND"):
                        col_labels.add(labels_raw.upper())

            # Regex fallback (always runs — complements the labeler)
            col_labels.update(_detect_pii(col_name, samples, dtype))

            for lbl in col_labels:
                sensitive_hits.setdefault(lbl, []).append(col_name)

        # ── Sensitive data summary ──
        if sensitive_hits:
            n_cols = sum(len(v) for v in sensitive_hits.values())
            method = "labeler + regex" if used_labeler else "regex fallback (labeler unavailable)"
            result.add("pii", "Sensitive data detected",
                        f"{len(sensitive_hits)} type(s) across {n_cols} column(s)",
                        "warn")
            result.add("pii", "Detection method", method, "info")
            for label, cols in sorted(sensitive_hits.items()):
                result.add("pii", label, ", ".join(cols), "warn")
        else:
            result.add("pii", "Sensitive data detected", "None", "found")

        return result
