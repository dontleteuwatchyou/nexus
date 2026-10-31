"""Nuclei — template-based vulnerability scanner.

The JSONL output is parsed into canonical-severity findings (critical / high /
medium / low / info) so nuclei results flow straight into the correlated
vulnerability report instead of being flattened to a generic flag.
"""

from __future__ import annotations

import json
import shutil

from ..models import ScanResult
from .base import ExternalTool

_CANON = {"critical", "high", "medium", "low", "info"}


def parse_nuclei_jsonl(stdout: str) -> list[dict]:
    """Parse nuclei ``-jsonl`` output into normalized finding dicts.

    Pure function (no I/O) so it can be unit-tested against captured output.
    Each dict: severity (canonical), name, matched, desc, template.
    """
    out: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            f = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = f.get("info", {}) if isinstance(f, dict) else {}
        sev = str(info.get("severity", "info")).lower()
        if sev not in _CANON:
            sev = "info"
        name = info.get("name") or f.get("template-id") or f.get("template") or "finding"
        matched = f.get("matched-at") or f.get("host") or f.get("url") or ""
        desc = (info.get("description") or "").strip().replace("\n", " ")[:200]
        out.append({
            "severity": sev,
            "name": str(name),
            "matched": str(matched),
            "desc": desc,
            "template": str(f.get("template-id") or f.get("template") or ""),
        })
    return out


class Nuclei(ExternalTool):
    name = "nuclei"
    bin_name = "nuclei"
    accepted_kinds = {"domain", "ip", "url"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 300.0,
        severity: str = "critical,high,medium,low,info",
        tags: str | None = None,
        templates: str | None = None,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        bin_path = shutil.which(cls.bin_name) or "nuclei"
        args = [bin_path, "-u", target, "-silent", "-jsonl", "-severity", severity]
        if tags:
            args.extend(["-tags", tags])
        if templates:
            args.extend(["-t", templates])

        rc, stdout, stderr = await cls._run_subprocess(args, timeout=timeout)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"] = rc
        result.raw["stdout"] = stdout[:50000]
        result.raw["stderr"] = stderr[:8000]

        if rc != 0 and not stdout.strip():
            result.errors.append(f"nuclei failed (rc={rc}): {stderr[:200]}")
            return result

        items = parse_nuclei_jsonl(stdout)
        counts: dict[str, int] = {}
        for it in items:
            counts[it["severity"]] = counts.get(it["severity"], 0) + 1
            detail = it["matched"]
            if it["desc"]:
                detail = f"{detail} — {it['desc']}" if detail else it["desc"]
            url = it["matched"] if it["matched"].startswith("http") else None
            # severity is canonical (critical/high/medium/low/info) → feeds the
            # correlated vulnerability report directly.
            result.add("nuclei", f"[{it['severity'].upper()}] {it['name']}",
                       detail or it["name"], it["severity"], url=url)
        result.raw["severity_counts"] = counts
        return result
