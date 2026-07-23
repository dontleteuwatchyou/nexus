#!/usr/bin/env python3
"""Offline retrieval regression test for the bundled Nexus corpus."""

from __future__ import annotations

import json
from pathlib import Path

from osint_toolkit.ai import KnowledgeIndex


def evaluate(cases_path: Path) -> tuple[int, int]:
    cases = json.loads(cases_path.read_text(encoding="utf-8"))
    index = KnowledgeIndex.bundled()
    passed = 0
    for case in cases:
        results = index.search(case["query"], limit=1)
        actual = results[0].source if results else None
        ok = actual == case["expected_source"]
        passed += ok
        print(f"{'PASS' if ok else 'FAIL'} {case['query']} -> {actual}")
    return passed, len(cases)


if __name__ == "__main__":
    root = Path(__file__).parent
    passed, total = evaluate(root / "eval_cases.json")
    print(f"RAG recall@1: {passed}/{total} ({passed / max(total, 1):.0%})")
    raise SystemExit(0 if passed == total else 1)
