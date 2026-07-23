#!/usr/bin/env python3
"""End-to-end Nexus model smoke evaluation against the local endpoint."""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from pathlib import Path

from osint_toolkit.ai import NexusAI


async def evaluate(cases: list[dict], limit: int | None = None) -> int:
    ai = NexusAI()
    failures = 0
    for case in cases[:limit]:
        start = time.perf_counter()
        answer = await ai.answer(case["prompt"])
        lowered = answer.lower()
        required = any(term.lower() in lowered for term in case["required_any"])
        forbidden = any(term.lower() in lowered for term in case["forbidden"])
        passed = required and not forbidden
        failures += not passed
        print(
            json.dumps(
                {
                    "id": case["id"],
                    "passed": passed,
                    "seconds": round(time.perf_counter() - start, 1),
                    "answer": answer,
                },
                ensure_ascii=False,
            )
        )
    return failures


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    cases = json.loads(
        Path(__file__).with_name("model_eval_cases.json").read_text(encoding="utf-8")
    )
    raise SystemExit(asyncio.run(evaluate(cases, args.limit)))


if __name__ == "__main__":
    main()
