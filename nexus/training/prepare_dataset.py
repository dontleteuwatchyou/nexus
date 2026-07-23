#!/usr/bin/env python3
"""Validate and deduplicate Nexus SFT JSONL data."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

SECRET = re.compile(
    r"(-----BEGIN [A-Z ]+PRIVATE KEY-----|"
    r"\b(?:ghp|github_pat|sk_live|AKIA)[A-Za-z0-9_-]{12,}\b)"
)
ROLES = {"system", "user", "assistant"}


def validate(record: dict, line: int) -> str:
    for key in ("messages", "source", "license", "category"):
        if not record.get(key):
            raise ValueError(f"line {line}: missing {key}")
    messages = record["messages"]
    if not isinstance(messages, list) or len(messages) < 2:
        raise ValueError(f"line {line}: messages must contain at least 2 items")
    for message in messages:
        if message.get("role") not in ROLES or not str(message.get("content", "")).strip():
            raise ValueError(f"line {line}: invalid message")
    canonical = json.dumps(messages, ensure_ascii=False, sort_keys=True)
    if SECRET.search(canonical):
        raise ValueError(f"line {line}: possible secret detected")
    return hashlib.sha256(canonical.encode()).hexdigest()


def prepare(source: Path, destination: Path) -> tuple[int, int]:
    seen: set[str] = set()
    kept: list[dict] = []
    with source.open(encoding="utf-8") as stream:
        for line_number, raw in enumerate(stream, 1):
            if not raw.strip():
                continue
            record = json.loads(raw)
            digest = validate(record, line_number)
            if digest not in seen:
                seen.add(digest)
                kept.append(record)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as stream:
        for record in kept:
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")
    return len(kept), len(seen)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    kept, _ = prepare(args.source, args.destination)
    print(f"Dataset ready: {kept} unique records -> {args.destination}")


if __name__ == "__main__":
    main()
