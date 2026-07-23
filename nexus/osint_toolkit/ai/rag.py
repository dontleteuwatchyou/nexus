"""Tiny dependency-free lexical RAG index for Nexus knowledge."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

TOKEN = re.compile(r"[a-zA-ZÀ-ÿ0-9_.+-]{2,}")


def _tokens(text: str) -> list[str]:
    return [item.lower() for item in TOKEN.findall(text)]


@dataclass(frozen=True)
class Document:
    title: str
    content: str
    source: str


class KnowledgeIndex:
    """BM25-style in-memory index, fast enough for the bundled corpus."""

    def __init__(self, documents: list[Document]) -> None:
        self.documents = documents
        self.terms = [Counter(_tokens(doc.title + " " + doc.content)) for doc in documents]
        self.lengths = [sum(freq.values()) for freq in self.terms]
        self.average_length = sum(self.lengths) / max(len(self.lengths), 1)
        self.document_frequency = Counter(
            token for frequencies in self.terms for token in frequencies
        )

    @classmethod
    def bundled(cls) -> KnowledgeIndex:
        root = Path(__file__).with_name("knowledge")
        documents = [
            Document(path.stem.replace("_", " "), path.read_text(encoding="utf-8"), path.name)
            for path in sorted(root.glob("*.md"))
        ]
        return cls(documents)

    def search(self, query: str, limit: int = 3) -> list[Document]:
        if not self.documents:
            return []
        query_terms = set(_tokens(query))
        scored: list[tuple[float, int]] = []
        total = len(self.documents)
        for index, frequencies in enumerate(self.terms):
            score = 0.0
            length = self.lengths[index]
            for token in query_terms:
                count = frequencies.get(token, 0)
                if not count:
                    continue
                frequency = self.document_frequency[token]
                inverse = math.log(1 + (total - frequency + 0.5) / (frequency + 0.5))
                normalised = count * 2.2 / (
                    count + 1.2 * (0.25 + 0.75 * length / max(self.average_length, 1))
                )
                score += inverse * normalised
            if score:
                scored.append((score, index))
        scored.sort(reverse=True)
        return [self.documents[index] for _, index in scored[:limit]]

    def context(self, query: str, limit: int = 3, max_chars: int = 5000) -> str:
        chunks = [
            f"[Source Nexus: {doc.source}]\n{doc.content.strip()}"
            for doc in self.search(query, limit)
        ]
        return "\n\n".join(chunks)[:max_chars]
