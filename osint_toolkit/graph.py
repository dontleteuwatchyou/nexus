"""Entity graph + finding harvester for cross-module correlation.

The OSINT/pentest modules each return a flat :class:`ScanResult`. On their
own they are a bag of independent lookups. The real power of a *unified*
framework is turning those into a connected picture: the username in a
Gravatar profile is the same username GitHub knows, whose commit email is
the email we started from, whose domain resolves to the IP that reverse-DNSes
back to the domain. This module models that as a typed, de-duplicated graph.

Two concepts:

* :class:`EntityGraph` — nodes (typed, normalised, de-duplicated) and edges
  (typed relations with provenance). An entity asserted by several independent
  source modules carries higher confidence ("corroborated").
* :func:`harvest` — reads one :class:`ScanResult`, folds the entities and
  relations it exposes into a graph, and returns the subset worth scanning
  next (the *pivots*).

Nothing here touches the network; it is pure data transformation and is
trivially unit-testable offline.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

# Entity kinds that a scanner module exists for (i.e. can be pivoted into).
SCANNABLE: frozenset[str] = frozenset(
    {"email", "username", "domain", "ip", "url", "phone", "crypto"}
)

# Pivot (kind, value) pairs.
Pivot = tuple[str, str]


def _norm(kind: str, value: str) -> str:
    """Normalise an entity value so duplicates collapse onto one node."""
    v = (value or "").strip()
    if kind in ("email", "username", "domain", "person", "org"):
        v = v.lower().rstrip(".")
    elif kind == "url":
        v = v.rstrip("/")
    return v


@dataclass
class EntityNode:
    kind: str
    value: str
    sources: set[str] = field(default_factory=set)   # modules that asserted it
    attrs: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> Pivot:
        return (self.kind, _norm(self.kind, self.value))

    @property
    def confidence(self) -> float:
        """0..1 — corroboration by independent sources raises confidence."""
        return min(1.0, 0.55 + 0.2 * (len(self.sources) - 1)) if self.sources else 0.5

    @property
    def corroborated(self) -> bool:
        return len(self.sources) >= 2

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "value": self.value,
            "sources": sorted(self.sources),
            "confidence": round(self.confidence, 2),
            "corroborated": self.corroborated,
            "attrs": self.attrs,
        }


@dataclass(frozen=True)
class Edge:
    src: Pivot
    dst: Pivot
    relation: str
    source: str

    def as_dict(self) -> dict:
        return {
            "src": list(self.src),
            "dst": list(self.dst),
            "relation": self.relation,
            "source": self.source,
        }


class EntityGraph:
    """A de-duplicated, provenance-tracked graph of discovered entities."""

    def __init__(self) -> None:
        self.nodes: dict[Pivot, EntityNode] = {}
        self.edges: set[Edge] = set()

    def add_entity(self, kind: str, value: str, *, source: str,
                   **attrs: Any) -> Pivot | None:
        value = (value or "").strip()
        if not value:
            return None
        key = (kind, _norm(kind, value))
        node = self.nodes.get(key)
        if node is None:
            node = EntityNode(kind=kind, value=value)
            self.nodes[key] = node
        if source:
            node.sources.add(source)
        for k, v in attrs.items():
            if v is not None and v != "":
                node.attrs.setdefault(k, v)
        return key

    def add_edge(self, src: Pivot | None, dst: Pivot | None,
                 relation: str, *, source: str) -> None:
        if not src or not dst or src == dst:
            return
        self.edges.add(Edge(src, dst, relation, source))

    def link(self, src_kind: str, src_val: str, relation: str,
             dst_kind: str, dst_val: str, *, source: str,
             **dst_attrs: Any) -> Pivot | None:
        """Add the destination entity and an edge from src to it in one call."""
        s = self.add_entity(src_kind, src_val, source=source)
        d = self.add_entity(dst_kind, dst_val, source=source, **dst_attrs)
        self.add_edge(s, d, relation, source=source)
        return d

    # ── Views ──────────────────────────────────────────────────────

    def neighbors(self, key: Pivot) -> list[tuple[str, EntityNode]]:
        out: list[tuple[str, EntityNode]] = []
        for e in self.edges:
            if e.src == key and e.dst in self.nodes:
                out.append((e.relation, self.nodes[e.dst]))
            elif e.dst == key and e.src in self.nodes:
                out.append((e.relation, self.nodes[e.src]))
        return out

    def corroborated(self) -> list[EntityNode]:
        """Entities confirmed by two or more independent source modules."""
        return sorted(
            (n for n in self.nodes.values() if n.corroborated),
            key=lambda n: (-len(n.sources), n.kind, n.value),
        )

    def by_kind(self, kind: str) -> list[EntityNode]:
        return [n for n in self.nodes.values() if n.kind == kind]

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for n in self.nodes.values():
            counts[n.kind] = counts.get(n.kind, 0) + 1
        return dict(sorted(counts.items()))

    def as_dict(self) -> dict:
        return {
            "nodes": [n.as_dict() for n in self.nodes.values()],
            "edges": [e.as_dict() for e in self.edges],
            "summary": self.summary(),
        }


# ── Harvesting ─────────────────────────────────────────────────────

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def _as_pivot(kind: str, value: str) -> Pivot | None:
    v = (value or "").strip()
    if kind in SCANNABLE and v:
        return (kind, v)
    return None


def harvest(graph: EntityGraph, result: ScanResult,  # type: ignore[name-defined]  # noqa: F821
            *, seed: Pivot | None = None,
            max_pivots: int = 12) -> list[Pivot]:
    """Fold *result* into *graph*; return pivot (kind, value) pairs to scan next.

    *seed* is the entity this result is about (so edges point out from it). If
    omitted it is inferred from ``result.module`` + ``result.target``.
    """
    module = result.module
    target = result.target
    raw = result.raw or {}
    pivots: list[Pivot] = []

    def _pivot(kind: str, value: str) -> None:
        p = _as_pivot(kind, value)
        if p and p not in pivots:
            pivots.append(p)

    # Infer the seed entity for this result.
    seed_kind = {
        "email": "email", "username": "username", "domain": "domain",
        "ip": "ip", "github": "username", "social": None,
        "web": "url", "phone": "phone", "crypto": "crypto",
    }.get(module, None)
    if seed is None and seed_kind:
        seed = graph.add_entity(seed_kind, target, source=module)
    elif seed is not None:
        graph.add_entity(seed[0], seed[1], source=module)

    src = module

    def _edge(relation: str, dst_kind: str, dst_val: str, **attrs: Any) -> None:
        d = graph.add_entity(dst_kind, dst_val, source=src, **attrs)
        if seed and d:
            graph.add_edge(seed, d, relation, source=src)

    # ── email ──────────────────────────────────────────────────────
    if module == "email":
        if "@" in target:
            _edge("has_domain", "domain", target.split("@", 1)[1])
            _pivot("domain", target.split("@", 1)[1])
        g = raw.get("gravatar") or {}
        if g.get("preferred_username"):
            _edge("gravatar_username", "username", g["preferred_username"])
            _pivot("username", g["preferred_username"])
        for nm in (g.get("name"), g.get("display_name")):
            if nm:
                _edge("gravatar_name", "person", nm)
        for acc in g.get("verified_accounts", []) or []:
            if acc.get("url"):
                _edge("verified_account", "url", acc["url"],
                      platform=acc.get("shortname"))
        for prof in (raw.get("emailrep") or {}).get("profiles", []) or []:
            _edge("emailrep_profile", "account", str(prof))

    # ── username ───────────────────────────────────────────────────
    elif module == "username":
        for acc in raw.get("found", []) or []:
            if isinstance(acc, dict) and acc.get("url"):
                _edge("account_on", "url", acc["url"], platform=acc.get("name"))

    # ── github ─────────────────────────────────────────────────────
    elif module == "github":
        prof = raw.get("profile") or {}
        if prof.get("name"):
            _edge("github_name", "person", prof["name"])
        if prof.get("email"):
            _edge("github_email", "email", prof["email"])
            _pivot("email", prof["email"])
        if prof.get("twitter_username"):
            _edge("github_twitter", "username", prof["twitter_username"])
            _pivot("username", prof["twitter_username"])
        if prof.get("blog"):
            _edge("github_blog", "url", prof["blog"])
        for em in raw.get("commit_emails", []) or []:
            if "noreply" not in em.lower():
                _edge("commit_email", "email", em)
                _pivot("email", em)
        for org in raw.get("orgs", []) or []:
            if org:
                _edge("member_of", "org", org)

    # ── domain ─────────────────────────────────────────────────────
    elif module == "domain":
        dns = raw.get("dns") or {}
        for ip in (dns.get("A") or [])[:2]:
            _edge("resolves_to", "ip", ip)
            _pivot("ip", ip)
        _edge("website", "url", f"https://{target}")
        for sub in (raw.get("subdomains") or [])[:25]:
            graph.link("domain", sub, "subdomain_of", "domain", target, source=src)
        for wv in (raw.get("whois") or {}).values() if isinstance(raw.get("whois"), dict) else []:
            for em in _EMAIL_RE.findall(str(wv)):
                _edge("whois_email", "email", em)

    # ── ip ─────────────────────────────────────────────────────────
    elif module == "ip":
        for f in result.findings:
            if f.label == "Reverse DNS (PTR)" and f.value:
                host = str(f.value).rstrip(".")
                _edge("reverse_dns", "domain", host)
                parts = host.split(".")
                if len(parts) >= 2:
                    _pivot("domain", ".".join(parts[-2:]))
                break

    # ── web ────────────────────────────────────────────────────────
    elif module == "web":
        host = re.sub(r"^https?://", "", target).split("/", 1)[0]
        if host:
            _edge("web_host", "domain", host)

    return pivots[:max_pivots]


def harvest_all(results: Iterable[ScanResult]) -> EntityGraph:  # type: ignore[name-defined]  # noqa: F821
    """Build a single graph from an iterable of already-collected results."""
    g = EntityGraph()
    for r in results:
        harvest(g, r)
    return g
