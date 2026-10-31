"""Cross-module dispatch and correlation.

Three categories:
  • OSINT      — passive public-source queries  (modules/*)
  • RECON      — active probes on the target    (recon/*)
  • EXTERNAL   — wrappers around 3rd-party CLI tools (external/*)
"""

from __future__ import annotations

import asyncio
import inspect
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from .external import ALL_TOOLS, find_tool
from .graph import EntityGraph, harvest
from .models import ScanResult
from .modules import breach as osint_breach
from .modules import crypto as osint_crypto
from .modules import domain as osint_domain
from .modules import dorks as osint_dorks
from .modules import email as osint_email
from .modules import github as osint_github
from .modules import image as osint_image
from .modules import ip as osint_ip
from .modules import phone as osint_phone
from .modules import social as osint_social
from .modules import username as osint_username
from .modules import web as osint_web
from .pentest import admin_finder as recon_admin
from .pentest import dirs as recon_dirs
from .pentest import dns_sec as recon_dns_sec
from .pentest import fingerprint as recon_fingerprint
from .pentest import graphql as recon_graphql
from .pentest import headers as recon_headers
from .pentest import js_recon as recon_js
from .pentest import ports as recon_ports
from .pentest import s3 as recon_s3
from .pentest import spring as recon_spring
from .pentest import ssl_audit as recon_ssl
from .pentest import subdomains as recon_subs
from .pentest import web_audit as recon_web_audit

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def detect_target_type(target: str) -> str:
    t = (target or "").strip()
    if osint_email.is_valid(t):           return "email"
    if osint_ip.is_valid(t):              return "ip"
    if osint_crypto.is_valid(t):          return "crypto"  # before username (BTC ~ username)
    if re.match(r"^https?://", t):        return "url"
    if re.match(r"^\+?\d[\d\s\-\.\(\)/]{6,17}$", t): return "phone"
    if osint_domain.is_valid(t):          return "domain"
    if " " in t and len(t.split()) >= 2:  return "name"
    if osint_username.is_valid(t):        return "username"
    return "unknown"


# ── Module catalogue ──────────────────────────────────────────────

ScanFn = Callable[..., Awaitable[ScanResult]]

OSINT_MODULES: dict[str, ScanFn] = {
    "email":     osint_email.scan,
    "username":  osint_username.scan,
    "domain":    osint_domain.scan,
    "ip":        osint_ip.scan,
    "phone":     osint_phone.scan,
    "url":       osint_web.scan,
    "web":       osint_web.scan,
    "social":    osint_social.scan,
    "breach":    osint_breach.scan,
    "github":    osint_github.scan,
    "image":     osint_image.scan,
    "crypto":    osint_crypto.scan,
    "dorks":     osint_dorks.scan,
}

# Which target types each OSINT module is meaningful for. Used by the
# full scan so we don't, e.g., run the `username` module against a domain
# (which would emit bogus "accounts found").
OSINT_TARGET_TYPES: dict[str, set[str]] = {
    "email":    {"email"},
    "username": {"username"},
    "domain":   {"domain"},
    "ip":       {"ip"},
    "phone":    {"phone"},
    "url":      {"url", "domain"},
    "web":      {"url", "domain"},
    "social":   {"username", "name"},
    "breach":   {"email", "domain", "username"},
    "github":   {"username"},
    # image is explicit-only (`-m image <image-url>`); empty set keeps it out
    # of --fullscan, where reverse-image links on a website URL are just noise.
    "image":    set(),
    "crypto":   {"crypto"},
    "dorks":    {"domain", "url", "email", "username", "name"},
}

PENTEST_MODULES: dict[str, ScanFn] = {
    "ports":         recon_ports.scan,
    "subdomains":    recon_subs.scan,
    "fingerprint":   recon_fingerprint.scan,
    "ssl":           recon_ssl.scan,
    "dirs":          recon_dirs.scan,
    "admin-finder":  recon_admin.scan,
    "cors":          recon_web_audit.scan_cors,
    "open-redirect": recon_web_audit.scan_open_redirect,
    "spring":        recon_spring.scan,
    "js":            recon_js.scan,
    "s3":            recon_s3.scan,
    "headers":       recon_headers.scan,
    "dns-sec":       recon_dns_sec.scan,
    "graphql":       recon_graphql.scan,
}


async def _external_scan(target: str, *, module: str, timeout: float = 60.0,
                          **kwargs) -> ScanResult:
    """Dispatch to an external tool wrapper by name."""
    tool_cls = find_tool(module)
    if tool_cls is None:
        r = ScanResult(target=target, module=f"external:{module}")
        r.errors.append(f"Unknown external tool: {module}")
        return r
    # Auto-pick kind from target if not provided
    kwargs.setdefault("kind", detect_target_type(target))
    return await tool_cls.scan(target, timeout=timeout, **kwargs)


EXTERNAL_MODULES: dict[str, ScanFn] = {
    t.name.lower(): (lambda target, *, tc=t, timeout=60.0, **kw:
                      tc.scan(target, timeout=timeout, **kw))
    for t in ALL_TOOLS
}


PENTEST_TARGET_TYPES: dict[str, set[str]] = {
    "ports":         {"domain", "ip", "url"},
    "subdomains":    {"domain"},
    "fingerprint":   {"domain", "url"},
    "ssl":           {"domain", "url", "ip"},
    "dirs":          {"domain", "url"},
    "admin-finder":  {"domain", "url"},
    "cors":          {"domain", "url"},
    "open-redirect": {"domain", "url"},
    "spring":        {"domain", "url"},
    "js":            {"domain", "url"},
    "s3":            {"username", "domain", "name"},  # keyword-based
    "headers":       {"domain", "url"},
    "dns-sec":       {"domain"},
    "graphql":       {"domain", "url"},
}


# External tools that must NEVER run as part of an unattended --fullscan:
# denial-of-service, brute-force / password-spray, flooders, and purely
# interactive attack frameworks. They stay available via explicit
# `-c external -m <tool>`, but a full scan must remain non-destructive.
FULLSCAN_EXCLUDE: set[str] = {
    # DoS
    "slowhttptest", "thc-ssl-dos", "thc-pptp-bruter",
    # brute-force / password spray
    "hydra", "medusa", "ncrack", "crowbar", "patator", "kerbrute",
    "sucrack", "smtp-user-enum", "polenum",
    # VoIP flood / fuzz
    "iaxflood", "inviteflood", "protos-sip", "siparmyknife", "sipp",
    "sippts", "sipsak", "sipvicious-svmap", "sipvicious-svwar",
    "sipvicious-svcrack", "sipvicious-svcrash",
    # interactive / hands-on frameworks (only emit notes, add only noise)
    "metasploit", "msfvenom", "havoc", "koadic", "bettercap",
    "evil-winrm", "chisel", "iodine", "stunnel", "maltego",
    "bloodhound", "ntlmrelayx", "psexec", "wmiexec", "secretsdump",
}


def list_modules() -> dict[str, list[str]]:
    return {
        "osint":    list(OSINT_MODULES.keys()),
        "pentest":    list(PENTEST_MODULES.keys()),
        "external": [t.name for t in ALL_TOOLS],
    }


# ── Scan dispatch ─────────────────────────────────────────────────

def _accepts(func: ScanFn, name: str) -> bool:
    """True if *func* declares a keyword parameter called *name*.

    Lets us forward `progress_cb` only to modules that actually support
    it, without every module needing to accept it.
    """
    try:
        return name in inspect.signature(func).parameters
    except (TypeError, ValueError):
        return False


async def scan_one(target: str, *,
                    category: str = "osint",
                    module: str | None = None,
                    timeout: float = 30.0,
                    progress_cb=None,
                    **kwargs) -> ScanResult:
    category = category.lower()

    if category == "osint":
        mod_name = module or detect_target_type(target)
        func = OSINT_MODULES.get(mod_name)
        if not func:
            r = ScanResult(target=target, module="unknown")
            r.errors.append(f"Cannot determine OSINT module for: {target}")
            return r
        call_kwargs = {"timeout": timeout}
        if progress_cb is not None and _accepts(func, "progress_cb"):
            call_kwargs["progress_cb"] = progress_cb
        return await func(target, **call_kwargs)

    if category == "pentest":
        if not module:
            r = ScanResult(target=target, module="unknown")
            r.errors.append("Recon module must be specified explicitly")
            return r
        func = PENTEST_MODULES.get(module)
        if not func:
            r = ScanResult(target=target, module=module)
            r.errors.append(f"Unknown pentest module: {module}")
            return r
        call_kwargs = {"timeout": timeout}
        if progress_cb is not None and _accepts(func, "progress_cb"):
            call_kwargs["progress_cb"] = progress_cb
        return await func(target, **call_kwargs)

    if category == "external":
        if not module:
            r = ScanResult(target=target, module="unknown")
            r.errors.append("External tool must be specified explicitly")
            return r
        return await _external_scan(target, module=module, timeout=timeout,
                                     **kwargs)

    r = ScanResult(target=target, module="unknown")
    r.errors.append(f"Unknown category: {category}")
    return r


# ── Correlation engine (OSINT) ────────────────────────────────────
#
# Each discovered entity is *enriched* by every module meaningful for its
# kind (not just the one canonical module), the results are harvested into
# a shared EntityGraph, and the pivots that fall out are expanded — breadth
# first, concurrently, depth-limited and de-duplicated. The graph records
# provenance, so an entity reached from two independent directions is marked
# corroborated.

# Modules run for each entity kind. `social` is network-free link generation
# (cheap), `github` adds strong identity links for usernames.
ENRICH_MODULES: dict[str, list[str]] = {
    "email":    ["email", "social"],
    "username": ["username", "github", "social"],
    "domain":   ["domain"],
    "ip":       ["ip"],
    "url":      ["web"],
    "phone":    ["phone", "social"],
    "crypto":   ["crypto"],
    "name":     ["social"],
}

# Safety valve: however tangled the pivots get, never scan more than this
# many distinct entities in one correlation run.
_MAX_ENTITIES = 60


@dataclass
class Correlation:
    """Result of a correlation run: the raw per-module scans + the graph."""
    results: dict[str, ScanResult]
    graph: EntityGraph


async def correlate(target: str, *, depth: int = 2,
                    timeout: float = 30.0,
                    concurrency: int = 8,
                    progress_cb=None) -> Correlation:
    """Depth-limited, concurrent, cross-module correlation scan.

    Returns a :class:`Correlation` holding every module result keyed by
    ``module:value`` plus the de-duplicated :class:`EntityGraph` linking the
    entities those modules surfaced.
    """
    seed_kind = detect_target_type(target)
    graph = EntityGraph()
    results: dict[str, ScanResult] = {}

    if seed_kind == "unknown":
        r = ScanResult(target=target, module="unknown")
        r.errors.append("Could not determine target type")
        return Correlation({f"unknown:{target}": r}, graph)

    visited: set[tuple[str, str]] = set()
    sem = asyncio.Semaphore(max(1, concurrency))

    def _mark(kind: str, value: str) -> bool:
        """Reserve an entity for scanning; False if already taken/over budget."""
        key = (kind, value.lower() if kind != "url" else value.rstrip("/"))
        if key in visited or len(visited) >= _MAX_ENTITIES:
            return False
        visited.add(key)
        return True

    async def _run_module(mod: str, value: str) -> tuple[str, ScanResult]:
        func = OSINT_MODULES.get(mod)
        if func is None:
            r = ScanResult(target=value, module=mod)
            r.errors.append(f"No such module: {mod}")
            return mod, r
        async with sem:
            try:
                res = await asyncio.wait_for(func(value, timeout=timeout),
                                             timeout=timeout)
            except asyncio.TimeoutError:
                res = ScanResult(target=value, module=mod)
                res.errors.append(f"TIMEOUT ({timeout}s)")
            except Exception as e:  # noqa: BLE001 - never let one module kill the run
                res = ScanResult(target=value, module=mod)
                res.errors.append(f"Scan failed: {e}")
        return mod, res

    async def _expand(kind: str, value: str, level: int):
        if not _mark(kind, value):
            return
        if progress_cb:
            progress_cb(f"[{kind}] {value}")
        seed = graph.add_entity(kind, value, source="seed")

        mods = ENRICH_MODULES.get(kind, [kind])
        scanned = await asyncio.gather(*[_run_module(m, value) for m in mods])

        pivots: list[tuple[str, str]] = []
        for mod, res in scanned:
            results[f"{mod}:{value}"] = res
            for p in harvest(graph, res, seed=seed):
                if p not in pivots:
                    pivots.append(p)

        if level < depth and pivots:
            await asyncio.gather(
                *[_expand(pk, pv, level + 1) for pk, pv in pivots]
            )

    await _expand(seed_kind, target, 0)
    return Correlation(results, graph)


async def scan_chained(target: str, *, depth: int = 1,
                        timeout: float = 30.0,
                        progress_cb=None) -> dict[str, ScanResult]:
    """Back-compatible wrapper: the per-module results of a correlation run.

    Kept so existing CLI/TUI callers keep working; new code should call
    :func:`correlate` to also get the entity graph.
    """
    corr = await correlate(target, depth=depth, timeout=timeout,
                           progress_cb=progress_cb)
    return corr.results


# ── Full scan (all categories) ─────────────────────────────────────

async def scan_full(target: str, *, timeout: float = 60.0,
                     category: str | None = None,
                     progress_cb=None,
                     concurrency: int = 10,
                     external_concurrency: int = 5) -> dict[str, ScanResult]:
    """Run all applicable modules against target.

    If category is set to "osint", "pentest", or "external", only that
    category is run.  Otherwise all three categories are run.

    Modules run **concurrently** with bounded parallelism: light
    (osint/pentest) modules share a pool of size *concurrency*, and the
    subprocess-heavy external tools share a smaller pool of size
    *external_concurrency* so a machine full of installed tools does not
    turn a full scan into a 20-minute sequential crawl.

    If *progress_cb* is given, it is called after each module finishes
    as ``progress_cb(key: str, result: ScanResult, done: int, total: int)``.
    """
    results: dict[str, ScanResult] = {}
    typ = detect_target_type(target)

    # Pre‑compute total so progress can show a fraction
    tasks: list[tuple[str, str, str | None]] = []  # (cat, mod, target_val)

    if category is None or category == "osint":
        for mod in OSINT_MODULES:
            if typ in OSINT_TARGET_TYPES.get(mod, {typ}):
                tasks.append(("osint", mod, target))

    if category is None or category == "pentest":
        for mod, allowed in PENTEST_TARGET_TYPES.items():
            if typ in allowed:
                tasks.append(("pentest", mod, target))

    if category is None or category == "external":
        for tool_cls in ALL_TOOLS:
            if tool_cls.name.lower() in FULLSCAN_EXCLUDE:
                continue  # destructive / interactive — not for unattended scans
            if typ in tool_cls.accepted_kinds:
                tasks.append(("external", tool_cls.name, target))

    total = len(tasks)

    # Two pools: light httpx modules can fan out wide; subprocess-heavy
    # external tools are throttled so we don't spawn dozens of scanners
    # (each with its own -t 50 threads) against the target at once.
    light_sem = asyncio.Semaphore(max(1, concurrency))
    ext_sem = asyncio.Semaphore(max(1, external_concurrency))
    progress_lock = asyncio.Lock()
    done = 0

    async def _run_one(idx: int, cat: str, mod: str) -> tuple[int, str, ScanResult]:
        nonlocal done
        key = f"{cat}:{mod}:{target}"
        sem = ext_sem if cat == "external" else light_sem
        async with sem:
            try:
                if cat == "external":
                    coro = _external_scan(target, module=mod, timeout=timeout)
                else:
                    coro = scan_one(target, category=cat, module=mod,
                                    timeout=timeout)
                res = await asyncio.wait_for(coro, timeout=timeout)
            except asyncio.TimeoutError:
                res = ScanResult(target=target, module=f"{cat}:{mod}")
                res.errors.append(f"TIMEOUT ({timeout}s)")
            except Exception as e:
                res = ScanResult(target=target, module=f"{cat}:{mod}")
                res.errors.append(f"{cat.upper()} {mod} failed: {e}")
        if progress_cb:
            async with progress_lock:
                done += 1
                progress_cb(f"{cat}:{mod}", res, done, total)
        return idx, key, res

    pending = [
        asyncio.create_task(_run_one(idx, cat, mod))
        for idx, (cat, mod, val) in enumerate(tasks, 1)
    ]
    hard_deadline = max(60.0, timeout * 3)
    done, still_pending = await asyncio.wait(pending, timeout=hard_deadline)
    for t in still_pending:
        t.cancel()
    for t in done:
        try:
            _idx, key, res = t.result()
            results[key] = res
        except Exception:
            pass

    return results
