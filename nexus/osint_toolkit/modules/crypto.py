"""Cryptocurrency address OSINT — 100% free sources, no API keys.

Detects the address type (Bitcoin legacy / bech32, Ethereum) and pulls
on-chain activity from free block explorers, then adds manual-lookup links
to the explorers that can't be queried without a key.

Sources:
- blockchain.info  (BTC balance / tx history)     — free, no key
- mempool.space    (BTC backup, native bech32)     — free, no key
- Ethplorer        (ETH balance / tokens, freekey) — free public key
- Link-only: Blockchair · WalletExplorer · OXT · BitcoinWhosWho · Etherscan
"""

from __future__ import annotations

import asyncio
import re

import httpx

from ..http import get_json, session
from ..models import ScanResult


BTC_LEGACY_RE = re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$")
BTC_BECH32_RE = re.compile(r"^bc1[a-z0-9]{11,87}$")
ETH_RE        = re.compile(r"^0x[a-fA-F0-9]{40}$")


def detect_kind(addr: str) -> str | None:
    a = (addr or "").strip()
    if ETH_RE.match(a):
        return "eth"
    if BTC_BECH32_RE.match(a) or BTC_LEGACY_RE.match(a):
        return "btc"
    return None


def is_valid(addr: str) -> bool:
    return detect_kind(addr) is not None


def _sat_to_btc(sat: int | float | None) -> str:
    try:
        return f"{(int(sat) / 1e8):.8f} BTC"
    except (TypeError, ValueError):
        return "?"


# ── Sources ───────────────────────────────────────────────────────

async def _btc_blockchain_info(client: httpx.AsyncClient, addr: str) -> dict | None:
    j = await get_json(client, f"https://blockchain.info/rawaddr/{addr}?limit=1",
                       timeout=15)
    if not j or not isinstance(j, dict) or "address" not in j:
        return None
    return {
        "source":         "blockchain.info",
        "balance":        _sat_to_btc(j.get("final_balance")),
        "total_received": _sat_to_btc(j.get("total_received")),
        "total_sent":     _sat_to_btc(j.get("total_sent")),
        "tx_count":       j.get("n_tx"),
    }


async def _btc_mempool(client: httpx.AsyncClient, addr: str) -> dict | None:
    """Fallback / cross-check via mempool.space (also validates bech32)."""
    j = await get_json(client, f"https://mempool.space/api/address/{addr}", timeout=12)
    if not j or not isinstance(j, dict):
        return None
    cs = j.get("chain_stats") or {}
    funded = cs.get("funded_txo_sum", 0)
    spent  = cs.get("spent_txo_sum", 0)
    return {
        "source":         "mempool.space",
        "balance":        _sat_to_btc(funded - spent),
        "total_received": _sat_to_btc(funded),
        "tx_count":       cs.get("tx_count"),
    }


async def _eth_ethplorer(client: httpx.AsyncClient, addr: str) -> dict | None:
    j = await get_json(
        client, f"https://api.ethplorer.io/getAddressInfo/{addr}?apiKey=freekey",
        timeout=15,
    )
    if not j or not isinstance(j, dict) or j.get("error"):
        return None
    eth = j.get("ETH") or {}
    tokens = j.get("tokens") or []
    contract = j.get("contractInfo") is not None or bool(j.get("isContract"))
    return {
        "source":       "ethplorer",
        "balance":      f"{eth.get('balance', 0):.6f} ETH",
        "usd":          (eth.get("price") or {}).get("rate") if isinstance(eth.get("price"), dict) else None,
        "token_count":  len(tokens),
        "top_tokens":   [
            {"name": (t.get("tokenInfo") or {}).get("name"),
             "symbol": (t.get("tokenInfo") or {}).get("symbol")}
            for t in tokens[:8]
        ],
        "is_contract":  contract,
        "tx_count":     j.get("countTxs"),
    }


# ── Link generators ───────────────────────────────────────────────

def _btc_links(addr: str) -> list[tuple[str, str]]:
    return [
        ("Blockchair",       f"https://blockchair.com/bitcoin/address/{addr}"),
        ("BitcoinWhosWho",   f"https://bitcoinwhoswho.com/address/{addr}"),
        ("WalletExplorer",   f"https://www.walletexplorer.com/address/{addr}"),
        ("OXT",              f"https://oxt.me/address/{addr}"),
        ("Blockchain.com",   f"https://www.blockchain.com/explorer/addresses/btc/{addr}"),
        ("Mempool.space",    f"https://mempool.space/address/{addr}"),
    ]


def _eth_links(addr: str) -> list[tuple[str, str]]:
    return [
        ("Etherscan",        f"https://etherscan.io/address/{addr}"),
        ("Blockchair",       f"https://blockchair.com/ethereum/address/{addr}"),
        ("Ethplorer",        f"https://ethplorer.io/address/{addr}"),
        ("Blockscout",       f"https://eth.blockscout.com/address/{addr}"),
    ]


# ── Orchestrator ──────────────────────────────────────────────────

async def scan(target: str, *, timeout: float = 20.0) -> ScanResult:
    addr = (target or "").strip()
    result = ScanResult(target=addr, module="crypto")

    kind = detect_kind(addr)
    if not kind:
        result.errors.append(f"Not a recognised BTC / ETH address: {target}")
        return result

    result.add("input", "Chain", "Bitcoin" if kind == "btc" else "Ethereum", "info")

    async with session(timeout=timeout) as client:
        if kind == "btc":
            primary, backup = await asyncio.gather(
                _btc_blockchain_info(client, addr),
                _btc_mempool(client, addr),
                return_exceptions=True,
            )
            data = primary if isinstance(primary, dict) else (
                backup if isinstance(backup, dict) else None)
        else:  # eth
            data = await _eth_ethplorer(client, addr)
            if isinstance(data, Exception):
                data = None

    if data:
        result.raw["chain"] = data
        result.add(data["source"], "Balance", data.get("balance", "?"), "found")
        if data.get("total_received"):
            result.add(data["source"], "Total received", data["total_received"], "info")
        if data.get("total_sent"):
            result.add(data["source"], "Total sent", data["total_sent"], "info")
        if data.get("tx_count") is not None:
            result.add(data["source"], "Transactions", str(data["tx_count"]),
                       "warn" if data["tx_count"] else "info")
        if kind == "eth":
            if data.get("is_contract"):
                result.add("ethplorer", "Type", "Smart contract", "warn")
            if data.get("token_count"):
                result.add("ethplorer", "ERC-20 tokens", str(data["token_count"]), "info")
            for tok in data.get("top_tokens", []):
                if tok.get("symbol"):
                    result.add("ethplorer", "Token",
                               f"{tok.get('name', '?')} ({tok['symbol']})", "info")
    else:
        result.add("chain", "On-chain data", "No activity found or lookup failed", "info")

    # Manual-lookup links
    links = _btc_links(addr) if kind == "btc" else _eth_links(addr)
    for label, url in links:
        result.add("explorer", label, url, "info", url=url)

    return result
