"""Shared async HTTP client with retry, timeout, and error handling.

All sources go through this. Never instantiate httpx.AsyncClient directly
in a source — use the shared HTTP context manager so behaviour stays
consistent (UA rotation, timeout, retry on transient errors).
"""

from __future__ import annotations

import asyncio
import logging
import random
from contextlib import asynccontextmanager
from typing import Any

import httpx

log = logging.getLogger("osint.http")

# Realistic UA rotation — some sources reject `python-httpx/...`
_USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
]

DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7",
    "Accept-Language": "en-US,en;q=0.9,fr;q=0.8",
    "Accept-Encoding": "gzip, deflate",
    "DNT": "1",
}


def _ua() -> str:
    return random.choice(_USER_AGENTS)


@asynccontextmanager
async def session(timeout: float = 15.0, follow_redirects: bool = True):
    """Yield a shared httpx.AsyncClient with sane defaults."""
    headers = {"User-Agent": _ua(), **DEFAULT_HEADERS}
    limits = httpx.Limits(max_keepalive_connections=20, max_connections=50)
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=follow_redirects,
        headers=headers,
        limits=limits,
    ) as client:
        yield client


async def get_json(client: httpx.AsyncClient, url: str, *, retries: int = 1,
                   **kwargs) -> Any | None:
    """GET → JSON. Returns None on any failure (status != 200, parse error, network)."""
    for attempt in range(retries + 1):
        try:
            r = await client.get(url, **kwargs)
            if r.status_code == 429:  # rate limited
                await asyncio.sleep(1.5)
                continue
            if r.status_code != 200:
                return None
            try:
                return r.json()
            except Exception:
                return None
        except (httpx.TimeoutException, httpx.ConnectError):
            if attempt < retries:
                await asyncio.sleep(0.5)
                continue
            return None
        except Exception as e:
            log.debug("GET %s failed: %s", url, e)
            return None
    return None


async def get_text(client: httpx.AsyncClient, url: str, *,
                   accept_statuses: tuple[int, ...] = (200,),
                   retries: int = 1, **kwargs) -> tuple[int | None, str | None]:
    """GET → (status, text). Returns (status, None) if status not in accept_statuses."""
    for attempt in range(retries + 1):
        try:
            r = await client.get(url, **kwargs)
            if r.status_code == 429:
                await asyncio.sleep(1.5)
                continue
            if r.status_code not in accept_statuses:
                return r.status_code, None
            return r.status_code, r.text
        except (httpx.TimeoutException, httpx.ConnectError):
            if attempt < retries:
                await asyncio.sleep(0.5)
                continue
            return None, None
        except Exception as e:
            log.debug("GET %s failed: %s", url, e)
            return None, None
    return None, None


async def head_status(client: httpx.AsyncClient, url: str, **kwargs) -> int | None:
    """HEAD → status code, or None on failure."""
    try:
        r = await client.head(url, **kwargs)
        return r.status_code
    except Exception:
        return None


async def get_status(client: httpx.AsyncClient, url: str, **kwargs) -> tuple[int | None, str | None]:
    """GET → (status, body). Body always returned (for false-positive detection)."""
    try:
        r = await client.get(url, **kwargs)
        return r.status_code, r.text
    except Exception:
        return None, None
