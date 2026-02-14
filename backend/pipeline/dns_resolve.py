from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Iterable

import dns.resolver


@dataclass(frozen=True)
class ResolveResult:
    name: str
    ips: list[str]
    error: str | None = None


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = 2.0
    r.lifetime = 3.0
    return r


def _resolve_sync(name: str) -> ResolveResult:
    r = _resolver()
    ips: list[str] = []
    try:
        for rdtype in ("A", "AAAA"):
            try:
                answers = r.resolve(name, rdtype, raise_on_no_answer=False)
                if answers:
                    for a in answers:
                        ips.append(str(a).strip())
            except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                return ResolveResult(name=name, ips=[], error="NXDOMAIN")
            except dns.resolver.NoAnswer:
                continue
            except dns.exception.Timeout:
                return ResolveResult(name=name, ips=[], error="TIMEOUT")
    except Exception as e:
        return ResolveResult(name=name, ips=[], error=str(e))

    # De-dupe while preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for ip in ips:
        if ip and ip not in seen:
            seen.add(ip)
            out.append(ip)

    return ResolveResult(name=name, ips=out, error=None if out else "NO_ANSWER")


async def resolve_many(names: Iterable[str], *, concurrency: int = 50) -> list[ResolveResult]:
    sem = asyncio.Semaphore(concurrency)

    async def one(n: str) -> ResolveResult:
        async with sem:
            return await asyncio.to_thread(_resolve_sync, n)

    tasks = [one(n) for n in names if n]
    if not tasks:
        return []
    return await asyncio.gather(*tasks)

