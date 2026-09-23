"""
Subdomain discovery scanner.

Queries the crt.sh certificate transparency log API — a completely
passive lookup of public certificate records. No DNS brute-forcing,
no active probing, no zone transfers.

Results are verified by attempting a DNS resolution to confirm the
subdomain is currently live, not just historically recorded.
"""

import asyncio
import httpx
import dns.resolver
import dns.exception
from models.scan import SubdomainEntry, SubdomainScanResult, utc_now_iso

_CRT_URL  = "https://crt.sh/?q=%.{domain}&output=json"
_TIMEOUT  = 15
_MAX_VERIFY = 50   # cap DNS verifications to keep scan time predictable


def _resolve(subdomain: str) -> tuple[bool, list[str]]:
    try:
        answers = dns.resolver.resolve(subdomain, "A", lifetime=4)
        ips = [r.to_text() for r in answers]
        return True, ips
    except Exception:
        return False, []


async def scan_subdomains(domain: str) -> SubdomainScanResult:
    raw: set[str] = set()

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(_CRT_URL.format(domain=domain))
            if resp.status_code == 200:
                for entry in resp.json():
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(f".{domain}") and name != domain:
                            raw.add(name)
    except Exception:
        pass

    # Deduplicate and sort; cap to avoid runaway DNS checks
    candidates = sorted(raw)[:_MAX_VERIFY]

    loop = asyncio.get_running_loop()
    tasks = [
        loop.run_in_executor(None, _resolve, sub)
        for sub in candidates
    ]
    results = await asyncio.gather(*tasks)

    subdomains: list[SubdomainEntry] = []
    for sub, (resolves, ips) in zip(candidates, results):
        subdomains.append(SubdomainEntry(
            subdomain=sub,
            resolves=resolves,
            ip_addresses=ips,
        ))

    live = sum(1 for s in subdomains if s.resolves)

    return SubdomainScanResult(
        domain=domain,
        scan_timestamp=utc_now_iso(),
        subdomains=subdomains,
        summary={
            "discovered": len(subdomains),
            "live": live,
            "unresolvable": len(subdomains) - live,
            "source": "certificate transparency (crt.sh)",
        },
    )
