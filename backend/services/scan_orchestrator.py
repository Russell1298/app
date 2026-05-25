"""
Scan orchestrator.

Runs all scanners concurrently and collects their results.
Each scanner is fully independent so asyncio.gather gives a real
speed-up — a full scan takes roughly as long as the slowest scanner
rather than the sum of all seven.
"""

import asyncio
from scanners.headers import scan_headers
from scanners.dns import scan_dns
from scanners.sslscan import scan_ssl
from scanners.exposure import scan_exposure
from scanners.fingerprint import scan_fingerprint
from scanners.subdomain import scan_subdomains
from scanners.secrets import scan_secrets
from reports.generator import build_full_report
from models.scan import FullScanResult


async def run_full_scan(domain: str) -> FullScanResult:
    (
        headers_result,
        dns_result,
        ssl_result,
        exposure_result,
        fingerprint_result,
        subdomain_result,
        secrets_result,
    ) = await asyncio.gather(
        scan_headers(domain),
        scan_dns(domain),
        scan_ssl(domain),
        scan_exposure(domain),
        scan_fingerprint(domain),
        scan_subdomains(domain),
        scan_secrets(domain),
        return_exceptions=False,
    )

    return build_full_report(
        domain=domain,
        headers=headers_result,
        dns=dns_result,
        ssl=ssl_result,
        exposure=exposure_result,
        fingerprint=fingerprint_result,
        subdomains=subdomain_result,
        secrets=secrets_result,
    )
