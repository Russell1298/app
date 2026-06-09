"""
Scan orchestrator.

Runs all scanners concurrently via asyncio.gather.  The two newest scanners
(checkout_scripts, dns_hijack) are treated as optional extras: if either
throws for any reason, the core scan still completes and the failed scanner
returns an empty/safe result instead of taking down the whole scan.
"""

import asyncio
import logging
from scanners.headers import scan_headers
from scanners.dns import scan_dns
from scanners.sslscan import scan_ssl
from scanners.exposure import scan_exposure
from scanners.fingerprint import scan_fingerprint
from scanners.subdomain import scan_subdomains
from scanners.secrets import scan_secrets
from scanners.checkout_scripts import scan_checkout_scripts
from scanners.dns_hijack import scan_dns_hijack
from reports.generator import build_full_report
from models.scan import (
    FullScanResult,
    CheckoutScriptScanResult,
    DNSHijackScanResult,
    utc_now_iso,
)

log = logging.getLogger(__name__)


def _checkout_fallback(domain: str) -> CheckoutScriptScanResult:
    return CheckoutScriptScanResult(
        domain=domain,
        scan_timestamp=utc_now_iso(),
        pages_scanned=[],
        scripts=[],
        findings=[],
        risk_score=0,
        risk_level="low",
        summary={"pages_scanned": 0, "skipped": True},
    )


def _dns_hijack_fallback(domain: str) -> DNSHijackScanResult:
    return DNSHijackScanResult(
        domain=domain,
        scan_timestamp=utc_now_iso(),
        resolver_results={},
        findings=[],
        risk_score=0,
        risk_level="low",
        summary={"checks_run": 0, "skipped": True},
    )


async def _safe_checkout(domain: str) -> CheckoutScriptScanResult:
    try:
        return await scan_checkout_scripts(domain)
    except Exception as exc:
        log.warning("checkout_scripts failed for %s: %s", domain, exc)
        return _checkout_fallback(domain)


async def _safe_dns_hijack(domain: str) -> DNSHijackScanResult:
    try:
        return await scan_dns_hijack(domain)
    except Exception as exc:
        log.warning("dns_hijack failed for %s: %s", domain, exc)
        return _dns_hijack_fallback(domain)


async def run_full_scan(domain: str) -> FullScanResult:
    (
        headers_result,
        dns_result,
        ssl_result,
        exposure_result,
        fingerprint_result,
        subdomain_result,
        secrets_result,
        checkout_result,
        dns_hijack_result,
    ) = await asyncio.gather(
        scan_headers(domain),
        scan_dns(domain),
        scan_ssl(domain),
        scan_exposure(domain),
        scan_fingerprint(domain),
        scan_subdomains(domain),
        scan_secrets(domain),
        _safe_checkout(domain),
        _safe_dns_hijack(domain),
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
        checkout_scripts=checkout_result,
        dns_hijack=dns_hijack_result,
    )
