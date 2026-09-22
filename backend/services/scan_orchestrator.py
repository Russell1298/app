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
from scanners.waf import Access, probe_access
from reports.generator import build_full_report
from netguard import assert_public_host_async
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


async def _safe_checkout(domain: str, access: Access) -> CheckoutScriptScanResult:
    try:
        return await scan_checkout_scripts(domain, access)
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
    # SSRF guard: refuse targets that resolve to private/internal/metadata IPs
    # before any scanner makes an outbound request to them.
    await assert_public_host_async(domain)

    async def _page_scanners():
        # One homepage probe decides whether the site's real pages are reachable.
        # Every page-reading scanner uses it, so none of them grades a WAF page.
        access = await probe_access(domain)
        return await asyncio.gather(
            scan_headers(domain, access),
            scan_exposure(domain, access),
            scan_secrets(domain, access),
            _safe_checkout(domain, access),
        )

    (
        (headers_result, exposure_result, secrets_result, checkout_result),
        dns_result,
        ssl_result,
        fingerprint_result,
        subdomain_result,
        dns_hijack_result,
    ) = await asyncio.gather(
        _page_scanners(),
        scan_dns(domain),
        scan_ssl(domain),
        scan_fingerprint(domain),
        scan_subdomains(domain),
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
