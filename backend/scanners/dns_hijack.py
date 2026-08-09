"""
DNS hijacking detection scanner.

Checks for indicators that a domain's DNS has been silently tampered with:
- Cross-resolver inconsistency (A records differ across Google, Cloudflare, Quad9)
- Fast-flux DNS (very low TTL paired with many IPs)
- MX records pointing to bare IP addresses (never legitimate)
- DNSSEC absence (attackers disable it before hijacking)

All queries are purely passive — read-only DNS lookups only.
"""

import asyncio
import ipaddress
import concurrent.futures
import dns.resolver
import dns.exception
from models.scan import DNSHijackFinding, DNSHijackScanResult, utc_now_iso
from scoring_config import PENALTY, scanner_score, risk_level

_RESOLVERS: dict[str, str] = {
    "Google (8.8.8.8)":      "8.8.8.8",
    "Cloudflare (1.1.1.1)":  "1.1.1.1",
    "Quad9 (9.9.9.9)":       "9.9.9.9",
}

_FAST_FLUX_TTL_THRESHOLD = 300   # seconds; TTL below this triggers inspection
_FAST_FLUX_IP_MIN = 3            # at least this many IPs alongside low TTL = fast-flux


def _make_resolver(server_ip: str) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.nameservers = [server_ip]
    r.timeout = 5
    r.lifetime = 8
    return r


def _query_a_with_ttl(
    domain: str, resolver: dns.resolver.Resolver
) -> tuple[list[str], int | None]:
    try:
        answers = resolver.resolve(domain, "A")
        ips = [r.to_text() for r in answers]
        min_ttl = min(r.ttl for r in answers) if answers else None
        return ips, min_ttl
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return [], None
    except dns.exception.DNSException:
        return [], None


def _query_mx_hosts(domain: str, resolver: dns.resolver.Resolver) -> list[str]:
    try:
        answers = resolver.resolve(domain, "MX")
        return [r.exchange.to_text().rstrip(".") for r in answers]
    except Exception:
        return []


def _is_bare_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.rstrip("."))
        return True
    except ValueError:
        return False


def _check_resolver_consistency(domain: str) -> tuple[dict[str, list[str]], DNSHijackFinding]:
    resolver_results: dict[str, list[str]] = {}

    def _query_one(item: tuple[str, str]) -> tuple[str, list[str]]:
        name, ip = item
        ips, _ = _query_a_with_ttl(domain, _make_resolver(ip))
        return name, sorted(ips)

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = {pool.submit(_query_one, item): item[0] for item in _RESOLVERS.items()}
        for future in concurrent.futures.as_completed(futures, timeout=14):
            try:
                name, ips = future.result()
                if ips:
                    resolver_results[name] = ips
            except Exception:
                pass

    if len(resolver_results) < 2:
        return resolver_results, DNSHijackFinding(
            check="Cross-resolver consistency",
            status="info",
            severity=None,
            description="Fewer than two resolvers returned results, so there is nothing to compare.",
            remediation=None,
            penalty=0,
        )

    unique_sets = {frozenset(ips) for ips in resolver_results.values()}
    if len(unique_sets) == 1:
        sample = next(iter(resolver_results.values()))
        return resolver_results, DNSHijackFinding(
            check="Cross-resolver consistency",
            status="pass",
            severity=None,
            description=(
                f"All {len(resolver_results)} resolvers agree on: {', '.join(sample)}"
            ),
            remediation=None,
            penalty=0,
        )

    details = "; ".join(
        f"{name}: {', '.join(ips)}" for name, ips in resolver_results.items()
    )
    return resolver_results, DNSHijackFinding(
        check="Cross-resolver consistency",
        status="fail",
        severity="high",
        description=(
            f"DNS resolvers disagree on the IP address for {domain}. "
            "This can indicate DNS cache poisoning, BGP hijacking, or a compromised "
            f"DNS provider. Observed: {details}"
        ),
        remediation=(
            "Compare your DNS registrar's published records against what each resolver "
            "returns. If you made no recent DNS changes, contact your registrar and DNS "
            "provider immediately to investigate unauthorised modifications. Enable DNSSEC "
            "DNSSEC signs your records so any tampering becomes detectable."
        ),
        penalty=PENALTY["high"],
    )


def _check_fast_flux(domain: str) -> DNSHijackFinding:
    ips, ttl = _query_a_with_ttl(domain, _make_resolver("8.8.8.8"))

    if not ips or ttl is None:
        return DNSHijackFinding(
            check="Fast-flux DNS",
            status="info",
            severity=None,
            description="Could not retrieve A records to check for fast-flux indicators.",
            remediation=None,
            penalty=0,
        )

    if ttl < _FAST_FLUX_TTL_THRESHOLD and len(ips) >= _FAST_FLUX_IP_MIN:
        return DNSHijackFinding(
            check="Fast-flux DNS",
            status="fail",
            severity="high",
            description=(
                f"Fast-flux indicators: {len(ips)} A records with TTL={ttl}s "
                f"(threshold: {_FAST_FLUX_TTL_THRESHOLD}s). "
                "Production sites rarely need TTLs under 5 minutes. Fast-flux is a technique "
                "attackers use to rapidly rotate IPs, making the domain harder to take down "
                "and obscuring malicious infrastructure."
            ),
            remediation=(
                "If you didn't configure this, your DNS may have been hijacked. Log in to "
                "your DNS provider and verify all A records. Increase TTL to at least 300s; "
                "3600s is typical for production. If records were changed without your "
                "authorisation, treat this as a security incident and rotate DNS provider credentials."
            ),
            penalty=PENALTY["high"],
        )

    if ttl < _FAST_FLUX_TTL_THRESHOLD:
        return DNSHijackFinding(
            check="Fast-flux DNS",
            status="warn",
            severity="low",
            description=(
                f"A record TTL is unusually low: {ttl}s (threshold: {_FAST_FLUX_TTL_THRESHOLD}s). "
                "Very short TTLs are sometimes used during DNS migrations, but are also "
                "characteristic of malicious fast-flux infrastructure."
            ),
            remediation=(
                "If not mid-migration, raise your A record TTL to at least 300s. "
                "A typical production TTL is 3600s (1 hour)."
            ),
            penalty=PENALTY["low"],
        )

    return DNSHijackFinding(
        check="Fast-flux DNS",
        status="pass",
        severity=None,
        description=f"A record TTL={ttl}s with {len(ips)} IP(s). No fast-flux indicators.",
        remediation=None,
        penalty=0,
    )


def _check_mx_anomaly(domain: str) -> DNSHijackFinding:
    mx_hosts = _query_mx_hosts(domain, _make_resolver("8.8.8.8"))

    if not mx_hosts:
        return DNSHijackFinding(
            check="MX record anomaly",
            status="info",
            severity=None,
            description="No MX records found.",
            remediation=None,
            penalty=0,
        )

    ip_mx = [v for v in mx_hosts if _is_bare_ip(v)]
    if ip_mx:
        return DNSHijackFinding(
            check="MX record anomaly",
            status="fail",
            severity="high",
            description=(
                f"MX record(s) point to bare IP address(es): {', '.join(ip_mx)}. "
                "Legitimate mail servers are always identified by hostname, never a bare IP. "
                "This is a strong indicator that DNS records have been tampered with to "
                "intercept or reroute your email."
            ),
            remediation=(
                "Log in to your DNS provider and verify who changed your MX records. "
                "Real mail services (Google Workspace, Microsoft 365, Proofpoint, etc.) "
                "always use hostnames. If you didn't make this change, your DNS account "
                "may be compromised. Change your provider password immediately and "
                "review recent access logs."
            ),
            penalty=PENALTY["high"],
        )

    return DNSHijackFinding(
        check="MX record anomaly",
        status="pass",
        severity=None,
        description=f"MX records use valid hostnames: {', '.join(mx_hosts[:3])}",
        remediation=None,
        penalty=0,
    )


def _check_dnssec(domain: str) -> DNSHijackFinding:
    resolver = _make_resolver("8.8.8.8")
    for rdtype in ("DS", "DNSKEY"):
        try:
            answers = resolver.resolve(domain, rdtype)
            if answers:
                return DNSHijackFinding(
                    check="DNSSEC",
                    status="pass",
                    severity=None,
                    description=f"DNSSEC {rdtype} record found. DNS responses are cryptographically signed.",
                    remediation=None,
                    penalty=0,
                )
        except Exception:
            continue

    return DNSHijackFinding(
        check="DNSSEC",
        status="warn",
        severity="medium",
        description=(
            "DNSSEC is not enabled. Without it, DNS responses cannot be verified as authentic. "
            "Attackers who compromise a resolver or registrar account can silently redirect "
            "visitors to a malicious site. Attackers typically disable DNSSEC before "
            "executing a DNS hijack to avoid detection."
        ),
        remediation=(
            "Enable DNSSEC through your domain registrar or DNS provider. Cloudflare, "
            "Google Domains, and most major registrars offer a one-click toggle. Once enabled, "
            "a DS record is published at your registrar so resolvers can verify your zone."
        ),
        penalty=PENALTY["medium"],
    )


_TIMEOUT_FINDING = DNSHijackFinding(
    check="unavailable",
    status="info",
    severity=None,
    description="This check could not be completed.",
    remediation=None,
    penalty=0,
)


def _run_all_checks(
    domain: str,
) -> tuple[dict[str, list[str]], DNSHijackFinding, DNSHijackFinding, DNSHijackFinding, DNSHijackFinding]:
    """Run the four DNS-hijack checks concurrently.

    Uses wait=False on shutdown so stalled DNS threads never block the caller.
    The asyncio.wait_for in scan_dns_hijack provides the hard outer deadline.
    """
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=4)
    try:
        f_c  = pool.submit(_check_resolver_consistency, domain)
        f_ff = pool.submit(_check_fast_flux, domain)
        f_mx = pool.submit(_check_mx_anomaly, domain)
        f_ds = pool.submit(_check_dnssec, domain)

        # Wait up to 16 s for all four; collect whatever finished.
        done, _ = concurrent.futures.wait([f_c, f_ff, f_mx, f_ds], timeout=16)
    finally:
        # Never block — stalled threads are abandoned, not waited on.
        pool.shutdown(wait=False)

    def _get_or(future, fallback):
        if future not in done:
            return fallback
        try:
            return future.result()
        except Exception:
            return fallback

    resolver_results, consistency_finding = _get_or(
        f_c,
        ({}, DNSHijackFinding(
            check="Cross-resolver consistency", status="info", severity=None,
            description="Resolver comparison timed out.", remediation=None, penalty=0,
        )),
    )
    fast_flux_finding = _get_or(
        f_ff,
        DNSHijackFinding(
            check="Fast-flux DNS", status="info", severity=None,
            description="Fast-flux check timed out.", remediation=None, penalty=0,
        ),
    )
    mx_finding = _get_or(
        f_mx,
        DNSHijackFinding(
            check="MX record anomaly", status="info", severity=None,
            description="MX anomaly check timed out.", remediation=None, penalty=0,
        ),
    )
    dnssec_finding = _get_or(
        f_ds,
        DNSHijackFinding(
            check="DNSSEC", status="info", severity=None,
            description="DNSSEC check timed out.", remediation=None, penalty=0,
        ),
    )
    return resolver_results, consistency_finding, fast_flux_finding, mx_finding, dnssec_finding


async def scan_dns_hijack(domain: str) -> DNSHijackScanResult:
    loop = asyncio.get_event_loop()
    try:
        (
            resolver_results,
            consistency_finding,
            fast_flux_finding,
            mx_finding,
            dnssec_finding,
        ) = await asyncio.wait_for(
            loop.run_in_executor(None, _run_all_checks, domain),
            timeout=20.0,
        )
    except (asyncio.TimeoutError, Exception):
        # Hard deadline hit — return a safe empty result so the scan still saves.
        return DNSHijackScanResult(
            domain=domain,
            scan_timestamp=utc_now_iso(),
            resolver_results={},
            findings=[DNSHijackFinding(
                check="DNS hijack scan",
                status="info",
                severity=None,
                description="DNS hijack checks could not complete in time and were skipped.",
                remediation=None,
                penalty=0,
            )],
            risk_score=0,
            risk_level="low",
            critical_triggers=[],
            summary={"checks_run": 0, "timed_out": True},
        )

    findings = [consistency_finding, fast_flux_finding, mx_finding, dnssec_finding]

    critical_triggers: list[str] = []
    if consistency_finding.status == "fail":
        critical_triggers.append("dns_resolver_inconsistency")
    if mx_finding.status == "fail":
        critical_triggers.append("mx_points_to_ip")

    total_penalty = sum(f.penalty for f in findings)
    score = scanner_score(total_penalty, "dns_hijack")

    return DNSHijackScanResult(
        domain=domain,
        scan_timestamp=utc_now_iso(),
        resolver_results=resolver_results,
        findings=findings,
        risk_score=score,
        risk_level=risk_level(score),
        critical_triggers=critical_triggers,
        summary={
            "checks_run": len(findings),
            "fail": sum(1 for f in findings if f.status == "fail"),
            "warn": sum(1 for f in findings if f.status == "warn"),
            "pass": sum(1 for f in findings if f.status == "pass"),
            "resolvers_queried": len(resolver_results),
        },
    )
