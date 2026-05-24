"""
DNS and email authentication scanner.

Performs passive DNS lookups only — no zone transfers, no brute forcing,
no subdomain enumeration. Uses the public resolver to read records the
domain owner has intentionally published.

Checks:
  - A / AAAA  : resolves to at least one IP
  - MX        : mail servers present
  - NS        : authoritative nameservers
  - TXT       : raw records for manual review
  - SPF       : email sender policy (v=spf1 in TXT)
  - DMARC     : _dmarc.<domain> TXT policy
  - CAA       : certificate authority restrictions
  - DNSSEC    : DS record presence at the domain
"""

import asyncio
import dns.resolver
import dns.exception
import dns.rdatatype
from models.scan import DNSRecord, DNSFinding, DNSScanResult, utc_now_iso

_RESOLVER = dns.resolver.Resolver()
_RESOLVER.timeout = 5
_RESOLVER.lifetime = 10


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _query(name: str, rdtype: str) -> list[str]:
    """Return string representations of all rdata for (name, rdtype), or []."""
    try:
        answers = _RESOLVER.resolve(name, rdtype)
        return [r.to_text().strip('"') for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.DNSException:
        return []


def _txt_records(name: str) -> list[str]:
    """Return all TXT record strings joined if multi-part."""
    try:
        answers = _RESOLVER.resolve(name, "TXT")
        results = []
        for rdata in answers:
            # Each TXT rdata may be split across multiple strings — join them
            joined = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
            results.append(joined)
        return results
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.DNSException:
        return []


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _check_a(domain: str) -> tuple[DNSRecord | None, DNSFinding]:
    values = _query(domain, "A") + _query(domain, "AAAA")
    if values:
        return (
            DNSRecord(record_type="A/AAAA", values=values),
            DNSFinding(
                check="A/AAAA resolution",
                status="pass",
                severity=None,
                description=f"Domain resolves to {len(values)} address(es): {', '.join(values[:5])}",
                remediation=None,
            ),
        )
    return (
        None,
        DNSFinding(
            check="A/AAAA resolution",
            status="fail",
            severity="high",
            description="Domain does not resolve to any IP address.",
            remediation="Add an A or AAAA record in your DNS zone pointing to your server.",
        ),
    )


def _check_mx(domain: str) -> tuple[DNSRecord | None, DNSFinding]:
    values = _query(domain, "MX")
    if values:
        return (
            DNSRecord(record_type="MX", values=values),
            DNSFinding(
                check="MX records",
                status="info",
                severity=None,
                description=f"Mail servers found: {', '.join(values)}",
                remediation=None,
            ),
        )
    return (
        None,
        DNSFinding(
            check="MX records",
            status="info",
            severity=None,
            description="No MX records found. If this domain sends or receives email, MX records are required.",
            remediation="Add MX records if the domain handles email.",
        ),
    )


def _check_ns(domain: str) -> tuple[DNSRecord | None, DNSFinding]:
    values = _query(domain, "NS")
    if values:
        return (
            DNSRecord(record_type="NS", values=values),
            DNSFinding(
                check="NS records",
                status="info",
                severity=None,
                description=f"Authoritative nameservers: {', '.join(values)}",
                remediation=None,
            ),
        )
    return (
        None,
        DNSFinding(
            check="NS records",
            status="warn",
            severity="low",
            description="Could not retrieve NS records for this domain.",
            remediation=None,
        ),
    )


def _check_txt(domain: str) -> DNSRecord | None:
    values = _txt_records(domain)
    if values:
        return DNSRecord(record_type="TXT", values=values)
    return None


def _check_spf(domain: str) -> DNSFinding:
    txt_records = _txt_records(domain)
    spf_records = [r for r in txt_records if r.startswith("v=spf1")]

    if not spf_records:
        return DNSFinding(
            check="SPF",
            status="fail",
            severity="high",
            description=(
                "No SPF record found. Without SPF, anyone can send email claiming to "
                "be from this domain, enabling phishing and spam attacks that impersonate "
                "your organisation."
            ),
            remediation=(
                "Add a TXT record: v=spf1 include:<your-mail-provider> -all\n"
                "Replace <your-mail-provider> with your actual email service "
                "(e.g. include:_spf.google.com for Google Workspace). "
                "End with -all to reject unauthorised senders."
            ),
        )

    if len(spf_records) > 1:
        return DNSFinding(
            check="SPF",
            status="fail",
            severity="medium",
            description=(
                f"Multiple SPF records found ({len(spf_records)}). "
                "RFC 7208 requires exactly one SPF record. Having more than one "
                "causes unpredictable evaluation and many receivers will reject or "
                "ignore your email."
            ),
            remediation=(
                "Merge all SPF mechanisms into a single TXT record. "
                "Delete the extras and keep only one v=spf1 ... record."
            ),
        )

    spf = spf_records[0]

    if "+all" in spf:
        return DNSFinding(
            check="SPF",
            status="fail",
            severity="high",
            description=(
                f"SPF record uses '+all' which passes all senders: {spf!r}. "
                "This is effectively no protection at all — anyone can spoof your domain."
            ),
            remediation="Change '+all' to '-all' to reject mail from unlisted senders.",
        )

    if "?all" in spf:
        return DNSFinding(
            check="SPF",
            status="warn",
            severity="medium",
            description=(
                f"SPF record uses '?all' (neutral) which provides no rejection: {spf!r}. "
                "Spoofed mail from your domain will not be rejected."
            ),
            remediation="Change '?all' to '-all' to enforce rejection of unauthorised senders.",
        )

    if "~all" in spf:
        return DNSFinding(
            check="SPF",
            status="warn",
            severity="low",
            description=(
                f"SPF uses '~all' (softfail): {spf!r}. "
                "Unauthorised senders are flagged but not always rejected. "
                "This is a transitional setting and should be hardened."
            ),
            remediation="Change '~all' to '-all' once you are confident your legitimate mail sources are listed.",
        )

    return DNSFinding(
        check="SPF",
        status="pass",
        severity=None,
        description=f"SPF record is present and uses a strict policy: {spf!r}",
        remediation=None,
    )


def _check_dmarc(domain: str) -> tuple[DNSRecord | None, DNSFinding]:
    dmarc_name = f"_dmarc.{domain}"
    values = _txt_records(dmarc_name)
    dmarc_records = [r for r in values if r.startswith("v=DMARC1")]

    if not dmarc_records:
        return (
            None,
            DNSFinding(
                check="DMARC",
                status="fail",
                severity="high",
                description=(
                    "No DMARC record found at _dmarc." + domain + ". "
                    "Without DMARC, even a correctly configured SPF or DKIM policy "
                    "provides no instruction to receiving mail servers on what to do "
                    "with failing messages, leaving your domain open to impersonation."
                ),
                remediation=(
                    "Add a TXT record at _dmarc." + domain + ":\n"
                    "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@" + domain + "\n"
                    "Start with p=none to monitor, then move to p=quarantine, "
                    "then p=reject once you are confident no legitimate mail is failing."
                ),
            ),
        )

    dmarc = dmarc_records[0]
    record = DNSRecord(record_type="DMARC", values=[dmarc])

    # Parse policy
    policy = "none"
    for part in dmarc.split(";"):
        part = part.strip()
        if part.startswith("p="):
            policy = part[2:].strip().lower()
            break

    if policy == "none":
        return (
            record,
            DNSFinding(
                check="DMARC",
                status="warn",
                severity="medium",
                description=(
                    f"DMARC record is present but policy is 'none': {dmarc!r}. "
                    "p=none only monitors — failing messages are not quarantined or rejected. "
                    "Your domain can still be spoofed without consequence."
                ),
                remediation=(
                    "Review your DMARC aggregate reports (rua=), then change p=none to "
                    "p=quarantine, and later p=reject once all legitimate mail is passing."
                ),
            ),
        )

    if policy == "quarantine":
        return (
            record,
            DNSFinding(
                check="DMARC",
                status="warn",
                severity="low",
                description=(
                    f"DMARC policy is 'quarantine': {dmarc!r}. "
                    "Failing messages go to spam rather than being rejected outright."
                ),
                remediation=(
                    "Consider upgrading to p=reject once you have confirmed no legitimate "
                    "mail is failing DMARC checks."
                ),
            ),
        )

    return (
        record,
        DNSFinding(
            check="DMARC",
            status="pass",
            severity=None,
            description=f"DMARC record is present with a strict policy (p={policy}): {dmarc!r}",
            remediation=None,
        ),
    )


def _check_caa(domain: str) -> tuple[DNSRecord | None, DNSFinding]:
    values = _query(domain, "CAA")
    if values:
        return (
            DNSRecord(record_type="CAA", values=values),
            DNSFinding(
                check="CAA",
                status="pass",
                severity=None,
                description=f"CAA records restrict certificate issuance to: {', '.join(values)}",
                remediation=None,
            ),
        )
    return (
        None,
        DNSFinding(
            check="CAA",
            status="warn",
            severity="low",
            description=(
                "No CAA records found. Without CAA, any certificate authority can issue "
                "TLS certificates for this domain. A compromised or rogue CA could issue "
                "fraudulent certificates."
            ),
            remediation=(
                "Add CAA records listing only the CA(s) you use, e.g.:\n"
                '0 issue "letsencrypt.org"\n'
                '0 issuewild "letsencrypt.org"\n'
                '0 iodef "mailto:security@' + domain + '"'
            ),
        ),
    )


def _check_dnssec(domain: str) -> DNSFinding:
    """Check for a DS record — presence implies DNSSEC is delegated."""
    ds_values = _query(domain, "DS")
    if ds_values:
        return DNSFinding(
            check="DNSSEC",
            status="pass",
            severity=None,
            description="DNSSEC DS record found — DNS responses for this domain are signed.",
            remediation=None,
        )
    # Also try DNSKEY directly (works when the resolver is authoritative or has the key)
    dnskey_values = _query(domain, "DNSKEY")
    if dnskey_values:
        return DNSFinding(
            check="DNSSEC",
            status="pass",
            severity=None,
            description="DNSSEC DNSKEY record found — DNS responses are cryptographically signed.",
            remediation=None,
        )
    return DNSFinding(
        check="DNSSEC",
        status="warn",
        severity="low",
        description=(
            "No DNSSEC DS or DNSKEY records found. Without DNSSEC, DNS responses can "
            "be forged by an attacker on the network, redirecting your visitors to "
            "malicious servers."
        ),
        remediation=(
            "Enable DNSSEC through your domain registrar or DNS hosting provider. "
            "Most managed DNS services offer one-click DNSSEC enablement."
        ),
    )


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

_SEVERITY_PENALTY = {"high": 25, "medium": 12, "low": 5}


def _score(findings: list[DNSFinding]) -> tuple[int, str]:
    total = 0
    for f in findings:
        if f.status in ("fail", "warn") and f.severity:
            total += _SEVERITY_PENALTY[f.severity]
    total = min(total, 100)
    if total < 25:
        return total, "low"
    if total < 50:
        return total, "medium"
    if total < 75:
        return total, "high"
    return total, "critical"


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def scan_dns(domain: str) -> DNSScanResult:
    """
    Run all DNS checks for a domain. Executes blocking dnspython calls in a
    thread pool so they don't block the FastAPI event loop.
    """
    loop = asyncio.get_event_loop()

    def _run_all() -> tuple:
        a_record, a_finding = _check_a(domain)
        mx_record, mx_finding = _check_mx(domain)
        ns_record, ns_finding = _check_ns(domain)
        txt_record = _check_txt(domain)
        spf_finding = _check_spf(domain)
        dmarc_record, dmarc_finding = _check_dmarc(domain)
        caa_record, caa_finding = _check_caa(domain)
        dnssec_finding = _check_dnssec(domain)
        return (
            a_record, a_finding,
            mx_record, mx_finding,
            ns_record, ns_finding,
            txt_record,
            spf_finding,
            dmarc_record, dmarc_finding,
            caa_record, caa_finding,
            dnssec_finding,
        )

    (
        a_record, a_finding,
        mx_record, mx_finding,
        ns_record, ns_finding,
        txt_record,
        spf_finding,
        dmarc_record, dmarc_finding,
        caa_record, caa_finding,
        dnssec_finding,
    ) = await loop.run_in_executor(None, _run_all)

    records = [r for r in [a_record, mx_record, ns_record, txt_record, dmarc_record, caa_record] if r]
    findings = [a_finding, mx_finding, ns_finding, spf_finding, dmarc_finding, caa_finding, dnssec_finding]

    risk_score, risk_level = _score(findings)

    fail_count = sum(1 for f in findings if f.status == "fail")
    warn_count = sum(1 for f in findings if f.status == "warn")
    pass_count = sum(1 for f in findings if f.status == "pass")

    return DNSScanResult(
        domain=domain,
        scan_timestamp=utc_now_iso(),
        records=records,
        findings=findings,
        risk_score=risk_score,
        risk_level=risk_level,
        summary={
            "checks_run": len(findings),
            "fail": fail_count,
            "warn": warn_count,
            "pass": pass_count,
        },
    )
