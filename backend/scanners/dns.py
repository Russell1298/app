"""
DNS and email authentication scanner.

Performs passive DNS lookups only. DNSSEC is reported as informational only
(not penalised) per v2 spec — too many legitimate large sites skip it.
"""

import asyncio
import dns.resolver
import dns.exception
import dns.rdatatype
from models.scan import DNSRecord, DNSFinding, DNSScanResult, utc_now_iso
from scoring_config import PENALTY, scanner_score, risk_level

_RESOLVER = dns.resolver.Resolver()
_RESOLVER.timeout = 5
_RESOLVER.lifetime = 10


def _query(name: str, rdtype: str) -> list[str]:
    try:
        answers = _RESOLVER.resolve(name, rdtype)
        return [r.to_text().strip('"') for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.DNSException:
        return []


def _txt_records(name: str) -> list[str]:
    try:
        answers = _RESOLVER.resolve(name, "TXT")
        results = []
        for rdata in answers:
            joined = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
            results.append(joined)
        return results
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.DNSException:
        return []


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
                "be from this domain, enabling phishing and spam attacks."
            ),
            remediation=(
                "Add a TXT record: v=spf1 include:<your-mail-provider> -all\n"
                "Replace <your-mail-provider> with your actual email service "
                "(e.g. include:_spf.google.com for Google Workspace)."
            ),
        )

    if len(spf_records) > 1:
        return DNSFinding(
            check="SPF",
            status="fail",
            severity="medium",
            description=(
                f"Multiple SPF records found ({len(spf_records)}). "
                "RFC 7208 requires exactly one SPF record."
            ),
            remediation="Merge all SPF mechanisms into a single TXT record.",
        )

    spf = spf_records[0]

    if "+all" in spf:
        return DNSFinding(
            check="SPF",
            status="fail",
            severity="high",
            description=(
                f"SPF record uses '+all' which passes all senders: {spf!r}. "
                "This is effectively no protection — anyone can spoof your domain."
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
                "Unauthorised senders are flagged but not always rejected."
            ),
            remediation="Change '~all' to '-all' once legitimate mail sources are all listed.",
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
                    f"No DMARC record found at _dmarc.{domain}. "
                    "Without DMARC, mail receivers have no instruction on what to do "
                    "with failing messages, leaving your domain open to impersonation."
                ),
                remediation=(
                    f"Add a TXT record at _dmarc.{domain}:\n"
                    f"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{domain}\n"
                    "Start with p=none to monitor, then move to p=quarantine, then p=reject."
                ),
            ),
        )

    dmarc = dmarc_records[0]
    record = DNSRecord(record_type="DMARC", values=[dmarc])

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
                    "p=none only monitors — failing messages are not quarantined or rejected."
                ),
                remediation=(
                    "Review DMARC aggregate reports, then change p=none to p=quarantine, "
                    "and later p=reject."
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
                    "Failing messages go to spam rather than being rejected."
                ),
                remediation="Consider upgrading to p=reject once you confirm no legitimate mail is failing.",
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
                "TLS certificates for this domain."
            ),
            remediation=(
                "Add CAA records listing only the CA(s) you use, e.g.:\n"
                '0 issue \"letsencrypt.org\"\n'
                f'0 iodef \"mailto:security@{domain}\"'
            ),
        ),
    )


def _check_dnssec(domain: str) -> DNSFinding:
    """DNSSEC is informational only in v2 — not penalised."""
    ds_values = _query(domain, "DS")
    if ds_values:
        return DNSFinding(
            check="DNSSEC",
            status="pass",
            severity=None,
            description="DNSSEC DS record found — DNS responses for this domain are signed.",
            remediation=None,
        )
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
        status="info",
        severity=None,
        description=(
            "DNSSEC is not configured. DNS responses are not cryptographically signed. "
            "Many large legitimate sites skip this — reported for information only."
        ),
        remediation="Consider enabling DNSSEC through your domain registrar or DNS provider.",
    )


def _score(findings: list[DNSFinding]) -> tuple[int, str]:
    total = 0
    for f in findings:
        if f.status in ("fail", "warn") and f.severity:
            total += PENALTY[f.severity]
    risk_score = scanner_score(total, "dns")
    return risk_score, risk_level(risk_score)


async def scan_dns(domain: str) -> DNSScanResult:
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

    risk_score, level = _score(findings)

    fail_count = sum(1 for f in findings if f.status == "fail")
    warn_count = sum(1 for f in findings if f.status == "warn")
    pass_count = sum(1 for f in findings if f.status == "pass")

    return DNSScanResult(
        domain=domain,
        scan_timestamp=utc_now_iso(),
        records=records,
        findings=findings,
        risk_score=risk_score,
        risk_level=level,
        critical_triggers=[],
        summary={
            "checks_run": len(findings),
            "fail": fail_count,
            "warn": warn_count,
            "pass": pass_count,
        },
    )
