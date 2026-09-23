"""
DNS and email authentication scanner.

Performs passive DNS lookups only. DNSSEC is handled by the dns_hijack
scanner, not here, so a single check produces a single finding.
"""

import asyncio
import uuid
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
import dns.exception
import dns.rdatatype
from models.scan import DNSRecord, DNSFinding, DNSScanResult, utc_now_iso
from scoring_config import PENALTY, scanner_score, risk_level

# Cloud service patterns that indicate a potentially dangling CNAME target.
_CLOUD_CNAME_PATTERNS = (
    # AWS. ".s3.amazonaws.com" alone missed load balancers, CloudFront and
    # Beanstalk, which is how three dangling payment hostnames went unreported.
    ".s3.amazonaws.com",
    ".s3-website",
    ".elb.amazonaws.com",
    ".elasticbeanstalk.com",
    ".cloudfront.net",
    ".awsglobalaccelerator.com",
    # Azure
    ".azurewebsites.net",
    ".cloudapp.azure.com",
    ".cloudapp.net",
    ".blob.core.windows.net",
    ".trafficmanager.net",
    ".azureedge.net",
    # Google
    ".storage.googleapis.com",
    ".appspot.com",
    ".firebaseapp.com",
    ".web.app",
    # Platforms and static hosts
    ".github.io",
    ".herokuapp.com",
    ".herokudns.com",
    ".netlify.app",
    ".netlify.com",
    ".vercel.app",
    ".pages.dev",
    ".surge.sh",
    ".bitbucket.io",
    ".ghost.io",
    ".shopify.com",
    ".fastly.net",
)

# Hostnames worth probing on every scan even when no subdomain list is
# supplied. Payment-adjacent names are first because a stale record there is
# the one a customer cannot afford to leave standing.
_TAKEOVER_CANDIDATES = (
    "checkout", "pay", "payment", "payments", "shop", "store", "cart",
    "www", "api", "cdn", "assets", "static", "img", "media",
    "mail", "blog", "help", "support", "admin", "portal",
    "app", "staging", "dev", "test", "beta", "old", "legacy",
)

_RESOLVER = dns.resolver.Resolver()
_RESOLVER.timeout = 5
_RESOLVER.lifetime = 10

# Takeover probing runs across many hostnames, so it gets a tighter budget.
_TAKEOVER_RESOLVER = dns.resolver.Resolver()
_TAKEOVER_RESOLVER.timeout = 3
_TAKEOVER_RESOLVER.lifetime = 5


def mail_domain(domain: str) -> str:
    """
    The domain email records live on. People type "www.shop.com"; SPF, DMARC and
    MX are published on "shop.com", and checking them on the www host reports
    missing records that exist.
    """
    return domain[4:] if domain.startswith("www.") and domain.count(".") >= 2 else domain


def climb(name: str):
    """
    name, then each parent down to two labels. CAA (RFC 8659) and DMARC's
    organizational-domain fallback are both defined by walking up the tree, and
    NS and DNSSEC live at the zone apex, not on every host under it.
    """
    labels = name.split(".")
    for i in range(0, max(1, len(labels) - 1)):
        yield ".".join(labels[i:])


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
                penalty=0,
            ),
        )
    return (
        None,
        DNSFinding(
            check="A/AAAA resolution",
            status="fail",
            severity="high",
            description="Domain does not resolve to any IP address.",
            remediation=(
                "Your domain doesn't point anywhere. Log in to your DNS provider (where "
                "you bought the domain, or Cloudflare) and add an A record pointing to your "
                "server's IP address. If you use IPv6, add an AAAA record too."
            ),
            penalty=PENALTY["high"],
        ),
    )


def _check_mx(domain: str) -> tuple[DNSRecord | None, DNSFinding]:
    values = _query(domain, "MX")
    if values:
        return (
            DNSRecord(record_type="MX", values=values),
            DNSFinding(check="MX records", status="info", severity=None,
                       description=f"Mail servers found: {', '.join(values)}",
                       remediation=None, penalty=0),
        )
    return (
        None,
        DNSFinding(check="MX records", status="info", severity=None,
                   description="No MX records found.",
                   remediation="If this domain sends or receives email, add MX records pointing to your email provider (Google Workspace, Microsoft 365, etc.). If it's a website-only domain, you can ignore this.", penalty=0),
    )


def _check_ns(domain: str) -> tuple[DNSRecord | None, DNSFinding]:
    values: list[str] = []
    for name in climb(domain):
        values = _query(name, "NS")
        if values:
            break
    if values:
        return (
            DNSRecord(record_type="NS", values=values),
            DNSFinding(check="NS records", status="info", severity=None,
                       description=f"Authoritative nameservers: {', '.join(values)}",
                       remediation=None, penalty=0),
        )
    return (
        None,
        DNSFinding(check="NS records", status="warn", severity="low",
                   description="Could not retrieve NS records for this domain.",
                   remediation=None, penalty=PENALTY["low"]),
    )


def _check_txt(domain: str) -> DNSRecord | None:
    values = _txt_records(domain)
    return DNSRecord(record_type="TXT", values=values) if values else None


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
                "Add an SPF record so other mail servers know which servers are allowed "
                "to send email as your domain. This blocks scammers from spoofing you. "
                "In your DNS settings add a TXT record. Your email provider gives you the "
                "exact value; for example Google Workspace uses: v=spf1 include:_spf.google.com -all"
            ),
            penalty=PENALTY["high"],
        )

    if len(spf_records) > 1:
        return DNSFinding(
            check="SPF",
            status="fail",
            severity="medium",
            description=f"Multiple SPF records found ({len(spf_records)}). RFC 7208 requires exactly one.",
            remediation=(
                "You have more than one SPF record, which makes them all invalid. Combine "
                "them into a single TXT record that lists every mail service you use, ending in -all."
            ),
            penalty=PENALTY["medium"],
        )

    spf = spf_records[0]

    if "+all" in spf:
        return DNSFinding(
            check="SPF",
            status="fail",
            severity="high",
            description=f"SPF uses '+all', so anyone can send email as your domain: {spf!r}",
            remediation="Your SPF record ends in '+all', which lets any server send email as your domain. Change '+all' to '-all' in your TXT record.",
            penalty=PENALTY["high"],
        )
    if "?all" in spf:
        return DNSFinding(
            check="SPF",
            status="warn",
            severity="medium",
            description=f"SPF uses '?all' (neutral), so spoofed mail is accepted: {spf!r}",
            remediation="Your SPF record ends in '?all' (neutral), which tells receiving servers to accept mail that fails the check. Once every real mail source is listed, change '?all' to '-all'.",
            penalty=PENALTY["medium"],
        )
    if "~all" in spf:
        return DNSFinding(
            check="SPF",
            status="warn",
            severity="low",
            description=f"SPF uses '~all' (softfail), so unauthorized senders are flagged and still delivered: {spf!r}",
            remediation="Your SPF record ends in '~all' (softfail), which flags fake mail and still delivers it. Once every legitimate sender is listed, tighten it to '-all'.",
            penalty=PENALTY["low"],
        )

    return DNSFinding(check="SPF", status="pass", severity=None,
                     description=f"SPF record is present with a strict policy: {spf!r}",
                     remediation=None, penalty=0)


def _check_dmarc(domain: str) -> tuple[DNSRecord | None, DNSFinding]:
    # Receivers fall back to the organizational domain's policy, so a record on a
    # parent covers this name too.
    dmarc_records: list[str] = []
    for name in climb(domain):
        dmarc_records = [r for r in _txt_records(f"_dmarc.{name}") if r.startswith("v=DMARC1")]
        if dmarc_records:
            break

    if not dmarc_records:
        return (
            None,
            DNSFinding(
                check="DMARC",
                status="fail",
                severity="high",
                description=(
                    f"No DMARC record found at _dmarc.{domain}. Without DMARC, mail receivers "
                    "have no instruction on what to do with failing messages."
                ),
                remediation=(
                    "Add a DMARC record to tell mail servers what to do with email that "
                    "fails your SPF checks. In your DNS, add a TXT record named '_dmarc' "
                    f"with a value like: v=DMARC1; p=quarantine; rua=mailto:you@{domain}. "
                    "Start with p=quarantine and move to p=reject once you've confirmed "
                    "your real email still arrives."
                ),
                penalty=PENALTY["high"],
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
        return (record, DNSFinding(
            check="DMARC", status="warn", severity="medium",
            description=f"DMARC policy is 'none', so failing messages are delivered normally: {dmarc!r}",
            remediation="Your DMARC policy is set to p=none, which reports on spoofed email and still delivers it. Once you have reviewed your reports, change it to p=quarantine, then to p=reject.",
            penalty=PENALTY["medium"],
        ))
    if policy == "quarantine":
        return (record, DNSFinding(
            check="DMARC", status="warn", severity="low",
            description=f"DMARC policy is 'quarantine', so failing messages go to spam: {dmarc!r}",
            remediation="Your DMARC is set to p=quarantine (fake mail goes to spam). For the strongest protection, change it to p=reject once you're confident your legitimate email passes.",
            penalty=PENALTY["low"],
        ))

    return (record, DNSFinding(
        check="DMARC", status="pass", severity=None,
        description=f"DMARC record present with strict policy (p={policy}): {dmarc!r}",
        remediation=None, penalty=0,
    ))


def _check_caa(domain: str) -> tuple[DNSRecord | None, DNSFinding]:
    values: list[str] = []
    for name in climb(domain):  # RFC 8659: the closest CAA record up the tree applies
        values = _query(name, "CAA")
        if values:
            break
    if values:
        return (
            DNSRecord(record_type="CAA", values=values),
            DNSFinding(check="CAA", status="pass", severity=None,
                       description=f"CAA records restrict certificate issuance to: {', '.join(values)}",
                       remediation=None, penalty=0),
        )
    return (
        None,
        DNSFinding(
            check="CAA", status="warn", severity="low",
            description="No CAA records. Any CA can issue certificates for this domain.",
            remediation='Add a CAA record to control which certificate authorities can issue SSL certificates for your domain. In your DNS, add a CAA record like: 0 issue "letsencrypt.org" (use whichever CA issues your certificates). This stops other CAs from issuing certs for you.',
            penalty=PENALTY["low"],
        ),
    )


def _cname_targets(domain: str) -> list[str]:
    """Return CNAME record values for *domain* (empty list if none)."""
    try:
        answers = _RESOLVER.resolve(domain, "CNAME")
        return [r.to_text().rstrip(".") for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.DNSException:
        return []


def _is_cloud_cname(target: str) -> bool:
    """Return True when *target* matches a known cloud service CNAME pattern."""
    tgt = target.lower()
    return any(pattern in tgt for pattern in _CLOUD_CNAME_PATTERNS)


def _cname_target_resolves(target: str) -> bool:
    """
    Return True when *target* still exists in DNS.

    This replaces an earlier HTTP check that treated any non-200 response as
    evidence of a dangling record. That flagged live-but-private buckets,
    WAF-protected endpoints and ordinary timeouts, which is exactly the kind
    of false positive that discredits a report. A target that does not resolve
    at all is unambiguous, needs no HTTP request, and keeps the scan passive.
    """
    for rdtype in ("A", "AAAA", "CNAME"):
        try:
            _TAKEOVER_RESOLVER.resolve(target, rdtype)
            return True
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return True          # the name exists, it just has no record of this type
        except dns.resolver.NXDOMAIN:
            continue             # definitively absent; try the next type to be sure
        except dns.exception.DNSException:
            return True          # timeout or resolver trouble: never guess "dangling"
    return False


def _wildcard_cname_target(domain: str) -> str | None:
    """
    Return the CNAME target a wildcard record answers with, if one exists.

    Without this, a single "*.example.com" record makes every hostname we probe
    look like its own dangling record. Testing a random name that nobody would
    ever create tells us what the wildcard does before we judge anything else.
    """
    probe = f"sekura-wildcard-probe-{uuid.uuid4().hex[:12]}.{domain}"
    targets = _cname_targets(probe)
    return targets[0] if targets else None


def _check_subdomain_takeovers(domain: str, subdomains: list[str] | None = None) -> list[DNSFinding]:
    """
    Look for records that CNAME to a cloud service which no longer exists.

    Candidates are a built-in list of common hostnames plus anything the caller
    supplies (e.g. from the certificate-transparency subdomain scanner). The
    built-in list matters: this check previously ran only on a caller-supplied
    list, and the orchestrator never supplied one, so it never ran at all.

    A wildcard record is reported once, as the single record it is. Reporting
    one misconfiguration as twenty findings is how a report loses its reader.
    """
    findings: list[DNSFinding] = []

    wildcard_target = _wildcard_cname_target(domain)
    wildcard_dangling = bool(
        wildcard_target
        and _is_cloud_cname(wildcard_target)
        and not _cname_target_resolves(wildcard_target)
    )
    if wildcard_dangling:
        findings.append(DNSFinding(
            check=f"Dangling wildcard DNS record: *.{domain}",
            status="fail",
            severity="high",
            description=(
                f"A wildcard record sends every unused subdomain of {domain} to "
                f"{wildcard_target}, which no longer exists in DNS. Any hostname a customer "
                f"or an attacker invents, including names like checkout.{domain}, resolves to "
                "a service that is gone. Whether someone else can claim that name depends on "
                "the provider, so this is a stale record to remove rather than a confirmed "
                "takeover."
            ),
            remediation=(
                f"Remove the wildcard CNAME for *.{domain} if the service behind it is retired, "
                "and publish records only for the hostnames you actually use. If the wildcard is "
                "still needed, point it at a host you control that returns a deliberate response. "
                "Keep the previous DNS state for rollback."
            ),
            penalty=30,
        ))

    candidates = {f"{prefix}.{domain}" for prefix in _TAKEOVER_CANDIDATES}
    candidates.update(subdomains or [])

    def _inspect(sub: str) -> DNSFinding | None:
        for target in _cname_targets(sub):
            if wildcard_target and target == wildcard_target:
                continue        # this is the wildcard answering, not its own record
            if not _is_cloud_cname(target):
                continue
            if _cname_target_resolves(target):
                continue
            return DNSFinding(
                check=f"Dangling DNS record: {sub}",
                status="fail",
                severity="high",
                description=(
                    f"{sub} points to {target}, which no longer exists in DNS. The record "
                    "outlived the service it was created for. Whether someone else can claim "
                    "that name depends on the provider, so this is a stale record to remove "
                    "rather than a confirmed takeover."
                ),
                remediation=(
                    f"Delete the CNAME record for {sub} in your DNS if the service is retired. "
                    f"If it is still needed, re-create it at {target} first, then confirm {sub} "
                    "resolves before leaving it in place. Keep the previous DNS state for rollback."
                ),
                penalty=30,
            )
        return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        for finding in pool.map(_inspect, sorted(candidates)):
            if finding is not None:
                findings.append(finding)
    return findings


def _score(findings: list[DNSFinding]) -> tuple[int, str]:
    total = sum(f.penalty for f in findings)
    risk_score = scanner_score(total, "dns")
    return risk_score, risk_level(risk_score)


async def scan_dns(domain: str, subdomains: list[str] | None = None) -> DNSScanResult:
    """
    Scan DNS/email-auth for *domain*.

    Optionally accepts a *subdomains* list (e.g. from the subdomain scanner) to
    check for dangling CNAME / subdomain-takeover risks. When omitted, only the
    apex domain checks are performed.
    """
    loop = asyncio.get_event_loop()

    mail = mail_domain(domain)

    def _run_all() -> tuple:
        a_record, a_finding = _check_a(domain)
        mx_record, mx_finding = _check_mx(mail)
        ns_record, ns_finding = _check_ns(domain)
        txt_record = _check_txt(mail)
        spf_finding = _check_spf(mail)
        dmarc_record, dmarc_finding = _check_dmarc(mail)
        caa_record, caa_finding = _check_caa(domain)
        # Candidates like checkout.<domain> hang off the apex, not www.
        takeover_findings = _check_subdomain_takeovers(mail, subdomains)
        return (
            a_record, a_finding, mx_record, mx_finding,
            ns_record, ns_finding, txt_record,
            spf_finding, dmarc_record, dmarc_finding,
            caa_record, caa_finding,
            takeover_findings,
        )

    (
        a_record, a_finding, mx_record, mx_finding,
        ns_record, ns_finding, txt_record,
        spf_finding, dmarc_record, dmarc_finding,
        caa_record, caa_finding,
        takeover_findings,
    ) = await loop.run_in_executor(None, _run_all)

    records = [r for r in [a_record, mx_record, ns_record, txt_record, dmarc_record, caa_record] if r]
    # DNSSEC is reported by the dns_hijack scanner, which is where an unsigned
    # zone actually matters. Checking it here too produced two findings for one
    # check, with contradictory verdicts.
    findings = [a_finding, mx_finding, ns_finding, spf_finding, dmarc_finding, caa_finding]
    findings.extend(takeover_findings)

    critical_triggers: list[str] = []
    if any(f.check.startswith("Dangling") for f in takeover_findings):
        critical_triggers.append("subdomain_takeover")

    risk_score, level = _score(findings)

    return DNSScanResult(
        domain=domain,
        scan_timestamp=utc_now_iso(),
        records=records,
        findings=findings,
        risk_score=risk_score,
        risk_level=level,
        critical_triggers=critical_triggers,
        summary={
            "checks_run": len(findings),
            "fail": sum(1 for f in findings if f.status == "fail"),
            "warn": sum(1 for f in findings if f.status == "warn"),
            "pass": sum(1 for f in findings if f.status == "pass"),
        },
    )
