"""
Action Plan report model.

Turns a FullScanResult into the Sekura owner-brief structure:

  page 1  owner brief      three prioritised actions, each with an owner
  page 2  developer detail the first action, in full
  page 3  developer detail actions two and three, condensed
  page 4  evidence + scope what the scan can and cannot support

The rule that shapes this document: a missing result is not a pass. Where a
scanner returned no evidence (zero JS files read, no resolver agreement, an
intercepted certificate), the area is marked incomplete and the overall
rating is withheld rather than printed over a gap.

This module holds no presentation logic. It builds plain dataclasses that
templates/action_plan.html renders.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import re

from models.scan import FullScanResult

# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------

BAND_IMMEDIATE   = "TODAY"
BAND_THIS_WEEK   = "THIS WEEK"
BAND_VERIFY      = "VERIFY FIRST"
BAND_NEXT_WINDOW = "NEXT WINDOW"

OWNER_EMAIL = "Email / IT provider"
OWNER_DEV   = "Web developer"
OWNER_HOST  = "Web developer / host"
OWNER_DNS   = "DNS provider"

# Mono blocks in the design run to roughly 66 characters before they wrap.
MONO_WRAP = 66


@dataclass
class CodeBlock:
    label: str
    caption: str
    lines: list[str]


@dataclass
class Step:
    title: str
    body: str


@dataclass
class Ref:
    label: str
    url: str | None = None


@dataclass
class Action:
    key: str
    band: str
    owner: str
    # Owner-brief card
    headline: str
    brief: str
    # Developer detail
    section_owner: str          # "EMAIL PROVIDER + DNS ADMIN"
    topic: str                  # "EMAIL" - the word in the page header
    unit_title: str             # short noun phrase, used on the condensed page
    detail_title: str
    detail_kicker: str
    detail_intro: str
    observed: CodeBlock | None = None
    steps: list[Step] = field(default_factory=list)
    verify: CodeBlock | None = None
    done_when: str = ""
    refs: list[Ref] = field(default_factory=list)
    # Filled in once the action's position is known
    number: str = "01"
    page: int = 2


@dataclass
class EvidenceRow:
    area: str
    note: str
    complete: bool


@dataclass
class Sheet:
    """One rendered page. `kind` selects the layout block in the template."""
    kind: str
    eyebrow: str
    page_no: int
    actions: list[Action] = field(default_factory=list)
    title: str = ""
    kicker: str = ""
    section_owner: str = ""


@dataclass
class ActionPlan:
    domain: str
    client_name: str
    scan_date: str
    security_score: int
    rating_withheld: bool
    withheld_reason: str
    start_here: str
    actions: list[Action]
    evidence_rows: list[EvidenceRow]
    scope: str
    sheets: list[Sheet]
    page_total: int


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _wrap_mono(value: str, width: int = MONO_WRAP) -> list[str]:
    """
    Wrap a long record value to the width of the mono block, breaking on
    whitespace only. Every other character is preserved verbatim: these blocks
    are evidence, and a developer will paste them back into a terminal.
    """
    tokens = re.findall(r"\S+\s*", value)
    lines: list[str] = []
    current = ""
    for token in tokens:
        if current and len(current) + len(token.rstrip()) > width:
            lines.append(current.rstrip())
            current = token
        else:
            current += token
    if current.strip():
        lines.append(current.rstrip())
    return lines or [value]


def _fmt_date(value: str) -> str:
    """Render an ISO timestamp as a date a business owner can read."""
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).strftime("%d %b %Y")
    except (ValueError, AttributeError):
        return value or "unknown"


def _txt_values(result: FullScanResult) -> list[str]:
    for record in result.dns.records:
        if record.record_type == "TXT":
            return record.values
    return []


def _find_txt(result: FullScanResult, marker: str) -> str | None:
    for value in _txt_values(result):
        if value.lower().startswith(marker.lower()):
            return value
    return None


def _severity_word(severity: str | None) -> str:
    return {"high": "high", "medium": "medium", "low": "low"}.get(severity or "", "informational")


def _dns_findings(result: FullScanResult, *keywords: str) -> list:
    out = []
    for finding in result.dns.findings:
        if finding.status in ("fail", "warn") and any(k.lower() in finding.check.lower() for k in keywords):
            out.append(finding)
    return out


def _ssl_findings(result: FullScanResult, *keywords: str) -> list:
    out = []
    for finding in result.ssl.findings:
        if finding.status in ("fail", "warn") and any(k.lower() in finding.check.lower() for k in keywords):
            out.append(finding)
    return out


def _redact(preview: str) -> str:
    """
    Never print a live credential into a document we hand to a third party.
    Keep enough of the token for the developer to locate it, mask the rest.
    """
    cleaned = preview.strip()
    if len(cleaned) <= 8:
        return "*" * len(cleaned)
    return f"{cleaned[:4]}{'*' * 8}{cleaned[-2:]}"


# Certificate authorities that indicate a TLS-intercepting proxy rather than
# the certificate a visitor's browser actually receives.
_INTERCEPT_MARKERS = (
    "egress gateway", "anthropic", "zscaler", "netskope", "bluecoat", "blue coat",
    "forcepoint", "palo alto", "mitmproxy", "charles proxy", "fiddler", "burp",
    "sslsplit", "corporate proxy", "squid",
)


def _cert_is_intercepted(result: FullScanResult) -> bool:
    # The scanner now detects interception directly and says so. The checks
    # below remain for scans stored before that flag existed.
    if getattr(result.ssl, "intercepted", False):
        return True
    cert = result.ssl.certificate
    if not cert:
        return False
    if cert.source == "ct_log":
        return True
    issuer = (cert.issuer or "").lower()
    if any(marker in issuer for marker in _INTERCEPT_MARKERS):
        return True
    # A leaf that names neither the domain nor a wildcard for it did not come
    # from the site we asked for.
    domain = result.domain.lower()
    names = [n.lower() for n in (cert.sans or [])] + [(cert.subject or "").lower()]
    apex = domain.split(".", 1)[-1]
    return not any(domain in n or f"*.{apex}" in n for n in names)


# ---------------------------------------------------------------------------
# Action builders
#
# Each builder returns an Action when the scan actually produced the finding,
# otherwise None. Order in _BUILDERS is the priority order: the first three
# that fire become actions 01, 02 and 03.
# ---------------------------------------------------------------------------

def _action_secrets(result: FullScanResult) -> Action | None:
    if not result.secrets or not result.secrets.findings:
        return None
    findings = result.secrets.findings
    names = sorted({f.pattern_name for f in findings})
    lines: list[str] = []
    for finding in findings[:3]:
        lines.append(f"{finding.pattern_name} / {finding.location}")
        lines += [f"  {chunk}" for chunk in _wrap_mono(finding.source_url, MONO_WRAP - 2)]
        lines.append(f"  match: {_redact(finding.match_preview)}")
    return Action(
        key="secrets",
        band=BAND_IMMEDIATE,
        owner=OWNER_DEV,
        headline="Rotate the credentials in your public code",
        brief=(
            f"{len(findings)} credential pattern{'s' if len(findings) != 1 else ''} "
            f"({', '.join(names[:2])}) "
            f"{'appears' if len(findings) == 1 else 'appear'} in files any visitor can download. "
            f"Treat {'it' if len(findings) == 1 else 'them'} as already seen."
        ),
        section_owner="WEB DEVELOPER",
        topic="SECRETS",
        unit_title="Exposed credentials",
        detail_title="Rotate first, then remove",
        detail_kicker=f"Secret exposure: high priority / Files read: {result.secrets.files_scanned}",
        detail_intro=(
            "The scan matched credential patterns in resources served to the browser. "
            "Pattern matching can produce false positives, so confirm each match before "
            "rotating, but treat a confirmed match as public from the moment it shipped."
        ),
        observed=CodeBlock("MATCHED PATTERNS", "VALUES REDACTED", lines),
        steps=[
            Step("1. Rotate with the issuing service.",
                 "Revoke and reissue each confirmed credential at its provider before editing any code. "
                 "Removing it from the page does not invalidate a key that has already been copied."),
            Step("2. Move the value server-side.",
                 "Anything the browser downloads is public. Keep the credential in a server environment "
                 "variable and proxy the call, or replace it with a publishable key scoped to the site."),
            Step("3. Check what it touched.",
                 "Review the provider's access and billing logs for use you do not recognise, over the "
                 "period the credential was reachable."),
        ],
        verify=CodeBlock("CONFIRM THE VALUE IS GONE", "SHELL WITH CURL", [
            f"curl -s https://{result.domain}/ | grep -nE 'api[_-]?key|secret'",
        ]),
        done_when=(
            "Each confirmed credential is rotated at the provider, the old value no longer appears in any "
            "file the site serves, and provider logs show no unrecognised use."
        ),
        refs=[Ref("OWASP: Secrets Management")],
    )


def _action_exposure(result: FullScanResult) -> Action | None:
    exposed = [f for f in result.exposure.findings if f.exposed and f.severity in ("high", "medium")]
    if not exposed:
        return None
    exposed.sort(key=lambda f: 0 if f.severity == "high" else 1)
    worst = exposed[0]
    lines = [f"GET /{f.path.lstrip('/')}  ->  HTTP {f.status_code}  ({f.label})" for f in exposed[:5]]
    return Action(
        key="exposure",
        band=BAND_IMMEDIATE if worst.severity == "high" else BAND_THIS_WEEK,
        owner=OWNER_HOST,
        headline="Close the paths that answer publicly",
        brief=(
            f"{len(exposed)} sensitive path{'s' if len(exposed) != 1 else ''} returned a response to an "
            "anonymous request. Your developer should confirm what each one serves."
        ),
        section_owner="WEB DEVELOPER + HOST",
        topic="PUBLIC PATHS",
        unit_title="Exposed paths",
        detail_title="Restrict the exposed paths",
        detail_kicker=f"Public exposure: {_severity_word(worst.severity)} priority / Paths responding: {len(exposed)}",
        detail_intro=(
            "These requests were ordinary anonymous HTTPS GETs. A response code alone does not prove the "
            "content is sensitive; confirm what each path returns before deciding how to restrict it."
        ),
        observed=CodeBlock("PATHS THAT RESPONDED", "METHOD, PATH, STATUS", lines),
        steps=[
            Step("1. Confirm what is served.",
                 "Open each path and record what it returns. A soft 404 rendered with status 200 is a "
                 "false positive and should be corrected at the server, not hidden."),
            Step("2. Restrict or remove.",
                 worst.remediation or "Block the path at the web server or CDN, or remove the file from the document root."),
            Step("3. Re-check after deploy.",
                 "Confirm from outside your network and from a cold cache; a CDN may serve the old response "
                 "for the length of its TTL."),
        ],
        verify=CodeBlock("RECHECK THE STATUS CODES", "SHELL WITH CURL", [
            f"curl -s -o /dev/null -w '%{{http_code}}\\n' https://{result.domain}/{f.path.lstrip('/')}"
            for f in exposed[:3]
        ]),
        done_when=(
            "Each path returns a deliberate response, the restriction is confirmed from outside your network, "
            "and the previous server configuration is saved for rollback."
        ),
        refs=[Ref("OWASP: Improper Access Control")],
    )


def _action_checkout(result: FullScanResult) -> Action | None:
    if not result.checkout_scripts or not result.checkout_scripts.findings:
        return None
    findings = result.checkout_scripts.findings
    worst = max(findings, key=lambda f: {"high": 3, "medium": 2, "low": 1}.get(f.severity, 0))
    lines: list[str] = []
    for finding in findings[:3]:
        lines += _wrap_mono(finding.evidence or finding.description)
    return Action(
        key="checkout_scripts",
        band=BAND_THIS_WEEK,
        owner=OWNER_DEV,
        headline="Review the scripts on your payment pages",
        brief=(
            "Third-party code running on a checkout page can read what a customer types. "
            "Your developer should confirm every script there is one you chose."
        ),
        section_owner="WEB DEVELOPER",
        topic="CHECKOUT",
        unit_title="Checkout scripts",
        detail_title="Control the checkout script surface",
        detail_kicker=(
            f"Checkout scripts: {_severity_word(worst.severity)} priority / "
            f"Pages read: {len(result.checkout_scripts.pages_scanned)}"
        ),
        detail_intro=(
            "Scripts loaded on a page that handles payment details run with full access to that page. "
            "These are configuration findings; they do not prove that card data was taken."
        ),
        observed=CodeBlock("SCRIPT FINDINGS", "EVIDENCE FROM THE PAGE", lines),
        steps=[
            Step("1. Inventory the scripts.",
                 "List every script on the payment path and the business reason for each. Remove anything "
                 "no one can account for."),
            Step("2. Pin what remains.",
                 worst.remediation or "Add Subresource Integrity hashes and serve every script over HTTPS from a host you control or trust."),
            Step("3. Constrain the page.",
                 "Add a Content-Security-Policy that names the script sources the checkout is allowed to load."),
        ],
        verify=CodeBlock("LIST SCRIPTS ON THE CHECKOUT PAGE", "SHELL WITH CURL", [
            f"curl -s https://{result.domain}/checkout | grep -oE '<script[^>]*>'",
        ]),
        done_when=(
            "Every script on the payment path is accounted for, integrity-pinned where third-party, and a "
            "Content-Security-Policy blocks sources outside that list."
        ),
        refs=[Ref("PCI DSS 4.0: 6.4.3 and 11.6.1")],
    )


def _action_email(result: FullScanResult) -> Action | None:
    dmarc_findings = _dns_findings(result, "DMARC")
    spf_findings = _dns_findings(result, "SPF")
    if not dmarc_findings and not spf_findings:
        return None

    dmarc_value = _find_txt(result, "v=DMARC1")
    if not dmarc_value:
        for value in _txt_values(result):
            if "v=dmarc1" in value.lower():
                dmarc_value = value
                break
    spf_value = _find_txt(result, "v=spf1")

    lines: list[str] = []
    if dmarc_value:
        lines += _wrap_mono(dmarc_value)
    else:
        lines.append("no DMARC record returned at _dmarc." + result.domain)
    lines.append("")
    if spf_value:
        lines += _wrap_mono(spf_value)
    else:
        lines.append("no SPF record returned for " + result.domain)

    kicker_parts = []
    if dmarc_findings:
        kicker_parts.append(f"DMARC: {_severity_word(dmarc_findings[0].severity)} priority")
    if spf_findings:
        kicker_parts.append(f"SPF: {_severity_word(spf_findings[0].severity)} priority")

    steps = [
        Step("1. Inventory senders.",
             "Include staff mail, website forms, receipts and marketing tools. Check SPF or DKIM alignment "
             "with the visible From domain."),
    ]
    if dmarc_findings:
        steps.append(Step("2. Move DMARC into enforcement.",
                          "After reviewing reports and fixing legitimate failures, change p=none to p=quarantine, "
                          "then p=reject when ready. Review sp= separately; left at none it leaves subdomains in "
                          "monitoring mode."))
    if spf_findings:
        steps.append(Step(f"{len(steps) + 1}. Tighten SPF after validation.",
                          "Confirm every required sender and the SPF lookup limit before changing a final ~all to "
                          "-all. Keep a single SPF record, and do not assume the includes already listed are the "
                          "complete sender inventory."))

    return Action(
        key="email_auth",
        band=BAND_THIS_WEEK,
        owner=OWNER_EMAIL,
        headline="Protect email sent in your name",
        brief=(
            "Reduce the risk of fake invoices and messages. Your email provider should review "
            "legitimate senders before changing policy."
        ),
        section_owner="EMAIL PROVIDER + DNS ADMIN",
        topic="EMAIL",
        unit_title="Email authentication",
        detail_title="Protect mail sent in your name",
        detail_kicker=" / ".join(kicker_parts) or "Email authentication",
        detail_intro=(
            "The scan read the published DMARC and SPF records for this domain. These are configuration "
            "findings; they do not prove that fraudulent mail reached a customer."
        ),
        observed=CodeBlock("OBSERVED TXT VALUES", "DMARC, THEN SPF", lines),
        steps=steps,
        verify=CodeBlock("RECHECK AFTER DNS PROPAGATION", "SHELL WITH DIG", [
            f"dig +short TXT _dmarc.{result.domain}",
            f"dig +short TXT {result.domain}",
        ]),
        done_when=(
            "The intended policy is visible in DNS, each legitimate sending service passes aligned "
            "authentication, and delivery tests and aggregate reports show no unexpected failures. "
            "Keep the previous TXT values for rollback."
        ),
        refs=[Ref("DMARC: RFC 7489"), Ref("SPF: RFC 7208")],
    )


def _action_certificate(result: FullScanResult) -> Action | None:
    cert = result.ssl.certificate
    findings = _ssl_findings(result, "certificate", "expir", "self", "hostname", "chain")
    intercepted = _cert_is_intercepted(result)
    if not findings and not intercepted:
        return None

    lines: list[str] = []
    if cert:
        lines += _wrap_mono(f"subject: {cert.subject}")
        lines += _wrap_mono(f"issuer:  {cert.issuer}")
        lines.append(f"expires: {_fmt_date(cert.not_after)}  ({cert.days_until_expiry} days)")
    else:
        lines.append("no certificate could be read for this domain")

    from_ct = bool(cert and cert.source == "ct_log")
    observed_caption = "FROM CERTIFICATE TRANSPARENCY" if from_ct else "SUBJECT, ISSUER, EXPIRY"

    if intercepted:
        kicker = "Certificate alert: unverified / Source: " + (
            "public certificate transparency log" if from_ct else "TLS inspection on the scan path"
        )
        if from_ct:
            intro = (
                "The network the scan ran from intercepts TLS, so the scanner could not read this "
                "site's live certificate. The values below are the most recent certificate logged "
                "publicly for the domain: evidence that it was issued, not evidence of what a "
                "visitor's browser receives today."
            )
        else:
            intro = (
                "The network the scan ran from intercepts TLS and no public certificate record was "
                "available, so this site's certificate could not be established at all. Nothing here "
                "should be read as a finding about the site until it is checked directly."
            )
        band = BAND_VERIFY
        headline = "Check the certificate evidence"
        brief = (
            "The scan may have recorded a gateway certificate. Have the developer confirm what "
            "visitors actually receive."
        )
        next_step = Step("1. Re-read the certificate without interception.",
                         "Run the command below from a connection with no TLS inspection and compare it with "
                         "what the browser shows. Only then judge the expiry and issuer.")
    else:
        worst = findings[0]
        kicker = f"Certificate: {_severity_word(worst.severity)} priority / Source: TLS handshake"
        intro = (
            "The scan completed a TLS handshake and read the leaf certificate presented for this hostname. "
            "Confirm renewal ownership before changing anything: a managed CDN certificate is renewed by "
            "the host, not on your server."
        )
        band = BAND_THIS_WEEK if worst.severity == "high" else BAND_NEXT_WINDOW
        headline = "Resolve the certificate warning"
        brief = (
            (findings[0].description or "").strip()
            or "Your developer or host should confirm the certificate and its renewal owner."
        )
        next_step = Step("1. Confirm the finding at the host.",
                         worst.remediation or "Ask the host or CDN to confirm the certificate's renewal status and owner.")

    steps = [next_step, Step("2. Confirm renewal ownership.",
                             "Record who renews this certificate and how. Renew only if the public certificate "
                             "requires it; managed CDN certificates should be handled through the host.")]

    return Action(
        key="certificate",
        band=band,
        owner=OWNER_HOST,
        headline=headline,
        brief=brief,
        section_owner="WEB HOST + DNS ADMIN",
        topic="CERTIFICATES",
        unit_title="Certificate alert",
        detail_title="Verify first. Then configure.",
        detail_kicker=kicker,
        detail_intro=intro,
        observed=CodeBlock("CERTIFICATE AS RECORDED", observed_caption, lines),
        steps=steps,
        verify=CodeBlock("INSPECT PUBLIC LEAF CERTIFICATE", "BASH + OPENSSL", [
            f"openssl s_client -connect {result.domain}:443 \\",
            f"  -servername {result.domain} </dev/null 2>/dev/null | \\",
            "  openssl x509 -noout -subject -issuer -dates",
        ]),
        done_when=(
            "The public hostname, issuer and expiry are recorded, browser trust succeeds, and renewal "
            "ownership is confirmed. This inspection command alone does not validate the certificate chain."
        ),
        refs=[Ref("OpenSSL s_client reference")],
    )


def _action_dns_hijack(result: FullScanResult) -> Action | None:
    if not result.dns_hijack:
        return None
    findings = [f for f in result.dns_hijack.findings if f.status in ("fail", "warn")]
    if not findings:
        return None
    worst = findings[0]
    lines = [f"{f.check}: {f.status}" for f in findings[:5]]
    resolvers = result.dns_hijack.resolver_results or {}
    lines.append(f"resolvers answering: {len(resolvers)}")
    return Action(
        key="dns_hijack",
        band=BAND_VERIFY,
        owner=OWNER_DNS,
        headline="Confirm where your domain points",
        brief=(
            "Public resolvers did not agree on this domain's answers, or a consistency check did not "
            "complete. Have your DNS provider confirm the intended records."
        ),
        section_owner="DNS PROVIDER",
        topic="DNS",
        unit_title="Resolver agreement",
        detail_title="Confirm resolver agreement",
        detail_kicker=f"DNS consistency: {_severity_word(worst.severity)} priority / Resolvers: {len(resolvers)}",
        detail_intro=(
            "Independent public resolvers were queried and compared. A disagreement is usually propagation "
            "or geo-routing rather than an attack; an incomplete check is evidence of nothing either way."
        ),
        observed=CodeBlock("CONSISTENCY CHECKS", "CHECK AND RESULT", lines),
        steps=[
            Step("1. Record the intended records.",
                 "Have the DNS provider export the current zone so there is an authoritative reference to "
                 "compare against."),
            Step("2. Compare resolvers yourself.",
                 worst.remediation or "Query several public resolvers and confirm they return the records you intend."),
        ],
        verify=CodeBlock("COMPARE TWO RESOLVERS", "SHELL WITH DIG", [
            f"dig +short A {result.domain} @1.1.1.1",
            f"dig +short A {result.domain} @8.8.8.8",
        ]),
        done_when=(
            "Every resolver queried returns the records the provider intends, and any difference is "
            "explained by propagation or geo-routing you configured."
        ),
        refs=[Ref("DNSSEC: RFC 9364")],
    )


def _action_caa(result: FullScanResult) -> Action | None:
    findings = _dns_findings(result, "CAA")
    if not findings:
        return None
    return Action(
        key="caa",
        band=BAND_NEXT_WINDOW,
        owner=OWNER_DNS,
        headline="Restrict certificate issuance",
        brief=(
            "Have the host confirm the certificate authorities required, then ask the DNS provider "
            "to add CAA controls."
        ),
        section_owner="DNS PROVIDER",
        topic="CERTIFICATES",
        unit_title="Certificate authority authorization",
        detail_title="Certificate authority authorization",
        detail_kicker=f"CAA: {_severity_word(findings[0].severity)} priority / Source: DNS lookup",
        detail_intro=(
            "No CAA record was returned for this domain. CAA limits which authorities may issue "
            "certificates; its absence does not remove their domain-validation requirements."
        ),
        observed=CodeBlock("CHECK CURRENT RECORDS", "SHELL WITH DIG", [
            f"dig +short CAA {result.domain}",
        ]),
        steps=[
            Step("1. Ask the host for its required values.",
                 "Request the CAA values the host or CDN needs, including backup and wildcard issuers, "
                 "before adding anything. Do not copy a generic issuer value into production."),
            Step("2. Add the records, then re-issue once.",
                 "Publish the approved records and confirm with the host that issuance and renewal still "
                 "succeed. Save the previous DNS state for rollback."),
        ],
        verify=CodeBlock("CONFIRM AFTER PROPAGATION", "SHELL WITH DIG", [
            f"dig +short CAA {result.domain}",
        ]),
        done_when=(
            "DNS returns the host-approved records and the host confirms that issuance and renewal "
            "remain possible."
        ),
        refs=[Ref("CAA: RFC 8659")],
    )


def _action_headers(result: FullScanResult) -> Action | None:
    missing = [f for f in result.headers.findings if f.status in ("missing", "weak")]
    if not missing:
        return None
    rank = {"high": 3, "medium": 2, "low": 1}
    missing.sort(key=lambda f: rank.get(f.severity, 0), reverse=True)
    lines = [f"{f.header}: {'not set' if f.status == 'missing' else (f.value or 'weak')}" for f in missing[:6]]
    return Action(
        key="headers",
        band=BAND_NEXT_WINDOW,
        owner=OWNER_DEV,
        headline="Add the missing browser protections",
        brief=(
            f"{len(missing)} response header{'s' if len(missing) != 1 else ''} that instruct the browser "
            "how to protect your visitors are absent or weak. This is a server configuration change."
        ),
        section_owner="WEB DEVELOPER + HOST",
        topic="HEADERS",
        unit_title="Security headers",
        detail_title="Set the response headers",
        detail_kicker=f"Security headers: {_severity_word(missing[0].severity)} priority / Headers short: {len(missing)}",
        detail_intro=(
            "These headers are sent by the web server or CDN, not by the site's code. Add them at the edge "
            "where possible, and test Content-Security-Policy in report-only mode before enforcing it."
        ),
        observed=CodeBlock("HEADERS AS RECEIVED", "HEADER AND VALUE", lines),
        steps=[
            Step("1. Set the low-risk headers first.",
                 "X-Content-Type-Options, X-Frame-Options and Referrer-Policy can be added without "
                 "affecting the page. Deploy and confirm nothing changes visually."),
            Step("2. Roll out CSP in report-only mode.",
                 "Publish Content-Security-Policy-Report-Only, collect violations for a full traffic cycle, "
                 "then enforce. Enforcing an untested policy will break legitimate scripts."),
            Step("3. Add HSTS last.",
                 "Strict-Transport-Security is difficult to undo. Confirm every subdomain serves HTTPS "
                 "before setting a long max-age, and only then consider preload."),
        ],
        verify=CodeBlock("RECHECK THE RESPONSE", "SHELL WITH CURL", [
            f"curl -sI https://{result.domain}/ | \\",
            "  grep -iE 'content-security|strict-transport|x-frame|referrer'",
        ]),
        done_when=(
            "Each header is present on every page, the CSP has run a full traffic cycle in report-only mode "
            "without unexplained violations, and the previous server configuration is saved for rollback."
        ),
        refs=[Ref("OWASP Secure Headers Project")],
    )


def _action_tls(result: FullScanResult) -> Action | None:
    deprecated = [v.version for v in result.ssl.tls_versions if v.supported and v.version in ("TLS 1.0", "TLS 1.1", "SSLv3", "SSLv2")]
    findings = _ssl_findings(result, "TLS 1.0", "TLS 1.1", "protocol", "cipher")
    if not deprecated and not findings:
        return None
    supported = [v.version for v in result.ssl.tls_versions if v.supported]
    return Action(
        key="tls",
        band=BAND_NEXT_WINDOW,
        owner=OWNER_HOST,
        headline="Turn off the outdated encryption protocols",
        brief=(
            f"The server still accepts {', '.join(deprecated) if deprecated else 'a deprecated protocol'}. "
            "Your host should disable it after confirming no customer still needs it."
        ),
        section_owner="WEB HOST",
        topic="PROTOCOLS",
        unit_title="TLS protocols",
        detail_title="Retire the deprecated protocols",
        detail_kicker=f"TLS protocols: medium priority / Accepted: {', '.join(supported) or 'not recorded'}",
        detail_intro=(
            "Protocol support is a server or CDN setting. Deprecated versions are also a payment-card "
            "compliance problem, not only a technical one."
        ),
        observed=CodeBlock("PROTOCOLS ACCEPTED", "VERSION AND RESULT", [
            f"{v.version}: {'accepted' if v.supported else 'refused' if v.supported is False else 'not tested'}"
            for v in result.ssl.tls_versions
        ]),
        steps=[
            Step("1. Check who still connects with it.",
                 "Ask the host for protocol statistics before changing anything. Very old devices and some "
                 "payment terminals may still negotiate the old version."),
            Step("2. Disable at the edge.",
                 "Turn off the deprecated versions in the CDN or server TLS profile, leaving TLS 1.2 and 1.3 "
                 "enabled, and re-test from outside."),
        ],
        verify=CodeBlock("TEST A SINGLE PROTOCOL", "BASH + OPENSSL", [
            f"openssl s_client -connect {result.domain}:443 -tls1_1 \\",
            f"  -servername {result.domain} </dev/null",
        ]),
        done_when=(
            "Only TLS 1.2 and TLS 1.3 negotiate successfully, the site still loads for your customers, "
            "and the host has the previous profile saved for rollback."
        ),
        refs=[Ref("TLS 1.2: RFC 5246"), Ref("TLS 1.3: RFC 8446")],
    )


def _action_dnssec(result: FullScanResult) -> Action | None:
    findings = _dns_findings(result, "DNSSEC", "DS record")
    if not findings:
        return None
    return Action(
        key="dnssec",
        band=BAND_NEXT_WINDOW,
        owner=OWNER_DNS,
        headline="Ask your DNS provider about DNSSEC",
        brief=(
            "Your DNS answers are not signed, so a forged response cannot be detected by a resolver. "
            "This is a registrar and DNS provider change."
        ),
        section_owner="DNS PROVIDER + REGISTRAR",
        topic="DNS",
        unit_title="Zone signing",
        detail_title="Sign the zone",
        detail_kicker=f"DNSSEC: {_severity_word(findings[0].severity)} priority / Source: DNS lookup",
        detail_intro=(
            "DNSSEC requires the DNS provider to sign the zone and the registrar to publish the matching "
            "DS record. Mis-sequencing those two steps takes a domain offline, so follow the provider's order."
        ),
        observed=CodeBlock("SIGNING STATE", "CHECK AND RESULT", [f"{f.check}: {f.status}" for f in findings[:4]]),
        steps=[
            Step("1. Confirm both parties support it.",
                 "Ask the DNS provider and the registrar to confirm DNSSEC support before starting. If either "
                 "does not, this is not a change to attempt."),
            Step("2. Enable in the provider's order.",
                 findings[0].remediation or "Sign the zone at the DNS provider, then publish the DS record at the registrar."),
        ],
        verify=CodeBlock("CHECK FOR SIGNED ANSWERS", "SHELL WITH DIG", [
            f"dig +dnssec +short A {result.domain}",
            f"dig +short DS {result.domain}",
        ]),
        done_when=(
            "The zone is signed, the DS record is published at the registrar, and validating resolvers "
            "return answers for the domain without SERVFAIL."
        ),
        refs=[Ref("DNSSEC: RFC 9364")],
    )


def _action_info_leak(result: FullScanResult) -> Action | None:
    leaks = result.headers.information_leaks
    if not leaks:
        return None
    return Action(
        key="info_leak",
        band=BAND_NEXT_WINDOW,
        owner=OWNER_DEV,
        headline="Stop advertising your software versions",
        brief=(
            "Response headers name the software and version your site runs. It is low risk on its own, "
            "and it is a short server configuration change."
        ),
        section_owner="WEB DEVELOPER + HOST",
        topic="HEADERS",
        unit_title="Version banners",
        detail_title="Remove the version banners",
        detail_kicker=f"Information disclosure: {_severity_word(leaks[0].severity)} priority / Headers: {len(leaks)}",
        detail_intro=(
            "Version banners do not create a vulnerability. They shorten the work of anyone scanning for "
            "a version with a known issue, which is reason enough to remove them."
        ),
        observed=CodeBlock("HEADERS AS RECEIVED", "HEADER AND VALUE", [f"{f.header}: {f.value}" for f in leaks[:5]]),
        steps=[
            Step("1. Suppress at the server.",
                 leaks[0].remediation or "Disable the server signature and remove framework version headers in the web server configuration."),
            Step("2. Keep patching regardless.",
                 "Hiding the version is not a substitute for updating it. Confirm the software behind these "
                 "headers is on a supported release."),
        ],
        verify=CodeBlock("RECHECK THE RESPONSE", "SHELL WITH CURL", [
            f"curl -sI https://{result.domain}/ | grep -iE 'server|x-powered-by'",
        ]),
        done_when="The headers are absent from every response and the software behind them is on a supported release.",
        refs=[Ref("OWASP: Fingerprint Web Server")],
    )


# Priority order. The first three that fire become actions 01, 02 and 03.
_BUILDERS = (
    _action_secrets,
    _action_exposure,
    _action_checkout,
    _action_email,
    _action_certificate,
    _action_dns_hijack,
    _action_headers,
    _action_tls,
    _action_caa,
    _action_dnssec,
    _action_info_leak,
)

MAX_ACTIONS = 3


# ---------------------------------------------------------------------------
# Evidence coverage
#
# A scanner that returned nothing is not a clean result. Each row states what
# the scan can support; any incomplete row withholds the overall rating.
# ---------------------------------------------------------------------------

def _evidence_rows(result: FullScanResult) -> list[EvidenceRow]:
    rows: list[EvidenceRow] = []

    # DNS + email. State the policy that was read, not just the record count:
    # the reader needs to see the evidence behind the finding.
    dns_issues = [f for f in result.dns.findings if f.status in ("fail", "warn")]
    if not result.dns.records:
        rows.append(EvidenceRow("DNS + email", "No DNS records were returned. The lookups did not complete.", False))
    else:
        observed: list[str] = []
        dmarc = next((v for v in _txt_values(result) if "v=dmarc1" in v.lower()), None)
        policy = re.search(r"\bp=(\w+)", dmarc or "")
        observed.append(f"DMARC {policy.group(0)}" if policy else "no DMARC record")
        spf = _find_txt(result, "v=spf1")
        qualifier = re.search(r"([-~?+]all)\s*$", spf or "")
        observed.append(f"SPF {qualifier.group(1)}" if qualifier else "no SPF record")
        has_caa = any("caa" in f.check.lower() and f.status == "pass" for f in result.dns.findings)
        observed.append("CAA present" if has_caa else "no CAA reported")
        rows.append(EvidenceRow(
            "DNS + email",
            f"{'; '.join(observed)}. {len(dns_issues)} configuration "
            f"finding{'s' if len(dns_issues) != 1 else ''}.",
            True,
        ))

    # TLS / certificate
    cert = result.ssl.certificate
    if _cert_is_intercepted(result):
        if cert is not None and cert.source == "ct_log":
            note = ("The scan network intercepts TLS. Certificate details come from the public "
                    "transparency log; protocol support was not tested.")
        elif cert is not None:
            note = ("A locally trusted issuer was recorded, so the connection was intercepted. The "
                    "certificate and protocol results need independent verification.")
        else:
            note = ("The scan network intercepts TLS and no public certificate record was found, so "
                    "the certificate could not be established at all.")
        rows.append(EvidenceRow("TLS / certificate", note, False))
    elif cert is None:
        rows.append(EvidenceRow("TLS / certificate", "No certificate was returned. The handshake result cannot be assessed.", False))
    else:
        tested = [v for v in result.ssl.tls_versions if v.supported is not None]
        rows.append(EvidenceRow(
            "TLS / certificate",
            f"Leaf certificate read; expiry in {result.ssl.certificate.days_until_expiry} days. "
            f"{len(tested)} protocol version{'s' if len(tested) != 1 else ''} tested.",
            bool(tested),
        ))

    # Headers + public paths
    header_count = len(result.headers.findings)
    path_count = len(result.exposure.findings)
    if header_count == 0 or path_count == 0:
        rows.append(EvidenceRow(
            "Headers + public paths",
            f"{header_count} header result{'s' if header_count != 1 else ''} and {path_count} path result"
            f"{'s' if path_count != 1 else ''} recorded. Coverage is unresolved.",
            False,
        ))
    else:
        exposed = sum(1 for f in result.exposure.findings if f.exposed)
        rows.append(EvidenceRow(
            "Headers + public paths",
            f"{header_count} headers checked; {path_count} paths requested, {exposed} responded.",
            True,
        ))

    # Secrets + checkout
    files = result.secrets.files_scanned if result.secrets else 0
    pages = len(result.checkout_scripts.pages_scanned) if result.checkout_scripts else 0
    if files == 0 or pages == 0:
        rows.append(EvidenceRow(
            "Secrets + checkout",
            f"{files} JS file{'s' if files != 1 else ''} and {pages} checkout page{'s' if pages != 1 else ''} "
            "were read. The evidence cannot support a clean result.",
            False,
        ))
    else:
        secret_hits = len(result.secrets.findings) if result.secrets else 0
        rows.append(EvidenceRow(
            "Secrets + checkout",
            f"{files} JS files and {pages} checkout pages read; {secret_hits} credential "
            f"pattern{'s' if secret_hits != 1 else ''} matched.",
            True,
        ))

    # DNS consistency
    if not result.dns_hijack:
        rows.append(EvidenceRow("DNS consistency", "The resolver consistency module did not run.", False))
    else:
        resolvers = result.dns_hijack.resolver_results or {}
        timed_out = any(f.status == "info" and "timeout" in (f.description or "").lower() for f in result.dns_hijack.findings)
        complete = len(resolvers) >= 2 and not timed_out
        rows.append(EvidenceRow(
            "DNS consistency",
            f"{len(resolvers)} resolver result{'s' if len(resolvers) != 1 else ''} compared"
            + ("; a check timed out." if timed_out else "."),
            complete,
        ))

    # Discovery + fingerprinting
    matches = len(result.fingerprint.matches)
    subs = len(result.subdomains.subdomains) if result.subdomains else 0
    rows.append(EvidenceRow(
        "Discovery + fingerprinting",
        f"{matches} technolog{'ies' if matches != 1 else 'y'} identified; {subs} subdomain candidate"
        f"{'s' if subs != 1 else ''} checked.",
        matches > 0 or subs > 0,
    ))

    return rows


SCOPE_TEXT = (
    "This assessment uses public DNS and certificate-log lookups plus ordinary HTTPS requests, including a "
    "fixed sensitive-path list. No login, exploitation, brute force, internal-network assessment or code "
    "review was performed. Exploitability was not confirmed."
)


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------

def _start_here(actions: list[Action]) -> str:
    if not actions:
        return "Nothing to hand over yet. Read page 2 before treating this as a clean result."
    verbs = {
        "secrets": "Rotate the exposed credentials.",
        "exposure": "Close the exposed paths.",
        "checkout_scripts": "Review the checkout scripts.",
        "email_auth": "Review email protection.",
        "certificate": "Verify the certificate alert.",
        "dns_hijack": "Confirm your DNS answers.",
        "headers": "Add the missing headers.",
        "tls": "Retire the old protocols.",
        "caa": "Add CAA controls.",
        "dnssec": "Ask about DNSSEC.",
        "info_leak": "Remove the version banners.",
    }
    return " ".join(verbs.get(a.key, a.headline + ".") for a in actions[:2])


def _compact_heading(actions: list[Action]) -> tuple[str, str, str, str]:
    """Title, kicker, owner line and header topic for the condensed page."""
    bands = {a.band for a in actions}
    if BAND_VERIFY in bands and len(actions) > 1:
        title = "Verify first. Then configure."
    elif BAND_VERIFY in bands:
        title = "Verify before you change anything."
    elif bands == {BAND_NEXT_WINDOW}:
        title = "Plan these for the next window."
    elif len(actions) == 1:
        title = actions[0].detail_title
    else:
        title = "Two more changes to hand over."

    kicker = " / ".join(a.detail_kicker.split(" / ")[0] for a in actions)

    owner_parts: list[str] = []
    for action in actions:
        for part in action.section_owner.split(" + "):
            if part not in owner_parts:
                owner_parts.append(part)
    owners = " + ".join(owner_parts[:2])

    topics = list(dict.fromkeys(a.topic for a in actions))
    return title, kicker, owners, " + ".join(topics[:2])


def build_action_plan(result: FullScanResult, client_name: str = "") -> ActionPlan:
    actions: list[Action] = []
    for builder in _BUILDERS:
        if len(actions) >= MAX_ACTIONS:
            break
        action = builder(result)
        if action is not None:
            actions.append(action)

    # Page layout: 1 brief, 2 first action, 3 remaining actions, 4 evidence.
    sheets: list[Sheet] = [Sheet("brief", "OWNER BRIEF", 1)]
    if actions:
        actions[0].number = "01"
        actions[0].page = 2
        sheets.append(Sheet("detail_full", f"DEVELOPER DETAIL / {actions[0].topic}", 2))
    rest = actions[1:]
    if rest:
        for index, action in enumerate(rest, start=2):
            action.number = f"{index:02d}"
            action.page = len(sheets) + 1
        compact_title, compact_kicker, owners, compact_topic = _compact_heading(rest)
        sheets.append(Sheet(
            "detail_compact",
            f"DEVELOPER DETAIL / {compact_topic}",
            len(sheets) + 1,
            rest,
            title=compact_title,
            kicker=compact_kicker,
            section_owner=owners,
        ))
    sheets.append(Sheet("evidence", "EVIDENCE + HANDOFF", len(sheets) + 1))

    if actions:
        sheets[1].actions = [actions[0]]

    rows = _evidence_rows(result)
    incomplete = [row for row in rows if not row.complete]
    security_score = max(0, 100 - result.overall_risk_score)

    if incomplete:
        areas = ", ".join(row.area for row in incomplete)
        withheld_reason = (
            f"The scan scored {security_score}/100. This report withholds an overall rating because the "
            f"evidence is incomplete for {areas}. A missing result is not a pass."
        )
    else:
        withheld_reason = (
            f"Every area below returned usable evidence, so this report issues an overall rating of "
            f"{security_score}/100 for the checks described in the scope."
        )

    try:
        scan_date = datetime.fromisoformat(result.scan_timestamp.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        scan_date = datetime.now(timezone.utc)

    return ActionPlan(
        domain=result.domain,
        client_name=client_name,
        scan_date=scan_date.strftime("%d %b %Y"),
        security_score=security_score,
        rating_withheld=bool(incomplete),
        withheld_reason=withheld_reason,
        start_here=_start_here(actions),
        actions=actions,
        evidence_rows=rows,
        scope=SCOPE_TEXT,
        sheets=sheets,
        page_total=len(sheets),
    )
