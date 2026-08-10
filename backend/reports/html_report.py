"""
Business report generator.

Takes a FullScanResult and produces a professional HTML report (and
optionally a PDF via WeasyPrint) suitable for sending to clients.
"""

from __future__ import annotations
from pathlib import Path
from datetime import datetime, timezone
from jinja2 import Environment, FileSystemLoader
from models.scan import FullScanResult

TEMPLATE_DIR = Path(__file__).parent / "templates"
_jinja = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)

# ---------------------------------------------------------------------------
# Business language mappings
# ---------------------------------------------------------------------------

_BUSINESS_IMPACT: dict[str, str] = {
    # Headers
    "Content-Security-Policy": (
        "Your website has no content security rules. Attackers can inject malicious "
        "scripts into your pages to steal customer login credentials, payment data, or "
        "hijack user sessions. This technique is known as Cross-Site Scripting (XSS)."
    ),
    "Strict-Transport-Security": (
        "Visitors may be silently redirected to an unencrypted version of your site. "
        "Anyone on the same network (e.g. a coffee shop or hotel WiFi) can intercept "
        "and read everything your customers send to you."
    ),
    "X-Frame-Options": (
        "Your website can be embedded invisibly inside another page. Attackers use this "
        "technique, called clickjacking, to trick your customers into clicking buttons "
        "they cannot see, such as authorising payments or changing account settings."
    ),
    "X-Content-Type-Options": (
        "Browsers may misinterpret files served by your website and execute them as a "
        "different type than intended. This can allow attackers to run malicious scripts "
        "through uploaded files such as images or documents."
    ),
    "Referrer-Policy": (
        "When a user clicks a link from your site to an external page, their browser may "
        "send the full URL of the page they were on, which can leak internal paths, "
        "search terms, or session tokens to third parties."
    ),
    "Permissions-Policy": (
        "Your website does not restrict which browser features third-party scripts can "
        "access. Injected advertising or analytics code could silently access your "
        "customers' camera, microphone, or location."
    ),
    # DNS
    "SPF": (
        "Anyone can send emails that appear to come from your domain. Criminals can "
        "impersonate your business to trick your customers into revealing passwords, "
        "making fraudulent payments, or installing malware. This directly damages your brand."
    ),
    "DMARC": (
        "Your domain has no email fraud policy, so receiving mail servers have no "
        "instruction on what to do with forged emails pretending to be from you. "
        "Phishing campaigns using your domain name are undetectable by email providers."
    ),
    "CAA": (
        "Any certificate authority in the world can issue a security certificate for "
        "your domain without your knowledge or consent. A compromised CA could allow "
        "attackers to create a fraudulent copy of your website that appears legitimate."
    ),
    "DNSSEC": (
        "Your DNS responses are not cryptographically signed. An attacker with access "
        "to network infrastructure could forge DNS responses and silently redirect your "
        "visitors to a malicious server."
    ),
    # SSL
    "Self-signed certificate": (
        "Your website uses an untrusted security certificate. Every visitor sees a "
        "red browser warning saying your site is 'not secure', causing most to leave "
        "immediately. This severely damages customer trust and conversions."
    ),
    "Certificate expiry": (
        "Your website's security certificate has expired or is about to expire. "
        "Browsers will block access and display a full-page warning to all visitors, "
        "effectively making your website inaccessible."
    ),
    "TLS 1.0": (
        "Your server accepts TLS 1.0, an encryption protocol deprecated in 2020. "
        "It has known vulnerabilities that allow attackers to decrypt communications "
        "between your server and visitors. This also puts you in violation of PCI-DSS "
        "compliance requirements if you process payments."
    ),
    "TLS 1.1": (
        "Your server accepts TLS 1.1, which has been deprecated and lacks support for "
        "modern secure cipher suites. Regulators and payment card standards require "
        "this to be disabled."
    ),
    # Exposure
    "Git directory": (
        "The .git directory on this site appears to be publicly accessible. If confirmed, "
        "an attacker may be able to retrieve your application's source code, full commit "
        "history, and any credentials that were ever committed, even if later deleted."
    ),
    ".env file": (
        "An environment configuration file appears to be accessible at a standard location. "
        "If it contains real application settings, this could expose database passwords, "
        "API keys, and other credentials used by your application."
    ),
    "phpMyAdmin": (
        "A phpMyAdmin database management interface appears to be accessible from the "
        "internet. If unprotected, it could allow an attacker to attempt access to "
        "your database directly through the browser."
    ),
    "WordPress admin": (
        "Your WordPress administration area is publicly reachable. WordPress login pages "
        "are frequently targeted by automated tools that test common password combinations. "
        "Restricting access by IP or enabling two-factor authentication significantly "
        "reduces this risk."
    ),
    "directory listing": (
        "Your web server appears to be showing a file directory listing, allowing visitors "
        "to browse the folder structure without knowing specific file paths."
    ),
    "Symfony profiler": (
        "A Symfony debug profiler endpoint appears to be accessible. In production, this "
        "could expose request details, environment variables, and database query logs."
    ),
    "Laravel Telescope": (
        "A Laravel Telescope monitoring endpoint appears to be accessible. If enabled "
        "in production without access controls, it logs application activity that may "
        "include customer data, queries, and exception details."
    ),
    # Secrets
    "Exposed credential": (
        "An API key, password, or access token was found in your website's publicly "
        "visible code. Anyone who visits your site can copy it. Attackers use these "
        "credentials to access your cloud accounts, billing, databases, or third-party "
        "services, and often run up large bills or exfiltrate customer data."
    ),
    "AWS Access Key ID": (
        "An Amazon Web Services access key was found in your public code. This gives "
        "anyone who finds it direct access to your AWS account, including storage, "
        "compute, and potentially customer data, and may result in significant "
        "unexpected charges."
    ),
    "Stripe": (
        "A Stripe payment API key was found in your public code. This credential "
        "could be used to initiate fraudulent charges, access transaction history, "
        "or refund payments, exposing you to direct financial loss."
    ),
    "GitHub": (
        "A GitHub access token was found in your public code. This may allow an "
        "attacker to read or modify your private repositories, exfiltrate source code, "
        "or disrupt your development workflow."
    ),
    "Private Key": (
        "A cryptographic private key was found in your public code. This could be used "
        "to impersonate your server, decrypt communications, or forge signed requests."
    ),
    "Database Connection String": (
        "A database connection string containing credentials was found in your public "
        "code. This gives anyone direct access to read, modify, or delete all data "
        "in your database."
    ),
    "MongoDB Connection String": (
        "A MongoDB connection string with credentials was found in your public code. "
        "This gives anyone direct access to your database, including all stored data."
    ),
    "Google API Key": (
        "A Google API key was found in your public code. Depending on the permissions "
        "granted, this may allow abuse of Google services billed to your account."
    ),
}

_EFFORT: dict[str, str] = {
    "Content-Security-Policy": "2 to 8 hours; requires policy tuning",
    "Strict-Transport-Security": "About 30 minutes",
    "X-Frame-Options": "About 15 minutes",
    "X-Content-Type-Options": "About 15 minutes",
    "Referrer-Policy": "About 15 minutes",
    "Permissions-Policy": "About 30 minutes",
    "SPF": "About 30 minutes (DNS change)",
    "DMARC": "About 30 minutes (DNS change)",
    "CAA": "About 15 minutes (DNS change)",
    "DNSSEC": "1 to 2 hours (registrar configuration)",
    "Self-signed certificate": "About 1 hour (Let's Encrypt or Certbot)",
    "Certificate expiry": "About 30 minutes (certificate renewal)",
    "TLS 1.0": "About 30 minutes (server config change)",
    "TLS 1.1": "About 30 minutes (server config change)",
    "Exposed .git directory": "About 30 minutes (web server config)",
    "Exposed .env file": "About 30 minutes (web server config)",
    "phpMyAdmin exposed": "1 to 2 hours (restrict or remove)",
    "WordPress admin exposed": "1 to 2 hours (IP restriction or 2FA)",
    "Open directory listing": "About 15 minutes (server config)",
    "Symfony profiler exposed": "About 15 minutes (disable in production config)",
    "Laravel Telescope exposed": "About 15 minutes (environment variable)",
    "AWS Access Key": "Immediate: revoke the key in the AWS console, then remove it from code",
    "Stripe": "Immediate: roll the key in the Stripe dashboard, then remove it from code",
    "GitHub": "Immediate: revoke the token in GitHub settings, then remove it from code",
    "Private Key": "Immediate: generate a new key pair and revoke the old certificate",
    "Hardcoded Password": "Immediate: change the password and move it to an environment variable",
    "API Key": "Immediate: rotate the key with the issuing service, then remove it from code",
    "Database Connection String": "Immediate: change the database credentials and remove them from code",
    "MongoDB Connection String": "Immediate: change the database credentials and remove them from code",
    "Google API Key": "Immediate: restrict or rotate the key in Google Cloud Console",
}

_SCANNER_LABEL: dict[str, str] = {
    "headers":          "Security Headers",
    "dns":              "DNS & Email",
    "ssl":              "SSL / TLS",
    "exposure":         "Public Exposure",
    "fingerprint":      "Fingerprint",
    "secrets":          "Secret Exposure",
    "checkout_scripts": "Checkout Scripts",
    "dns_hijack":       "DNS Hijack Detection",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _business_impact(title: str, fallback_description: str) -> str:
    for key, impact in _BUSINESS_IMPACT.items():
        if key.lower() in title.lower():
            return impact
    return fallback_description


def _effort(title: str) -> str:
    for key, effort in _EFFORT.items():
        if key.lower() in title.lower():
            return effort
    return "Varies; consult your development team"


def _collect_all_findings(result: FullScanResult) -> list[dict]:
    findings: list[dict] = []

    for f in result.headers.findings:
        if f.status in ("missing", "weak"):
            findings.append({
                "title": f"Missing {f.header}" if f.status == "missing" else f"Weak {f.header}",
                "scanner": "headers",
                "severity": f.severity,
                "description": f.description,
                "remediation": f.remediation,
            })
    for f in result.headers.information_leaks:
        findings.append({
            "title": f"Server information leak via {f.header}",
            "scanner": "headers",
            "severity": f.severity,
            "description": f.description,
            "remediation": f.remediation,
        })

    for f in result.dns.findings:
        if f.status in ("fail", "warn") and f.severity:
            findings.append({
                "title": f.check,
                "scanner": "dns",
                "severity": f.severity,
                "description": f.description,
                "remediation": f.remediation or "",
            })

    for f in result.ssl.findings:
        if f.status in ("fail", "warn") and f.severity:
            findings.append({
                "title": f.check,
                "scanner": "ssl",
                "severity": f.severity,
                "description": f.description,
                "remediation": f.remediation or "",
            })

    for f in result.exposure.findings:
        if f.exposed and f.status_code == 200 and f.severity not in ("info",):
            findings.append({
                "title": f.label,
                "scanner": "exposure",
                "severity": f.severity,
                "description": f.description,
                "remediation": f.remediation or "",
                "confidence": f.confidence,
            })

    if result.secrets:
        for f in result.secrets.findings:
            findings.append({
                "title": f"Exposed {f.pattern_name}",
                "scanner": "secrets",
                "severity": f.severity,
                "description": (
                    f"A {f.pattern_name} pattern was detected in the {f.location} "
                    f"of {f.source_url}. Preview: {f.match_preview}"
                ),
                "remediation": (
                    "Remove the credential from the codebase and rotate it immediately "
                    "with the issuing service. Use environment variables for secrets."
                ),
            })

    if result.checkout_scripts:
        for f in result.checkout_scripts.findings:
            findings.append({
                "title": f.finding_id.replace("_", " ").capitalize(),
                "scanner": "checkout_scripts",
                "severity": f.severity,
                "description": f.description,
                "remediation": f.remediation or "",
            })

    if result.dns_hijack:
        for f in result.dns_hijack.findings:
            if f.status in ("fail", "warn") and f.severity:
                findings.append({
                    "title": f.check,
                    "scanner": "dns_hijack",
                    "severity": f.severity,
                    "description": f.description,
                    "remediation": f.remediation or "",
                })

    for f in findings:
        f["business_impact"] = _business_impact(f["title"], f["description"])
        f["effort"] = _effort(f["title"])
        f["scanner_label"] = _SCANNER_LABEL.get(f["scanner"], f["scanner"].title())

    rank = {"high": 3, "medium": 2, "low": 1, "info": 0}
    findings.sort(key=lambda x: rank.get(x["severity"], 0), reverse=True)
    return findings


def _executive_summary(result: FullScanResult, findings: list[dict]) -> str:
    high   = sum(1 for f in findings if f["severity"] == "high")
    medium = sum(1 for f in findings if f["severity"] == "medium")
    low    = sum(1 for f in findings if f["severity"] == "low")
    domain = result.domain
    level  = result.overall_risk_level

    if level == "critical":
        opening = (
            f"The security assessment of {domain} identified critical vulnerabilities "
            f"that require immediate attention. "
        )
    elif level == "high":
        opening = (
            f"The security assessment of {domain} identified significant security weaknesses "
            f"that should be addressed promptly. "
        )
    elif level == "medium":
        opening = (
            f"The security assessment of {domain} identified several security gaps "
            f"that represent a moderate risk to the business. "
        )
    else:
        opening = (
            f"The security assessment of {domain} found a generally acceptable security posture "
            f"with some areas for improvement. "
        )

    counts = []
    if high:
        counts.append(f"{high} high-severity issue{'s' if high > 1 else ''}")
    if medium:
        counts.append(f"{medium} medium-severity issue{'s' if medium > 1 else ''}")
    if low:
        counts.append(f"{low} low-severity issue{'s' if low > 1 else ''}")

    count_str = f"The scan detected {', '.join(counts)}. " if counts else "No significant security issues were detected. "

    if high > 0:
        close = (
            "The high-priority items must be resolved to protect customer data, prevent "
            "reputational damage, and maintain compliance with data protection requirements."
        )
    elif medium > 0:
        close = (
            "Addressing the identified issues will meaningfully reduce the organisation's "
            "exposure to common web-based threats."
        )
    else:
        close = (
            "We recommend implementing the suggested improvements to further harden the "
            "website's security posture."
        )

    return opening + count_str + close


def _glance_rows(result: FullScanResult, findings: list[dict]) -> list[dict]:
    def worst(scanner: str) -> str | None:
        sev = [f["severity"] for f in findings if f["scanner"] == scanner]
        for s in ("high", "medium", "low"):
            if s in sev:
                return s
        return None

    rows = [
        {"category": "Security Headers",      "count": result.headers.summary.get("missing", 0) + result.headers.summary.get("weak", 0), "worst": worst("headers")},
        {"category": "DNS & Email Security",  "count": result.dns.summary.get("fail", 0) + result.dns.summary.get("warn", 0),             "worst": worst("dns")},
        {"category": "SSL / TLS",             "count": result.ssl.summary.get("fail", 0) + result.ssl.summary.get("warn", 0),             "worst": worst("ssl")},
        {"category": "Public Exposure",       "count": result.exposure.summary.get("exposed", 0),                                          "worst": worst("exposure")},
    ]
    if result.secrets and result.secrets.findings:
        rows.append({
            "category": "Secret / Credential Exposure",
            "count": len(result.secrets.findings),
            "worst": worst("secrets") or result.secrets.risk_level if result.secrets.risk_level != "low" else worst("secrets"),
        })
    if result.checkout_scripts:
        rows.append({
            "category": "Checkout Scripts",
            "count": len(result.checkout_scripts.findings),
            "worst": worst("checkout_scripts"),
        })
    if result.dns_hijack:
        rows.append({
            "category": "DNS Hijack Detection",
            "count": sum(1 for f in result.dns_hijack.findings if f.status in ("fail", "warn")),
            "worst": worst("dns_hijack"),
        })
    return rows


def _roadmap(findings: list[dict]) -> dict:
    immediate, short_term, ongoing = [], [], []
    for f in findings:
        item = {"title": f["title"], "action": f["remediation"] or "See finding details above"}
        if f["severity"] == "high":
            immediate.append(item)
        elif f["severity"] == "medium":
            short_term.append(item)
        else:
            ongoing.append(item)
    return {"immediate": immediate, "short_term": short_term, "ongoing": ongoing}


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def generate_html(
    result: FullScanResult,
    client_name: str = "",
) -> str:
    all_findings = _collect_all_findings(result)

    # Present SECURITY scores (100 = clean), matching the dashboard. Scanners
    # store risk scores internally; the report must show the same number the
    # client saw on screen.
    def _fail_count(scanner: str) -> int:
        return sum(1 for f in all_findings if f["scanner"] == scanner)

    scanner_scores = [
        ("Security Headers", 100 - result.headers.risk_score,  result.headers.risk_level,  _fail_count("headers")),
        ("DNS & Email",      100 - result.dns.risk_score,      result.dns.risk_level,      _fail_count("dns")),
        ("SSL / TLS",        100 - result.ssl.risk_score,      result.ssl.risk_level,      _fail_count("ssl")),
        ("Exposure",         100 - result.exposure.risk_score, result.exposure.risk_level, _fail_count("exposure")),
    ]
    if result.secrets:
        scanner_scores.append(("Secrets", 100 - result.secrets.risk_score, result.secrets.risk_level, _fail_count("secrets")))
    if result.checkout_scripts:
        scanner_scores.append(("Checkout Scripts", 100 - result.checkout_scripts.risk_score, result.checkout_scripts.risk_level, _fail_count("checkout_scripts")))
    if result.dns_hijack:
        scanner_scores.append(("DNS Hijack", 100 - result.dns_hijack.risk_score, result.dns_hijack.risk_level, _fail_count("dns_hijack")))

    # Live subdomains for the attack surface section
    live_subdomains = []
    if result.subdomains:
        live_subdomains = [s for s in result.subdomains.subdomains if s.resolves]

    context = {
        "result":             result,
        "security_score":     max(0, 100 - result.overall_risk_score),
        "client_name":        client_name,
        "scan_date":          datetime.now(timezone.utc).strftime("%d %B %Y"),
        "executive_summary":  _executive_summary(result, all_findings),
        "scanner_scores":     scanner_scores,
        "glance_rows":        _glance_rows(result, all_findings),
        "high_findings":      [f for f in all_findings if f["severity"] == "high"],
        "medium_findings":    [f for f in all_findings if f["severity"] == "medium"],
        "low_findings":       [f for f in all_findings if f["severity"] == "low"],
        "roadmap":            _roadmap(all_findings),
        "live_subdomains":    live_subdomains,
        "all_subdomains":     result.subdomains.subdomains if result.subdomains else [],
    }

    template = _jinja.get_template("report.html")
    return template.render(**context)


def generate_pdf(result: FullScanResult, client_name: str = "") -> bytes:
    from weasyprint import HTML, CSS
    html_str = generate_html(result, client_name)
    return HTML(string=html_str, base_url=".").write_pdf()
