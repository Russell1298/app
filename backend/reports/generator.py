"""
Report generator.

Aggregates scanner results into a FullScanResult. Applies the v2 weighted
overall risk score, then applies critical-fail floor caps as a post-step
(not baked into individual scanners). This is what makes the score
business-defensible: a site leaking .env cannot score 50 due to a clean cert.
"""

from models.scan import (
    HeaderScanResult, DNSScanResult, SSLScanResult,
    ExposureScanResult, FingerprintScanResult,
    SubdomainScanResult, SecretScanResult,
    CheckoutScriptScanResult, DNSHijackScanResult,
    FullScanResult, utc_now_iso,
)
from scoring_config import SCANNER_WEIGHTS, CRITICAL_CAPS, risk_level


def _weighted_score(
    headers: HeaderScanResult,
    dns: DNSScanResult,
    ssl: SSLScanResult,
    exposure: ExposureScanResult,
    secrets: SecretScanResult | None = None,
    checkout_scripts: CheckoutScriptScanResult | None = None,
    dns_hijack: DNSHijackScanResult | None = None,
) -> int:
    raw = (
        ssl.risk_score      * SCANNER_WEIGHTS["ssl"] +
        headers.risk_score  * SCANNER_WEIGHTS["headers"] +
        dns.risk_score      * SCANNER_WEIGHTS["dns"] +
        exposure.risk_score * SCANNER_WEIGHTS["exposure"]
    )
    if secrets:
        raw += secrets.risk_score * SCANNER_WEIGHTS["secrets"]
    if checkout_scripts:
        raw += checkout_scripts.risk_score * SCANNER_WEIGHTS["checkout_scripts"]
    if dns_hijack:
        raw += dns_hijack.risk_score * SCANNER_WEIGHTS["dns_hijack"]
    score = min(100, round(raw))

    # Collect all critical triggers emitted by scanners
    all_triggers: set[str] = set()
    for result in [headers, dns, ssl, exposure]:
        all_triggers.update(result.critical_triggers)
    for optional in [secrets, checkout_scripts, dns_hijack]:
        if optional:
            all_triggers.update(optional.critical_triggers)

    # Apply floor caps: certain findings cannot be averaged away by good hygiene elsewhere
    for trigger, floor in CRITICAL_CAPS.items():
        if trigger in all_triggers:
            score = max(score, floor)

    return min(100, score)


def _top_findings(
    headers: HeaderScanResult,
    dns: DNSScanResult,
    ssl: SSLScanResult,
    exposure: ExposureScanResult,
    secrets: SecretScanResult | None = None,
    checkout_scripts: CheckoutScriptScanResult | None = None,
    dns_hijack: DNSHijackScanResult | None = None,
) -> list[dict]:
    candidates: list[dict] = []
    severity_rank = {"high": 3, "medium": 2, "low": 1, "info": 0}

    for f in headers.findings:
        if f.status == "missing" and f.severity in ("high", "medium"):
            candidates.append({
                "scanner": "headers",
                "severity": f.severity,
                "title": f"Missing {f.header}",
                "description": f.description,
                "remediation": f.remediation,
                "evidence": f"HTTP response did not include the {f.header} header.",
            })
    for f in headers.information_leaks:
        if f.severity in ("high", "medium"):
            candidates.append({
                "scanner": "headers",
                "severity": f.severity,
                "title": f"Information leak: {f.header}",
                "description": f.description,
                "remediation": f.remediation,
                "evidence": f"{f.header}: {f.value}",
            })

    txt_records = next((r.values for r in dns.records if r.record_type == "TXT"), [])
    for f in dns.findings:
        if f.status in ("fail", "warn") and f.severity in ("high", "medium"):
            if "SPF" in f.check and txt_records:
                dns_evidence = f"TXT records found:\n" + "\n".join(f"  {v}" for v in txt_records[:3])
            elif "SPF" in f.check:
                dns_evidence = "No TXT records found for this domain."
            elif "DMARC" in f.check:
                dmarc = next((r for r in dns.records if r.record_type == "TXT" and any("dmarc" in v.lower() for v in r.values)), None)
                dns_evidence = f"_dmarc lookup returned: {dmarc.values[0]}" if dmarc else "No DMARC record found at _dmarc." + headers.domain
            else:
                dns_evidence = f"DNS check '{f.check}' status: {f.status}"
            candidates.append({
                "scanner": "dns",
                "severity": f.severity,
                "title": f.check,
                "description": f.description,
                "remediation": f.remediation,
                "evidence": dns_evidence,
            })

    cert = ssl.certificate
    tls_supported = [v.version for v in ssl.tls_versions if v.supported]
    for f in ssl.findings:
        if f.status in ("fail", "warn") and f.severity in ("high", "medium"):
            if cert and ("expir" in f.check.lower() or "certif" in f.check.lower() or "self" in f.check.lower()):
                ssl_evidence = (
                    f"Subject: {cert.subject}\n"
                    f"Issuer: {cert.issuer}\n"
                    f"Expires: {cert.not_after} ({cert.days_until_expiry} days)"
                )
            elif tls_supported:
                ssl_evidence = f"Supported TLS versions: {', '.join(tls_supported)}"
            else:
                ssl_evidence = f"SSL check '{f.check}' status: {f.status}"
            candidates.append({
                "scanner": "ssl",
                "severity": f.severity,
                "title": f.check,
                "description": f.description,
                "remediation": f.remediation,
                "evidence": ssl_evidence,
            })

    for f in exposure.findings:
        if f.exposed and f.severity in ("high", "medium"):
            candidates.append({
                "scanner": "exposure",
                "severity": f.severity,
                "title": f.label,
                "description": f.description,
                "remediation": f.remediation,
                "evidence": f"GET /{f.path.lstrip('/')} → HTTP {f.status_code} (publicly accessible)",
            })

    if secrets:
        for f in secrets.findings:
            if f.severity in ("high", "medium"):
                candidates.append({
                    "scanner": "secrets",
                    "severity": f.severity,
                    "title": f"Exposed credential: {f.pattern_name}",
                    "description": (
                        f"A {f.pattern_name} was found in the {f.location} of {f.source_url}. "
                        "This credential is publicly visible to anyone who visits the site."
                    ),
                    "remediation": (
                        "Remove this credential from your website's code right away, then "
                        "change it (rotate it) with the service it belongs to; assume it has "
                        "already been seen. Keep secrets in server-side environment variables, "
                        "out of any code that ships to the browser."
                    ),
                    "evidence": f"URL: {f.source_url}\nLocation: {f.location}\nPreview: {f.match_preview}",
                })

    if checkout_scripts:
        for f in checkout_scripts.findings:
            if f.severity in ("high", "medium"):
                candidates.append({
                    "scanner": "checkout_scripts",
                    "severity": f.severity,
                    "title": f.finding_id.replace("_", " ").title(),
                    "description": f.description,
                    "remediation": f.remediation,
                    "evidence": f.evidence,
                })

    if dns_hijack:
        for f in dns_hijack.findings:
            if f.status in ("fail", "warn") and f.severity in ("high", "medium"):
                candidates.append({
                    "scanner": "dns_hijack",
                    "severity": f.severity,
                    "title": f.check,
                    "description": f.description,
                    "remediation": f.remediation,
                    "evidence": f"DNS hijack check '{f.check}' status: {f.status}",
                })

    candidates.sort(key=lambda c: severity_rank.get(c["severity"], 0), reverse=True)
    return candidates[:10]


def build_full_report(
    domain: str,
    headers: HeaderScanResult,
    dns: DNSScanResult,
    ssl: SSLScanResult,
    exposure: ExposureScanResult,
    fingerprint: FingerprintScanResult,
    subdomains: SubdomainScanResult | None = None,
    secrets: SecretScanResult | None = None,
    checkout_scripts: CheckoutScriptScanResult | None = None,
    dns_hijack: DNSHijackScanResult | None = None,
) -> FullScanResult:
    score = _weighted_score(headers, dns, ssl, exposure, secrets, checkout_scripts, dns_hijack)
    return FullScanResult(
        domain=domain,
        scan_timestamp=utc_now_iso(),
        headers=headers,
        dns=dns,
        ssl=ssl,
        exposure=exposure,
        fingerprint=fingerprint,
        subdomains=subdomains,
        secrets=secrets,
        checkout_scripts=checkout_scripts,
        dns_hijack=dns_hijack,
        overall_risk_score=score,
        overall_risk_level=risk_level(score),
        top_findings=_top_findings(headers, dns, ssl, exposure, secrets, checkout_scripts, dns_hijack),
    )
