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
    FullScanResult, utc_now_iso,
)
from scoring_config import SCANNER_WEIGHTS, CRITICAL_CAPS, risk_level


def _weighted_score(
    headers: HeaderScanResult,
    dns: DNSScanResult,
    ssl: SSLScanResult,
    exposure: ExposureScanResult,
    secrets: SecretScanResult | None = None,
) -> int:
    raw = (
        ssl.risk_score      * SCANNER_WEIGHTS["ssl"] +
        headers.risk_score  * SCANNER_WEIGHTS["headers"] +
        dns.risk_score      * SCANNER_WEIGHTS["dns"] +
        exposure.risk_score * SCANNER_WEIGHTS["exposure"]
    )
    if secrets:
        raw += secrets.risk_score * SCANNER_WEIGHTS["secrets"]
    score = min(100, round(raw))

    # Collect all critical triggers emitted by scanners
    all_triggers: set[str] = set()
    for result in [headers, dns, ssl, exposure]:
        all_triggers.update(result.critical_triggers)
    if secrets:
        all_triggers.update(secrets.critical_triggers)

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
            })
    for f in headers.information_leaks:
        if f.severity in ("high", "medium"):
            candidates.append({
                "scanner": "headers",
                "severity": f.severity,
                "title": f"Information leak: {f.header}",
                "description": f.description,
                "remediation": f.remediation,
            })

    for f in dns.findings:
        if f.status in ("fail", "warn") and f.severity in ("high", "medium"):
            candidates.append({
                "scanner": "dns",
                "severity": f.severity,
                "title": f.check,
                "description": f.description,
                "remediation": f.remediation,
            })

    for f in ssl.findings:
        if f.status in ("fail", "warn") and f.severity in ("high", "medium"):
            candidates.append({
                "scanner": "ssl",
                "severity": f.severity,
                "title": f.check,
                "description": f.description,
                "remediation": f.remediation,
            })

    for f in exposure.findings:
        if f.exposed and f.severity in ("high", "medium"):
            candidates.append({
                "scanner": "exposure",
                "severity": f.severity,
                "title": f.label,
                "description": f.description,
                "remediation": f.remediation,
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
                        "Remove the credential from the codebase immediately and rotate it "
                        "with the issuing service. Never commit secrets to client-facing code."
                    ),
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
) -> FullScanResult:
    score = _weighted_score(headers, dns, ssl, exposure, secrets)
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
        overall_risk_score=score,
        overall_risk_level=risk_level(score),
        top_findings=_top_findings(headers, dns, ssl, exposure, secrets),
    )
