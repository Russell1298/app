"""
Report generator.

Aggregates the results of all scanners into a single FullScanResult.
Computes a weighted overall risk score and surfaces the highest-severity
findings as a top_findings list for quick consumption by the frontend.
"""

from models.scan import (
    HeaderScanResult, DNSScanResult, SSLScanResult,
    ExposureScanResult, FingerprintScanResult,
    SubdomainScanResult, SecretScanResult,
    FullScanResult, utc_now_iso,
)

_SCANNER_WEIGHTS = {
    "ssl":      0.28,
    "headers":  0.23,
    "dns":      0.22,
    "exposure": 0.17,
    "secrets":  0.10,
}


def _weighted_score(
    headers: HeaderScanResult,
    dns: DNSScanResult,
    ssl: SSLScanResult,
    exposure: ExposureScanResult,
    secrets: SecretScanResult | None = None,
) -> int:
    raw = (
        ssl.risk_score      * _SCANNER_WEIGHTS["ssl"] +
        headers.risk_score  * _SCANNER_WEIGHTS["headers"] +
        dns.risk_score      * _SCANNER_WEIGHTS["dns"] +
        exposure.risk_score * _SCANNER_WEIGHTS["exposure"]
    )
    if secrets:
        raw += secrets.risk_score * _SCANNER_WEIGHTS["secrets"]
    return min(100, int(raw))


def _risk_level(score: int) -> str:
    if score < 25:
        return "low"
    if score < 50:
        return "medium"
    if score < 75:
        return "high"
    return "critical"


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
        overall_risk_level=_risk_level(score),
        top_findings=_top_findings(headers, dns, ssl, exposure, secrets),
    )
