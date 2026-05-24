"""
Report generator.

Aggregates the results of all scanners into a single FullScanResult.
Computes a weighted overall risk score and surfaces the highest-severity
findings as a top_findings list for quick consumption by the frontend.
"""

from models.scan import (
    HeaderScanResult, DNSScanResult, SSLScanResult,
    ExposureScanResult, FingerprintScanResult, FullScanResult, utc_now_iso,
)

# Weight each scanner by how directly its failures impact users.
# Weights do not need to sum to 1 — they scale the contribution.
_SCANNER_WEIGHTS = {
    "ssl":      0.30,
    "headers":  0.25,
    "dns":      0.25,
    "exposure": 0.20,
}


def _weighted_score(
    headers: HeaderScanResult,
    dns: DNSScanResult,
    ssl: SSLScanResult,
    exposure: ExposureScanResult,
) -> int:
    raw = (
        ssl.risk_score      * _SCANNER_WEIGHTS["ssl"] +
        headers.risk_score  * _SCANNER_WEIGHTS["headers"] +
        dns.risk_score      * _SCANNER_WEIGHTS["dns"] +
        exposure.risk_score * _SCANNER_WEIGHTS["exposure"]
    )
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
) -> list[dict]:
    """
    Collect every high/critical finding across all scanners and return
    the worst ones — capped at 10 — as simple dicts for the frontend.
    """
    candidates: list[dict] = []

    severity_rank = {"high": 3, "medium": 2, "low": 1, "info": 0}

    # Headers
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

    # DNS
    for f in dns.findings:
        if f.status in ("fail", "warn") and f.severity in ("high", "medium"):
            candidates.append({
                "scanner": "dns",
                "severity": f.severity,
                "title": f.check,
                "description": f.description,
                "remediation": f.remediation,
            })

    # SSL
    for f in ssl.findings:
        if f.status in ("fail", "warn") and f.severity in ("high", "medium"):
            candidates.append({
                "scanner": "ssl",
                "severity": f.severity,
                "title": f.check,
                "description": f.description,
                "remediation": f.remediation,
            })

    # Exposure
    for f in exposure.findings:
        if f.exposed and f.severity in ("high", "medium"):
            candidates.append({
                "scanner": "exposure",
                "severity": f.severity,
                "title": f.label,
                "description": f.description,
                "remediation": f.remediation,
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
) -> FullScanResult:
    score = _weighted_score(headers, dns, ssl, exposure)
    return FullScanResult(
        domain=domain,
        scan_timestamp=utc_now_iso(),
        headers=headers,
        dns=dns,
        ssl=ssl,
        exposure=exposure,
        fingerprint=fingerprint,
        overall_risk_score=score,
        overall_risk_level=_risk_level(score),
        top_findings=_top_findings(headers, dns, ssl, exposure),
    )
