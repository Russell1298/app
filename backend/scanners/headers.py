"""
Security header scanner.

Fetches HTTP response headers for a domain and evaluates the presence,
absence, and quality of security-relevant headers.
"""

import re
import httpx
from models.scan import HeaderFinding, InformationLeakFinding, HeaderScanResult, utc_now_iso
from scoring_config import PENALTY, scanner_score, risk_level

_HSTS_MIN_AGE = 15_552_000  # 180 days per v2 spec

REQUIRED_HEADERS: list[dict] = [
    {
        "header": "content-security-policy",
        "display": "Content-Security-Policy",
        "severity": "high",
        "description": (
            "CSP is missing. Without it the browser applies no restrictions on "
            "which scripts, styles, or resources can load, leaving the site open "
            "to cross-site scripting (XSS) and data-injection attacks."
        ),
        "remediation": (
            "Add a Content-Security-Policy header. Start with \"default-src 'self'\" "
            "and broaden only what your app needs. Use a CSP evaluator to validate "
            "before deploying."
        ),
    },
    {
        "header": "strict-transport-security",
        "display": "Strict-Transport-Security",
        "severity": "high",
        "description": (
            "HSTS is missing. Without it, browsers may connect over plain HTTP "
            "enabling protocol-downgrade and man-in-the-middle attacks."
        ),
        "remediation": (
            "Add Strict-Transport-Security: max-age=31536000; includeSubDomains. "
            "Only set this after confirming HTTPS works everywhere."
        ),
    },
    {
        "header": "x-frame-options",
        "display": "X-Frame-Options",
        "severity": "medium",
        "description": (
            "X-Frame-Options is missing. Without it, the page can be embedded in "
            "an iframe on an attacker-controlled site, enabling clickjacking attacks."
        ),
        "remediation": (
            "Add X-Frame-Options: DENY (or SAMEORIGIN). "
            "Alternatively, set frame-ancestors in your CSP policy."
        ),
    },
    {
        "header": "x-content-type-options",
        "display": "X-Content-Type-Options",
        "severity": "medium",
        "description": (
            "X-Content-Type-Options is missing. Browsers may sniff the MIME type "
            "of responses and execute them as a different type than intended."
        ),
        "remediation": "Add X-Content-Type-Options: nosniff.",
    },
    {
        "header": "referrer-policy",
        "display": "Referrer-Policy",
        "severity": "low",
        "description": (
            "Referrer-Policy is missing. Browsers may send full URLs in the Referer "
            "header to third-party sites, leaking internal paths or session tokens."
        ),
        "remediation": "Add Referrer-Policy: strict-origin-when-cross-origin.",
    },
    {
        "header": "permissions-policy",
        "display": "Permissions-Policy",
        "severity": "low",
        "description": (
            "Permissions-Policy is missing. Embedded iframes or injected scripts "
            "can access browser features your site does not need."
        ),
        "remediation": "Add Permissions-Policy: camera=(), microphone=(), geolocation=()",
    },
]

LEAK_HEADERS: list[dict] = [
    {
        "header": "server",
        "severity": "low",
        "versioned_only": True,
        "description": (
            "The Server header exposes web server software and version. "
            "Attackers use this to look up known vulnerabilities for that exact version."
        ),
        "remediation": (
            "Suppress or obscure the Server header. "
            "nginx: server_tokens off; Apache: ServerTokens Prod; ServerSignature Off"
        ),
    },
    {
        "header": "x-powered-by",
        "severity": "medium",
        "versioned_only": False,
        "description": (
            "X-Powered-By exposes the application framework and version. "
            "This helps attackers target known CVEs."
        ),
        "remediation": "Remove this header. Express: app.disable('x-powered-by'); PHP: expose_php = Off",
    },
    {
        "header": "x-aspnet-version",
        "severity": "medium",
        "versioned_only": False,
        "description": "Reveals the exact ASP.NET runtime version in use.",
        "remediation": "Set <httpRuntime enableVersionHeader='false' /> in web.config",
    },
    {
        "header": "x-aspnetmvc-version",
        "severity": "low",
        "versioned_only": False,
        "description": "Reveals the ASP.NET MVC version.",
        "remediation": "Remove via MvcHandler.DisableMvcResponseHeader = true in Global.asax",
    },
]

_BONUS_HEADERS = (
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
)

_VERSION_RE = re.compile(r'\d')


def _check_hsts_value(value: str) -> HeaderFinding | None:
    lower = value.lower()
    if "max-age=" not in lower:
        return HeaderFinding(
            header="Strict-Transport-Security",
            status="weak",
            severity="high",
            value=value,
            description="HSTS header is present but missing max-age directive.",
            remediation="Set max-age to at least 15552000 (180 days).",
        )
    try:
        max_age = int(lower.split("max-age=")[1].split(";")[0].strip())
        if max_age < _HSTS_MIN_AGE:
            return HeaderFinding(
                header="Strict-Transport-Security",
                status="weak",
                severity="medium",
                value=value,
                description=f"HSTS max-age is only {max_age} seconds (less than 180 days).",
                remediation="Increase max-age to at least 15552000 (180 days).",
            )
    except (IndexError, ValueError):
        pass
    return None


async def scan_headers(domain: str) -> HeaderScanResult:
    url = f"https://{domain}"
    headers_received: dict[str, str] = {}
    fetch_error: str | None = None
    scanned_url = url

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=10.0,
            headers={"User-Agent": "SecurityHeaderScanner/1.0 (defensive assessment)"},
        ) as client:
            response = await client.get(url)
            headers_received = dict(response.headers)
            scanned_url = str(response.url)
    except httpx.ConnectError:
        try:
            url = f"http://{domain}"
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=10.0,
                headers={"User-Agent": "SecurityHeaderScanner/1.0 (defensive assessment)"},
            ) as client:
                response = await client.get(url)
                headers_received = dict(response.headers)
                scanned_url = str(response.url)
        except httpx.RequestError as e:
            fetch_error = str(e)
            scanned_url = url
    except httpx.RequestError as e:
        fetch_error = str(e)
        scanned_url = url

    if fetch_error:
        return HeaderScanResult(
            domain=domain,
            scanned_url=scanned_url,
            scan_timestamp=utc_now_iso(),
            findings=[],
            information_leaks=[],
            risk_score=0,
            risk_level="low",
            critical_triggers=[],
            summary={"error": fetch_error, "headers_checked": 0},
        )

    lower_headers = {k.lower(): v for k, v in headers_received.items()}

    csp_value = lower_headers.get("content-security-policy", "")
    csp_ro_value = lower_headers.get("content-security-policy-report-only", "")
    has_frame_ancestors = "frame-ancestors" in csp_value or "frame-ancestors" in csp_ro_value

    findings: list[HeaderFinding] = []
    information_leaks: list[InformationLeakFinding] = []
    total_penalty = 0

    for spec in REQUIRED_HEADERS:
        key = spec["header"]
        value = lower_headers.get(key)

        if value is None:
            if key == "content-security-policy" and csp_ro_value:
                findings.append(HeaderFinding(
                    header=spec["display"],
                    status="weak",
                    severity="medium",
                    value=csp_ro_value,
                    description=(
                        "Content-Security-Policy is in report-only mode. "
                        "Violations are monitored but not blocked — XSS attacks are still possible."
                    ),
                    remediation=(
                        "Switch Content-Security-Policy-Report-Only to Content-Security-Policy "
                        "once your policy is validated."
                    ),
                ))
                total_penalty += PENALTY["medium"]
            elif key == "x-frame-options" and has_frame_ancestors:
                findings.append(HeaderFinding(
                    header=spec["display"],
                    status="present",
                    severity=spec["severity"],
                    value="(via CSP frame-ancestors)",
                    description="Frame embedding is restricted via the CSP frame-ancestors directive.",
                    remediation="No action required.",
                ))
            else:
                findings.append(HeaderFinding(
                    header=spec["display"],
                    status="missing",
                    severity=spec["severity"],
                    value=None,
                    description=spec["description"],
                    remediation=spec["remediation"],
                ))
                total_penalty += PENALTY[spec["severity"]]
        else:
            weak_finding = None
            if key == "strict-transport-security":
                weak_finding = _check_hsts_value(value)

            if weak_finding:
                findings.append(weak_finding)
                total_penalty += PENALTY[weak_finding.severity]
            else:
                findings.append(HeaderFinding(
                    header=spec["display"],
                    status="present",
                    severity=spec["severity"],
                    value=value,
                    description=f"{spec['display']} is properly set.",
                    remediation="No action required.",
                ))

    for spec in LEAK_HEADERS:
        value = lower_headers.get(spec["header"])
        if value:
            if spec.get("versioned_only") and not _VERSION_RE.search(value):
                continue
            information_leaks.append(InformationLeakFinding(
                header=spec["header"],
                value=value,
                severity=spec["severity"],
                description=spec["description"],
                remediation=spec["remediation"],
            ))
            total_penalty += PENALTY[spec["severity"]]

    # Bonus credits for optional hardening headers — only when base penalty is already low
    if total_penalty <= 20:
        for bonus_header in _BONUS_HEADERS:
            if bonus_header in lower_headers:
                total_penalty = max(0, total_penalty - 3)

    risk_score = scanner_score(total_penalty, "headers")
    level = risk_level(risk_score)

    missing_count = sum(1 for f in findings if f.status == "missing")
    weak_count = sum(1 for f in findings if f.status == "weak")
    passing_count = sum(1 for f in findings if f.status == "present")

    return HeaderScanResult(
        domain=domain,
        scanned_url=scanned_url,
        scan_timestamp=utc_now_iso(),
        findings=findings,
        information_leaks=information_leaks,
        risk_score=risk_score,
        risk_level=level,
        critical_triggers=[],
        summary={
            "total_headers_checked": len(REQUIRED_HEADERS),
            "missing": missing_count,
            "weak": weak_count,
            "passing": passing_count,
            "information_leaks": len(information_leaks),
        },
    )
