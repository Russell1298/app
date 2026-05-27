"""
Security header scanner.

Fetches HTTP response headers for a domain and evaluates the presence,
absence, and quality of security-relevant headers. Only performs a
passive GET request — no exploitation or intrusion of any kind.
"""

import httpx
from models.scan import HeaderFinding, InformationLeakFinding, HeaderScanResult, utc_now_iso

# Headers we require, with scoring weight and guidance
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
            "Add a Content-Security-Policy header. Start with a restrictive policy "
            "such as \"default-src 'self'\" and broaden only what your app needs. "
            "Use a CSP evaluator tool to validate the policy before deploying."
        ),
        "weight": 25,
    },
    {
        "header": "strict-transport-security",
        "display": "Strict-Transport-Security",
        "severity": "high",
        "description": (
            "HSTS is missing. Without it, browsers may connect over plain HTTP "
            "even for a site that supports HTTPS, enabling protocol-downgrade and "
            "man-in-the-middle attacks."
        ),
        "remediation": (
            "Add Strict-Transport-Security: max-age=31536000; includeSubDomains. "
            "Only set this after confirming HTTPS works everywhere — it cannot "
            "easily be undone once cached by a browser."
        ),
        "weight": 20,
    },
    {
        "header": "x-frame-options",
        "display": "X-Frame-Options",
        "severity": "medium",
        "description": (
            "X-Frame-Options is missing. Without it, the page can be embedded in "
            "an iframe on an attacker-controlled site, enabling clickjacking attacks "
            "that trick users into performing unintended actions."
        ),
        "remediation": (
            "Add X-Frame-Options: DENY (or SAMEORIGIN if you embed your own pages). "
            "Alternatively, set frame-ancestors in your CSP policy."
        ),
        "weight": 15,
    },
    {
        "header": "x-content-type-options",
        "display": "X-Content-Type-Options",
        "severity": "medium",
        "description": (
            "X-Content-Type-Options is missing. Browsers may sniff the MIME type of "
            "responses and execute them as a different type than intended, which can "
            "be exploited to run scripts disguised as other content."
        ),
        "remediation": (
            "Add X-Content-Type-Options: nosniff. This is a one-line change with no "
            "side effects for correctly configured sites."
        ),
        "weight": 10,
    },
    {
        "header": "referrer-policy",
        "display": "Referrer-Policy",
        "severity": "low",
        "description": (
            "Referrer-Policy is missing. By default, browsers may send the full URL "
            "in the Referer header to third-party sites, leaking internal paths, "
            "query parameters, or session tokens."
        ),
        "remediation": (
            "Add Referrer-Policy: strict-origin-when-cross-origin. This balances "
            "analytics compatibility with privacy."
        ),
        "weight": 5,
    },
    {
        "header": "permissions-policy",
        "display": "Permissions-Policy",
        "severity": "low",
        "description": (
            "Permissions-Policy is missing. Without it, embedded iframes or injected "
            "scripts can access browser features (camera, microphone, geolocation) "
            "that your site does not need."
        ),
        "remediation": (
            "Add Permissions-Policy and disable features your app does not use, "
            "e.g. Permissions-Policy: camera=(), microphone=(), geolocation=()"
        ),
        "weight": 5,
    },
]

# Headers that reveal server internals — their presence is a finding
LEAK_HEADERS: list[dict] = [
    {
        "header": "server",
        "severity": "low",
        "description": (
            "The Server header exposes the web server software and version. "
            "Attackers use this to look up known vulnerabilities for that exact version."
        ),
        "remediation": (
            "Configure your web server to suppress or obscure the Server header. "
            "In nginx: server_tokens off; In Apache: ServerTokens Prod; ServerSignature Off"
        ),
    },
    {
        "header": "x-powered-by",
        "severity": "medium",
        "description": (
            "X-Powered-By exposes the application framework and version "
            "(e.g. PHP/8.1, Express). This helps attackers target known CVEs."
        ),
        "remediation": (
            "Remove this header. In Express: app.disable('x-powered-by'); "
            "In PHP: expose_php = Off in php.ini"
        ),
    },
    {
        "header": "x-aspnet-version",
        "severity": "medium",
        "description": "Reveals the exact ASP.NET runtime version in use.",
        "remediation": "Set <httpRuntime enableVersionHeader='false' /> in web.config",
    },
    {
        "header": "x-aspnetmvc-version",
        "severity": "low",
        "description": "Reveals the ASP.NET MVC version.",
        "remediation": "Remove via MvcHandler.DisableMvcResponseHeader = true in Global.asax",
    },
]

SEVERITY_WEIGHT = {"low": 1, "medium": 2, "high": 3}


def _check_hsts_value(value: str) -> HeaderFinding | None:
    """Return a weak finding if HSTS max-age is too short."""
    lower = value.lower()
    if "max-age=" not in lower:
        return HeaderFinding(
            header="Strict-Transport-Security",
            status="weak",
            severity="high",
            value=value,
            description="HSTS header is present but missing max-age directive.",
            remediation="Set max-age to at least 31536000 (one year).",
        )
    try:
        max_age = int(lower.split("max-age=")[1].split(";")[0].strip())
        if max_age < 31536000:
            return HeaderFinding(
                header="Strict-Transport-Security",
                status="weak",
                severity="medium",
                value=value,
                description=f"HSTS max-age is only {max_age} seconds (less than one year).",
                remediation="Increase max-age to at least 31536000.",
            )
    except (IndexError, ValueError):
        pass
    return None


async def scan_headers(domain: str) -> HeaderScanResult:
    """
    Perform a passive HTTP GET to the domain and evaluate security headers.
    Returns a structured report — no authentication, no exploitation.
    """
    url = f"https://{domain}"
    headers_received: dict[str, str] = {}
    fetch_error: str | None = None

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
        # Fall back to HTTP if HTTPS is not available
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

    findings: list[HeaderFinding] = []
    information_leaks: list[InformationLeakFinding] = []
    total_penalty = 0
    max_penalty = sum(h["weight"] for h in REQUIRED_HEADERS)

    if fetch_error:
        return HeaderScanResult(
            domain=domain,
            scanned_url=scanned_url,
            scan_timestamp=utc_now_iso(),
            findings=[],
            information_leaks=[],
            risk_score=0,
            risk_level="low",
            summary={"error": fetch_error, "headers_checked": 0},
        )

    lower_headers = {k.lower(): v for k, v in headers_received.items()}

    # Pre-compute CSP values for cross-header checks
    csp_value = lower_headers.get("content-security-policy", "")
    csp_ro_value = lower_headers.get("content-security-policy-report-only", "")
    has_frame_ancestors = "frame-ancestors" in csp_value or "frame-ancestors" in csp_ro_value

    # Evaluate required security headers
    for spec in REQUIRED_HEADERS:
        key = spec["header"]
        value = lower_headers.get(key)

        if value is None:
            if key == "content-security-policy" and csp_ro_value:
                # Report-only CSP present: give partial credit, downgrade severity
                findings.append(
                    HeaderFinding(
                        header=spec["display"],
                        status="weak",
                        severity="medium",
                        value=csp_ro_value,
                        description=(
                            "Content-Security-Policy is in report-only mode. "
                            "Violations are monitored but not blocked — XSS and "
                            "data-injection attacks are still possible."
                        ),
                        remediation=(
                            "Switch Content-Security-Policy-Report-Only to "
                            "Content-Security-Policy once your policy is validated."
                        ),
                    )
                )
                total_penalty += spec["weight"] // 2
            elif key == "x-frame-options" and has_frame_ancestors:
                # CSP frame-ancestors is the modern equivalent — no penalty
                findings.append(
                    HeaderFinding(
                        header=spec["display"],
                        status="present",
                        severity=spec["severity"],
                        value="(via CSP frame-ancestors)",
                        description="Frame embedding is restricted via the Content-Security-Policy frame-ancestors directive.",
                        remediation="No action required.",
                    )
                )
            else:
                findings.append(
                    HeaderFinding(
                        header=spec["display"],
                        status="missing",
                        severity=spec["severity"],
                        value=None,
                        description=spec["description"],
                        remediation=spec["remediation"],
                    )
                )
                total_penalty += spec["weight"]
        else:
            # Header present — check for known weak configurations
            weak_finding = None
            if key == "strict-transport-security":
                weak_finding = _check_hsts_value(value)

            if weak_finding:
                findings.append(weak_finding)
                total_penalty += spec["weight"] // 2
            else:
                findings.append(
                    HeaderFinding(
                        header=spec["display"],
                        status="present",
                        severity=spec["severity"],
                        value=value,
                        description=f"{spec['display']} is properly set.",
                        remediation="No action required.",
                    )
                )

    # Check for information-leaking headers
    for spec in LEAK_HEADERS:
        value = lower_headers.get(spec["header"])
        if value:
            information_leaks.append(
                InformationLeakFinding(
                    header=spec["header"],
                    value=value,
                    severity=spec["severity"],
                    description=spec["description"],
                    remediation=spec["remediation"],
                )
            )
            total_penalty += SEVERITY_WEIGHT[spec["severity"]] * 3

    # Risk score: 0 = no issues, 100 = worst possible
    adjusted_max = max_penalty + (len(LEAK_HEADERS) * 3 * 2)  # assume med severity leaks
    raw_score = min(100, int((total_penalty / adjusted_max) * 100))

    if raw_score < 25:
        risk_level = "low"
    elif raw_score < 50:
        risk_level = "medium"
    elif raw_score < 75:
        risk_level = "high"
    else:
        risk_level = "critical"

    missing_count = sum(1 for f in findings if f.status == "missing")
    weak_count = sum(1 for f in findings if f.status == "weak")
    passing_count = sum(1 for f in findings if f.status == "present")

    summary = {
        "total_headers_checked": len(REQUIRED_HEADERS),
        "missing": missing_count,
        "weak": weak_count,
        "passing": passing_count,
        "information_leaks": len(information_leaks),
    }

    return HeaderScanResult(
        domain=domain,
        scanned_url=scanned_url,
        scan_timestamp=utc_now_iso(),
        findings=findings,
        information_leaks=information_leaks,
        risk_score=raw_score,
        risk_level=risk_level,
        summary=summary,
    )
