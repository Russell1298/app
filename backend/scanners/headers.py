"""
Security header scanner.

Fetches HTTP response headers for a domain and evaluates the presence,
absence, and quality of security-relevant headers.
"""

import re
import httpx
from models.scan import HeaderFinding, InformationLeakFinding, HeaderScanResult, utc_now_iso
from scanners import SCAN_HEADERS
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
            "Add a Content-Security-Policy header so the browser only loads scripts "
            "and content you trust. On WordPress, a security plugin like Wordfence can "
            "set it for you. On your own Nginx or Apache server, add the header starting "
            "with \"default-src 'self'\" and allow more only where your site needs it. "
            "Turn it on in report-only mode first to see what it would block."
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
            "Turn on HSTS so browsers always use HTTPS for your site. Add this response "
            "header: Strict-Transport-Security: max-age=31536000; includeSubDomains. "
            "Most hosts and CDNs (like Cloudflare) have a one-click HSTS toggle. Only "
            "enable it once HTTPS works everywhere on your site."
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
            "Stop other sites from loading your pages inside a hidden frame (a trick "
            "used for clickjacking). Add the header X-Frame-Options: SAMEORIGIN. If you "
            "use Cloudflare or a security plugin, look for a 'clickjacking' or 'frame "
            "options' setting."
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
        "remediation": (
            "Add the header X-Content-Type-Options: nosniff. This stops browsers from "
            "guessing file types, which can turn a harmless upload into a running script. "
            "It is one line in your server or CDN config."
        ),
    },
    {
        "header": "referrer-policy",
        "display": "Referrer-Policy",
        "severity": "low",
        "description": (
            "Referrer-Policy is missing. Browsers may send full URLs in the Referer "
            "header to third-party sites, leaking internal paths or session tokens."
        ),
        "remediation": (
            "Add the header Referrer-Policy: strict-origin-when-cross-origin. This keeps "
            "your full page URLs from leaking to other websites visitors click through to. "
            "This applies to almost every site."
        ),
    },
    {
        "header": "permissions-policy",
        "display": "Permissions-Policy",
        "severity": "low",
        "description": (
            "Permissions-Policy is missing. Embedded iframes or injected scripts "
            "can access browser features your site does not need."
        ),
        "remediation": (
            "Add the header Permissions-Policy: camera=(), microphone=(), geolocation=() "
            "to block access to the camera, mic, and location unless your site "
            "uses them. Adjust the list if you do need one of these."
        ),
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
            "Your server is announcing its exact software and version, which tells "
            "attackers which known bugs to try. Hide it: on Nginx add 'server_tokens off;', "
            "on Apache set 'ServerTokens Prod' and 'ServerSignature Off', then reload the server."
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
        "remediation": (
            "Your site is broadcasting which framework it runs (the X-Powered-By header), "
            "making it easier to target. Remove it: in Express use app.disable('x-powered-by'), "
            "in PHP set expose_php = Off in php.ini. Cloudflare can also strip this header for you."
        ),
    },
    {
        "header": "x-aspnet-version",
        "severity": "medium",
        "versioned_only": False,
        "description": "Reveals the exact ASP.NET runtime version in use.",
        "remediation": (
            "Your site reveals the exact ASP.NET version. Hide it by adding "
            "<httpRuntime enableVersionHeader='false' /> to your web.config, then restart the app."
        ),
    },
    {
        "header": "x-aspnetmvc-version",
        "severity": "low",
        "versioned_only": False,
        "description": "Reveals the ASP.NET MVC version.",
        "remediation": (
            "Your site reveals the ASP.NET MVC version. Remove it by adding "
            "MvcHandler.DisableMvcResponseHeader = true; in Global.asax (Application_Start)."
        ),
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
            remediation=(
                "Your HSTS header is missing the max-age part, so it does nothing. Update "
                "it to: Strict-Transport-Security: max-age=31536000; includeSubDomains."
            ),
            penalty=PENALTY["high"],
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
                remediation=(
                    "Your HSTS max-age is too short. Set it to at least 31536000 (one "
                    "year): Strict-Transport-Security: max-age=31536000; includeSubDomains."
                ),
                penalty=PENALTY["medium"],
            )
    except (IndexError, ValueError):
        pass
    return None


def _check_cookies(set_cookie_lines: list[str]) -> list[HeaderFinding]:
    """
    Inspect Set-Cookie headers for the Secure, HttpOnly, and SameSite attributes.

    High-traffic sites (logins, carts, sessions) live on these flags: a session
    cookie without Secure/HttpOnly is the direct path to account takeover. Passive
    check — reads the same Set-Cookie headers any browser receives.
    """
    if not set_cookie_lines:
        return []

    no_secure: list[str] = []
    no_httponly: list[str] = []
    weak_samesite: list[str] = []

    for line in set_cookie_lines:
        if not line:
            continue
        name = line.split("=", 1)[0].strip()
        low = line.lower()
        if "secure" not in low:
            no_secure.append(name)
        if "httponly" not in low:
            no_httponly.append(name)
        samesite = None
        if "samesite=" in low:
            samesite = low.split("samesite=", 1)[1].split(";")[0].strip()
        if samesite is None or samesite == "none":
            weak_samesite.append(name)

    findings: list[HeaderFinding] = []

    if no_secure:
        findings.append(HeaderFinding(
            header="Set-Cookie (Secure)",
            status="weak",
            severity="medium",
            value=", ".join(no_secure[:8]),
            description=(
                "One or more cookies are set without the Secure flag. A cookie without Secure "
                "can be sent over plain HTTP, where anyone on the network path can read it. On "
                "a busy site this usually includes the session cookie, which means account takeover."
            ),
            remediation=(
                "Add the Secure attribute to every cookie so it is only ever sent over HTTPS. "
                "Set it where the cookie is created (your app framework or your CDN cookie "
                f"settings). Affected cookies: {', '.join(no_secure[:8])}."
            ),
            penalty=PENALTY["medium"],
        ))

    if no_httponly:
        findings.append(HeaderFinding(
            header="Set-Cookie (HttpOnly)",
            status="weak",
            severity="low",
            value=", ".join(no_httponly[:8]),
            description=(
                "One or more cookies are set without the HttpOnly flag, so JavaScript on the "
                "page can read them. If any script on the site is compromised, session and auth "
                "cookies can be stolen."
            ),
            remediation=(
                "Add the HttpOnly attribute to cookies that do not need to be read by "
                "JavaScript, especially session and authentication cookies. Affected cookies: "
                f"{', '.join(no_httponly[:8])}."
            ),
            penalty=PENALTY["low"],
        ))

    if weak_samesite:
        findings.append(HeaderFinding(
            header="Set-Cookie (SameSite)",
            status="weak",
            severity="low",
            value=", ".join(weak_samesite[:8]),
            description=(
                "One or more cookies have no SameSite attribute or use SameSite=None. This lets "
                "the cookie ride along on cross-site requests, which is the basis of cross-site "
                "request forgery (CSRF)."
            ),
            remediation=(
                "Set SameSite=Lax (or Strict for sensitive actions) on your cookies. Use "
                "SameSite=None only when a cookie must work across sites, and always pair it with "
                f"Secure. Affected cookies: {', '.join(weak_samesite[:8])}."
            ),
            penalty=PENALTY["low"],
        ))

    return findings


async def scan_headers(domain: str) -> HeaderScanResult:
    url = f"https://{domain}"
    headers_received: dict[str, str] = {}
    set_cookie_lines: list[str] = []
    redirect_history: list[httpx.Response] = []
    fetch_error: str | None = None
    scanned_url = url

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=10.0,
            headers=dict(SCAN_HEADERS),
        ) as client:
            response = await client.get(url)
            headers_received = dict(response.headers)
            set_cookie_lines = response.headers.get_list("set-cookie")
            scanned_url = str(response.url)
            redirect_history = list(response.history)
    except httpx.ConnectError:
        try:
            url = f"http://{domain}"
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=10.0,
                headers=dict(SCAN_HEADERS),
            ) as client:
                response = await client.get(url)
                headers_received = dict(response.headers)
                scanned_url = str(response.url)
                redirect_history = list(response.history)
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

    # HSTS is sometimes set only on an intermediate redirect response (e.g. google.com
    # sets it on the https://google.com -> https://www.google.com redirect, not on the
    # final page). Walk the history and use the first HSTS value found.
    if "strict-transport-security" not in lower_headers:
        for hist_resp in redirect_history:
            hsts_val = hist_resp.headers.get("strict-transport-security")
            if hsts_val:
                lower_headers["strict-transport-security"] = hsts_val
                break

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
                p = PENALTY["medium"]
                findings.append(HeaderFinding(
                    header=spec["display"],
                    status="weak",
                    severity="medium",
                    value=csp_ro_value,
                    description=(
                        "Content-Security-Policy is in report-only mode. "
                        "Violations are recorded and allowed through. XSS attacks remain possible."
                    ),
                    remediation=(
                        "Your Content-Security-Policy is in 'report-only' mode, so it watches "
                        "for problems without blocking anything. Once you have checked "
                        "the reports and nothing legitimate is flagged, rename the header from "
                        "Content-Security-Policy-Report-Only to Content-Security-Policy to turn "
                        "on real protection."
                    ),
                    penalty=p,
                ))
                total_penalty += p
            elif key == "x-frame-options" and has_frame_ancestors:
                findings.append(HeaderFinding(
                    header=spec["display"],
                    status="present",
                    severity=spec["severity"],
                    value="(via CSP frame-ancestors)",
                    description="Frame embedding is restricted via the CSP frame-ancestors directive.",
                    remediation="No action required.",
                    penalty=0,
                ))
            else:
                p = PENALTY[spec["severity"]]
                findings.append(HeaderFinding(
                    header=spec["display"],
                    status="missing",
                    severity=spec["severity"],
                    value=None,
                    description=spec["description"],
                    remediation=spec["remediation"],
                    penalty=p,
                ))
                total_penalty += p
        else:
            weak_finding = None
            if key == "strict-transport-security":
                weak_finding = _check_hsts_value(value)

            if weak_finding:
                findings.append(weak_finding)
                total_penalty += weak_finding.penalty
            else:
                findings.append(HeaderFinding(
                    header=spec["display"],
                    status="present",
                    severity=spec["severity"],
                    value=value,
                    description=f"{spec['display']} is properly set.",
                    remediation="No action required.",
                    penalty=0,
                ))

    for spec in LEAK_HEADERS:
        value = lower_headers.get(spec["header"])
        if value:
            if spec.get("versioned_only") and not _VERSION_RE.search(value):
                continue
            p = PENALTY[spec["severity"]]
            information_leaks.append(InformationLeakFinding(
                header=spec["header"],
                value=value,
                severity=spec["severity"],
                description=spec["description"],
                remediation=spec["remediation"],
                penalty=p,
            ))
            total_penalty += p

    # Cookie security flags (Secure / HttpOnly / SameSite) — high-value for
    # sites with sessions, logins, and carts.
    cookie_findings = _check_cookies(set_cookie_lines)
    for cf in cookie_findings:
        findings.append(cf)
        total_penalty += cf.penalty

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
            "cookies_flagged": len(cookie_findings),
        },
    )
