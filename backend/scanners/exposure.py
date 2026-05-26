"""
Exposure scanner.

Makes targeted passive HTTP GET requests to well-known paths that should
never be publicly accessible on a production site. Only checks paths that
are universally recognised as dangerous exposures — no fuzzing, no
enumeration, no authentication bypass.

Each finding includes a confidence tier based on response body content:
  confirmed — response body contains signatures of real sensitive content
  likely    — endpoint is accessible and matches a known dangerous path
  possible  — endpoint exists but content could not be verified
"""

import re
import httpx
import asyncio
from models.scan import ExposureFinding, ExposureScanResult, utc_now_iso

_TIMEOUT = 8
_HEADERS = {"User-Agent": "SecurityScanner/1.0 (defensive assessment)"}

# Each probe: (path, label, severity, description, remediation)
# Descriptions use careful, hedged language — the scanner only observes HTTP
# status codes and partial body content, not actual exploitability.
_PROBES: list[dict] = [
    {
        "path": "/.git/HEAD",
        "label": "Git directory accessible",
        "severity": "high",
        "description": (
            "The /.git/HEAD path returned an HTTP 200 response. If the .git directory "
            "is truly accessible, an attacker may be able to retrieve source code, "
            "commit history, and any credentials ever committed — even if later removed."
        ),
        "remediation": (
            "Block access to .git at the web server level.\n"
            "nginx:  location ~ /\\.git { deny all; }\n"
            "Apache: RedirectMatch 404 /\\.git"
        ),
    },
    {
        "path": "/.env",
        "label": ".env file accessible",
        "severity": "high",
        "description": (
            "A /.env path returned an HTTP 200 response. Environment files commonly "
            "contain database credentials, API keys, and other secrets. If this is a "
            "real configuration file, those values would be publicly readable."
        ),
        "remediation": (
            "Block access to dot-files at the web server level and ensure .env is "
            "never placed in the webroot. Store secrets in environment variables or "
            "a dedicated secrets manager."
        ),
    },
    {
        "path": "/.env.production",
        "label": ".env.production file accessible",
        "severity": "high",
        "description": (
            "A /.env.production path returned an HTTP 200 response, potentially "
            "exposing production application secrets."
        ),
        "remediation": "Block access to all dot-files at the web server level.",
    },
    {
        "path": "/.env.local",
        "label": ".env.local file accessible",
        "severity": "high",
        "description": (
            "A /.env.local path returned an HTTP 200 response, potentially "
            "exposing local override configuration."
        ),
        "remediation": "Block access to all dot-files at the web server level.",
    },
    {
        "path": "/robots.txt",
        "label": "robots.txt present",
        "severity": "info",
        "description": (
            "robots.txt is present. Review it for internal paths listed under Disallow — "
            "those paths are still accessible to humans and malicious crawlers; "
            "they simply will not be indexed by compliant bots."
        ),
        "remediation": (
            "Ensure robots.txt does not reveal paths that should be kept confidential. "
            "Rely on proper access controls, not robots.txt, to protect sensitive areas."
        ),
    },
    {
        "path": "/sitemap.xml",
        "label": "sitemap.xml present",
        "severity": "info",
        "description": "sitemap.xml is present. Useful for confirming the public URL structure.",
        "remediation": None,
    },
    {
        "path": "/admin",
        "label": "Admin path accessible",
        "severity": "medium",
        "description": (
            "An /admin path returned a 200 response. If this is an unprotected "
            "administration interface, it could be targeted for credential-stuffing "
            "or brute-force attacks. Login forms that require valid credentials are "
            "lower risk but should still be restricted by IP where possible."
        ),
        "remediation": (
            "Restrict the admin interface to specific IP ranges or move it behind a VPN. "
            "Ensure multi-factor authentication is enforced."
        ),
    },
    {
        "path": "/wp-admin/",
        "label": "WordPress admin accessible",
        "severity": "medium",
        "description": (
            "A /wp-admin path returned a 200 response. WordPress login pages are heavily "
            "targeted by automated credential-stuffing tools. This is expected if the "
            "site runs WordPress, but the login page should be hardened."
        ),
        "remediation": (
            "Restrict /wp-admin to known IPs, enable two-factor authentication, "
            "and consider a WAF rule to limit login attempts."
        ),
    },
    {
        "path": "/wp-login.php",
        "label": "WordPress login accessible",
        "severity": "medium",
        "description": "The WordPress login endpoint is publicly accessible.",
        "remediation": "Apply the same hardening as wp-admin above.",
    },
    {
        "path": "/phpmyadmin/",
        "label": "phpMyAdmin endpoint accessible",
        "severity": "high",
        "description": (
            "A phpMyAdmin endpoint appears to be accessible. If this is a live "
            "database administration panel without IP restriction, it represents "
            "a significant risk — phpMyAdmin panels are frequently targeted by "
            "automated scanners attempting default or common credentials."
        ),
        "remediation": (
            "Remove phpMyAdmin from the webroot entirely or restrict it to localhost. "
            "Use an SSH tunnel to access it when needed."
        ),
    },
    {
        "path": "/server-status",
        "label": "Apache server-status accessible",
        "severity": "medium",
        "description": (
            "An Apache mod_status page may be accessible, potentially exposing "
            "real-time request data, active connections, and server version details."
        ),
        "remediation": 'Restrict with: <Location "/server-status"> Require ip 127.0.0.1 </Location>',
    },
    {
        "path": "/server-info",
        "label": "Apache server-info accessible",
        "severity": "medium",
        "description": (
            "An Apache mod_info page may be accessible, potentially exposing "
            "server configuration and loaded module details."
        ),
        "remediation": "Apply the same IP restriction as server-status.",
    },
    {
        "path": "/.well-known/security.txt",
        "label": "security.txt",
        "severity": "info",
        "description": (
            "security.txt is present — a positive signal that provides a contact "
            "point for responsible disclosure of vulnerabilities."
        ),
        "remediation": None,
    },
    {
        "path": "/debug",
        "label": "Debug endpoint accessible",
        "severity": "medium",
        "description": (
            "A /debug path returned a 200 response. Depending on the framework, "
            "debug endpoints can expose diagnostic information, stack traces, or "
            "environment details. Verify whether this endpoint reveals sensitive data."
        ),
        "remediation": "Disable or restrict debug endpoints in production environments.",
    },
    {
        "path": "/_profiler",
        "label": "Symfony profiler accessible",
        "severity": "high",
        "description": (
            "A Symfony profiler endpoint appears to be accessible. If the profiler "
            "is enabled in production, it can expose detailed request data, "
            "environment variables, database queries, and sometimes credentials."
        ),
        "remediation": "Disable the profiler in production: web_profiler.toolbar: false",
    },
    {
        "path": "/telescope",
        "label": "Laravel Telescope accessible",
        "severity": "high",
        "description": (
            "A Laravel Telescope endpoint appears to be accessible. If enabled in "
            "production without authentication, it logs every application request, "
            "database query, queued job, and exception."
        ),
        "remediation": (
            "Restrict Telescope with a gate policy or disable it: TELESCOPE_ENABLED=false"
        ),
    },
]

_DIRECTORY_LISTING_MARKERS = (
    "Index of /",
    "Directory listing for",
    "<title>Index of",
    "Parent Directory",
)

# Body content patterns that confirm a finding is real sensitive data
_ENV_PATTERN = re.compile(r'(?m)^[A-Z_][A-Z0-9_]*\s*=\S', re.MULTILINE)

_CONFIRMED_SIGNATURES: dict[str, list[str]] = {
    "/.git/HEAD":         ["ref: refs/heads/", "ref: refs/"],
    "/_profiler":         ["Symfony", "sf-toolbar", "Profiler"],
    "/telescope":         ["Telescope", "telescope"],
    "/phpmyadmin/":       ["phpMyAdmin", "PMA_"],
    "/server-status":     ["requests/sec", "Apache Status", "Server Version:"],
    "/server-info":       ["Apache Server Information", "Server Settings"],
}

# Paths where a 200 alone doesn't confirm anything — auth pages are expected to return 200
_POSSIBLE_ONLY_PATHS = {"/admin", "/wp-admin/", "/wp-login.php", "/debug"}


def _confidence(path: str, body: str) -> str:
    """Determine confidence from response body content."""
    if path in ("/.env", "/.env.production", "/.env.local"):
        return "confirmed" if _ENV_PATTERN.search(body[:3000]) else "likely"

    sigs = _CONFIRMED_SIGNATURES.get(path)
    if sigs and any(s in body for s in sigs):
        return "confirmed"

    if path in _POSSIBLE_ONLY_PATHS:
        return "possible"

    return "likely"


async def _probe(client: httpx.AsyncClient, base_url: str, probe: dict) -> ExposureFinding | None:
    url = base_url.rstrip("/") + probe["path"]
    try:
        resp = await client.get(url)
    except httpx.RequestError:
        return None

    status_code = resp.status_code

    if status_code == 200:
        body = resp.text[:4000]
        conf = _confidence(probe["path"], body)
        return ExposureFinding(
            path=probe["path"],
            label=probe["label"],
            status_code=status_code,
            exposed=True,
            severity=probe["severity"],
            description=probe["description"],
            remediation=probe.get("remediation"),
            confidence=conf,
        )

    if status_code == 403 and probe["severity"] in ("high", "medium"):
        return ExposureFinding(
            path=probe["path"],
            label=probe["label"],
            status_code=status_code,
            exposed=True,
            severity="low",
            description=(
                probe["description"] +
                " Access is currently blocked (HTTP 403), meaning the path exists "
                "but is presently restricted. This will become a risk if that "
                "restriction is removed."
            ),
            remediation=probe.get("remediation"),
            confidence="possible",
        )

    return None


async def _check_directory_listing(client: httpx.AsyncClient, base_url: str) -> ExposureFinding | None:
    try:
        resp = await client.get(base_url + "/")
    except httpx.RequestError:
        return None

    if resp.status_code == 200:
        body = resp.text
        if any(marker in body for marker in _DIRECTORY_LISTING_MARKERS):
            return ExposureFinding(
                path="/",
                label="Open directory listing",
                status_code=200,
                exposed=True,
                severity="medium",
                description=(
                    "The web root appears to be returning a directory listing, allowing "
                    "visitors to browse files without knowing specific URLs."
                ),
                remediation=(
                    "Disable directory indexing.\n"
                    "nginx:  autoindex off;\n"
                    "Apache: Options -Indexes"
                ),
                confidence="confirmed",
            )
    return None


async def scan_exposure(domain: str) -> ExposureScanResult:
    base_url = f"https://{domain}"

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=_TIMEOUT,
        headers=_HEADERS,
    ) as client:
        tasks = [_probe(client, base_url, p) for p in _PROBES]
        tasks.append(_check_directory_listing(client, base_url))
        results = await asyncio.gather(*tasks, return_exceptions=True)

    findings: list[ExposureFinding] = [
        r for r in results if isinstance(r, ExposureFinding)
    ]

    exposed = [f for f in findings if f.exposed and f.severity != "info"]
    info    = [f for f in findings if f.severity == "info"]

    penalty_map = {"high": 25, "medium": 12, "low": 5, "info": 0}
    risk_score = min(100, sum(
        penalty_map[f.severity] for f in findings
        if f.exposed and f.status_code == 200
    ))

    if risk_score < 25:
        risk_level = "low"
    elif risk_score < 50:
        risk_level = "medium"
    elif risk_score < 75:
        risk_level = "high"
    else:
        risk_level = "critical"

    return ExposureScanResult(
        domain=domain,
        scan_timestamp=utc_now_iso(),
        findings=findings,
        risk_score=risk_score,
        risk_level=risk_level,
        summary={
            "paths_checked": len(_PROBES) + 1,
            "exposed": len(exposed),
            "informational": len(info),
        },
    )
