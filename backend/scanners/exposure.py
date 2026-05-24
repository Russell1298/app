"""
Exposure scanner.

Makes targeted passive HTTP GET requests to well-known paths that should
never be publicly accessible on a production site. Only checks paths that
are universally recognised as dangerous exposures — no fuzzing, no
enumeration, no authentication bypass.

Checks:
  - .git/HEAD                exposed version control
  - .env                     environment/secrets file
  - robots.txt               path disclosure
  - sitemap.xml              for info only
  - /admin /wp-admin /phpmyadmin  common admin interfaces
  - /.well-known/security.txt     security contact presence
  - Server-generated directory listings (open directory indexing)
  - Debug/diagnostic endpoints
"""

import httpx
import asyncio
from models.scan import ExposureFinding, ExposureScanResult, utc_now_iso

_TIMEOUT = 8
_HEADERS = {"User-Agent": "SecurityScanner/1.0 (defensive assessment)"}

# Each probe: (path, label, severity, description, remediation)
# Severity is what it means IF the path returns 200.
_PROBES: list[dict] = [
    {
        "path": "/.git/HEAD",
        "label": "Exposed .git directory",
        "severity": "high",
        "description": (
            "The .git directory is publicly accessible. Attackers can download your "
            "entire source code, commit history, secrets, and credentials that were "
            "ever committed, even if later deleted."
        ),
        "remediation": (
            "Block access to .git at the web server level.\n"
            "nginx:  location ~ /\\.git { deny all; }\n"
            "Apache: RedirectMatch 404 /\\.git"
        ),
    },
    {
        "path": "/.env",
        "label": "Exposed .env file",
        "severity": "high",
        "description": (
            "The .env file is publicly accessible. This file commonly contains "
            "database credentials, API keys, and other secrets."
        ),
        "remediation": (
            "Block access to dot-files at the web server level and ensure .env is "
            "never placed in the webroot. Move secrets to environment variables or "
            "a secrets manager."
        ),
    },
    {
        "path": "/.env.production",
        "label": "Exposed .env.production file",
        "severity": "high",
        "description": "Production environment file is publicly accessible, potentially exposing secrets.",
        "remediation": "Block access to all dot-files at the web server level.",
    },
    {
        "path": "/.env.local",
        "label": "Exposed .env.local file",
        "severity": "high",
        "description": "Local environment file is publicly accessible, potentially exposing secrets.",
        "remediation": "Block access to all dot-files at the web server level.",
    },
    {
        "path": "/robots.txt",
        "label": "robots.txt present",
        "severity": "info",
        "description": (
            "robots.txt is present. Review it for paths that reveal internal "
            "structure — disallowed paths are still accessible to humans and "
            "malicious crawlers, they just won't be indexed by compliant bots."
        ),
        "remediation": (
            "Ensure robots.txt does not list paths that should be kept confidential. "
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
        "label": "Admin interface exposed",
        "severity": "medium",
        "description": (
            "An /admin path returned a 200 response. Admin interfaces exposed to the "
            "public internet are a common target for credential stuffing and brute-force attacks."
        ),
        "remediation": (
            "Restrict the admin interface to specific IP ranges or move it behind a VPN. "
            "Ensure multi-factor authentication is enforced."
        ),
    },
    {
        "path": "/wp-admin/",
        "label": "WordPress admin exposed",
        "severity": "medium",
        "description": (
            "WordPress admin login is publicly accessible. WordPress admin panels are "
            "heavily targeted for brute-force and credential-stuffing attacks."
        ),
        "remediation": (
            "Restrict /wp-admin to known IPs, enable two-factor authentication, "
            "and consider a WAF rule to block excessive login attempts."
        ),
    },
    {
        "path": "/wp-login.php",
        "label": "WordPress login page exposed",
        "severity": "medium",
        "description": "WordPress login page is publicly accessible.",
        "remediation": "Same as wp-admin restrictions above.",
    },
    {
        "path": "/phpmyadmin/",
        "label": "phpMyAdmin exposed",
        "severity": "high",
        "description": (
            "phpMyAdmin is publicly accessible. This provides a browser-based interface "
            "to your database and is a high-value target for attackers."
        ),
        "remediation": (
            "Remove phpMyAdmin from the webroot entirely or restrict it to localhost. "
            "Use an SSH tunnel to access it when needed."
        ),
    },
    {
        "path": "/server-status",
        "label": "Apache server-status exposed",
        "severity": "medium",
        "description": (
            "Apache mod_status is publicly accessible, exposing real-time request data, "
            "active connections, and server internals."
        ),
        "remediation": 'Restrict with: <Location "/server-status"> Require ip 127.0.0.1 </Location>',
    },
    {
        "path": "/server-info",
        "label": "Apache server-info exposed",
        "severity": "medium",
        "description": "Apache mod_info is publicly accessible, exposing server configuration details.",
        "remediation": "Apply the same IP restriction as server-status.",
    },
    {
        "path": "/.well-known/security.txt",
        "label": "security.txt",
        "severity": "info",
        "description": (
            "security.txt is present. This is a positive signal — it provides a "
            "contact point for responsible disclosure of vulnerabilities."
        ),
        "remediation": None,
    },
    {
        "path": "/debug",
        "label": "Debug endpoint exposed",
        "severity": "medium",
        "description": "A /debug endpoint returned a 200 response, potentially exposing diagnostic information.",
        "remediation": "Disable or restrict debug endpoints in production environments.",
    },
    {
        "path": "/_profiler",
        "label": "Symfony profiler exposed",
        "severity": "high",
        "description": (
            "The Symfony web profiler is publicly accessible. It exposes request details, "
            "environment variables, query logs, and sometimes credentials."
        ),
        "remediation": "Disable the profiler in production: web_profiler.toolbar: false",
    },
    {
        "path": "/telescope",
        "label": "Laravel Telescope exposed",
        "severity": "high",
        "description": (
            "Laravel Telescope is publicly accessible. It logs every request, query, "
            "job, and exception — a significant data exposure risk."
        ),
        "remediation": (
            "Restrict Telescope with a gate policy or remove it from production: "
            "TELESCOPE_ENABLED=false"
        ),
    },
]

_DIRECTORY_LISTING_MARKERS = (
    "Index of /",
    "Directory listing for",
    "<title>Index of",
    "Parent Directory",
)


async def _probe(client: httpx.AsyncClient, base_url: str, probe: dict) -> ExposureFinding | None:
    url = base_url.rstrip("/") + probe["path"]
    try:
        resp = await client.get(url)
    except httpx.RequestError:
        return None

    status_code = resp.status_code

    # Only flag 200 responses (and 403 for admin paths — means it exists but is locked)
    if status_code == 200:
        exposed = True
    elif status_code == 403 and probe["severity"] in ("high", "medium"):
        # 403 = exists but access denied — still worth noting for admin paths
        exposed = True
        probe = dict(probe)
        probe["description"] = (
            probe["description"] + " (Access is currently denied — 403 — but the path exists "
            "and may become accessible if misconfigured.)"
        )
        probe["severity"] = "low"
    else:
        return None

    return ExposureFinding(
        path=probe["path"],
        label=probe["label"],
        status_code=status_code,
        exposed=exposed,
        severity=probe["severity"],
        description=probe["description"],
        remediation=probe.get("remediation"),
    )


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
                    "The web root returns a directory listing. Attackers can browse "
                    "all files and directories without needing to guess paths."
                ),
                remediation=(
                    "Disable directory indexing.\n"
                    "nginx:  autoindex off;\n"
                    "Apache: Options -Indexes"
                ),
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
    info = [f for f in findings if f.severity == "info"]

    # Only penalise genuine 200 exposures. 403s are noted but don't drive the score
    # — they mean the path exists but is currently blocked by config.
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
