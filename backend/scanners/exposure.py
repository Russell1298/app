"""
Exposure scanner.

Makes targeted HTTP GET requests to well-known paths that should never be
publicly accessible. This is an ACTIVE check: it sends requests a typical
visitor would not, which is the only way to determine reachability. It is
non-intrusive (read-only, no exploitation), but it is not passive.

Groups related findings and emits critical_triggers for the overall score
cap logic.

Only HTTP 200 responses count as exposures. HTTP 403 means the path exists
but is correctly restricted — shown as informational, never penalised.
"""

import re
import httpx
import asyncio
from collections import defaultdict
from models.scan import ExposureFinding, ExposureScanResult, utc_now_iso
from scoring_config import PENALTY, scanner_score, risk_level

_TIMEOUT = 8
_HEADERS = {"User-Agent": "SecurityScanner/1.0 (defensive assessment)"}

_PROBES: list[dict] = [
    {
        "path": "/.git/HEAD",
        "label": "Git directory accessible",
        "severity": "high",
        "description": (
            "The /.git/HEAD path returned an HTTP 200 response. If the .git directory "
            "is truly accessible, an attacker may retrieve source code, commit history, "
            "and any credentials ever committed, including ones later removed."
        ),
        "remediation": "Your .git folder is reachable from the web, which can leak your entire source code and any passwords ever committed. Block it. On Nginx: location ~ /\\.git { deny all; } On Apache: RedirectMatch 404 /\\.git. Better yet, keep the .git folder out of your public web folder entirely.",
    },
    {
        "path": "/.env",
        "label": ".env file accessible",
        "severity": "high",
        "description": "A /.env path returned HTTP 200. Environment files commonly contain database credentials, API keys, and other secrets.",
        "remediation": "Your .env file is downloadable, and these files usually hold database passwords and API keys. Block access to it now and move it outside your public web folder. On Nginx: location ~ /\\.env { deny all; }. Then change (rotate) any secrets that were in it, since they may already be compromised.",
    },
    {
        "path": "/.env.production",
        "label": ".env.production file accessible",
        "severity": "high",
        "description": "A /.env.production path returned HTTP 200, potentially exposing production secrets.",
        "remediation": "Your .env.production file is downloadable and likely contains live secrets. Block access to it, move it outside the public web folder, and change any passwords or keys it held.",
    },
    {
        "path": "/.env.local",
        "label": ".env.local file accessible",
        "severity": "high",
        "description": "A /.env.local path returned HTTP 200, potentially exposing local override configuration.",
        "remediation": "Your .env.local file is reachable from the web and may expose configuration secrets. Block access to all dot-files at the server level and keep these files out of your public folder.",
    },
    {
        "path": "/robots.txt",
        "label": "robots.txt present",
        "severity": "info",
        "description": "robots.txt is present. Review the Disallow entries, because those paths stay reachable by anyone who reads the file.",
        "remediation": "Anything listed under 'Disallow' stays publicly reachable. The file asks well-behaved crawlers to skip those paths and nothing more. Protect sensitive pages with a login or an IP restriction.",
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
        "description": "An /admin path returned 200. If unprotected, it could be targeted for credential-stuffing attacks.",
        "remediation": "Your /admin page is open to the internet, so bots will try to guess passwords. Limit it to your own IP address, put it behind a VPN, or add two-factor authentication. Check your hosting panel or security plugin for an 'admin IP restriction' option.",
    },
    {
        "path": "/wp-admin/",
        "label": "WordPress admin accessible",
        "severity": "medium",
        "description": "A /wp-admin path returned 200. WordPress login pages are heavily targeted by automated credential-stuffing tools.",
        "remediation": "Your WordPress admin (/wp-admin) is open to the internet and is a top target for password-guessing bots. Restrict it to your IP, turn on two-factor login, and limit login attempts. Plugins like Wordfence or Limit Login Attempts handle this.",
    },
    {
        "path": "/wp-login.php",
        "label": "WordPress login accessible",
        "severity": "medium",
        "description": "The WordPress login endpoint is publicly accessible.",
        "remediation": "Your WordPress login page (/wp-login.php) is publicly reachable. Protect it the same way as wp-admin: limit login attempts, add two-factor authentication, and restrict it to known IPs if you can.",
    },
    {
        "path": "/phpmyadmin/",
        "label": "phpMyAdmin endpoint accessible",
        "severity": "high",
        "description": "A phpMyAdmin endpoint appears to be accessible. Without IP restriction this is a high-value target for automated attacks.",
        "remediation": "phpMyAdmin gives direct access to your database and is currently reachable from the web. Remove it from your public web folder, or restrict it to localhost and reach it through an SSH tunnel when you need it.",
    },
    {
        "path": "/adminer.php",
        "label": "Adminer database tool accessible",
        "severity": "medium",
        "description": "An Adminer database management script appears to be publicly accessible. Without IP restriction it provides a browser-based interface to your database.",
        "remediation": "Adminer (a database tool) is publicly reachable and gives browser access to your database. Delete adminer.php from your web folder when you're not using it, or lock it down to your own IP or an SSH tunnel.",
    },
    {
        "path": "/admin/",
        "label": "Generic admin panel accessible",
        "severity": "medium",
        "description": "An /admin/ path returned 200. If unprotected, this admin panel could be targeted for credential-stuffing or brute-force attacks.",
        "remediation": "Your /admin/ panel is open to the internet. Restrict it to your own IP address or put it behind a VPN, and add two-factor authentication to slow down password-guessing bots.",
    },
    {
        "path": "/server-status",
        "label": "Apache server-status accessible",
        "severity": "medium",
        "description": "An Apache mod_status page may be accessible, exposing real-time request data and server version.",
        "remediation": 'Apache\'s server-status page is exposed, showing live traffic and your server version. Lock it to localhost: <Location "/server-status"> Require ip 127.0.0.1 </Location>, then reload Apache.',
    },
    {
        "path": "/server-info",
        "label": "Apache server-info accessible",
        "severity": "medium",
        "description": "An Apache mod_info page may be accessible, exposing server configuration details.",
        "remediation": "Apache's server-info page is exposed, revealing your server configuration. Restrict it to localhost the same way as server-status (Require ip 127.0.0.1), then reload Apache.",
    },
    {
        "path": "/.well-known/security.txt",
        "label": "security.txt",
        "severity": "info",
        "description": "security.txt is present. It gives security researchers a contact route for reporting issues.",
        "remediation": None,
    },
    {
        "path": "/debug",
        "label": "Debug endpoint accessible",
        "severity": "high",
        "description": "A /debug path returned 200. Debug endpoints can expose stack traces, environment details, and diagnostic data.",
        "remediation": "A /debug endpoint is reachable and can leak error traces, environment details, and internal data. Turn off debug mode in production and remove or block the endpoint.",
    },
    {
        "path": "/_profiler",
        "label": "Symfony profiler accessible",
        "severity": "high",
        "description": "A Symfony profiler endpoint appears accessible. In production it can expose requests, env vars, DB queries, and credentials.",
        "remediation": "The Symfony profiler is exposed, which in production can reveal requests, environment variables, and database queries. Disable it in production: set web_profiler.toolbar: false and set APP_ENV to 'prod'.",
    },
    {
        "path": "/telescope",
        "label": "Laravel Telescope accessible",
        "severity": "high",
        "description": "A Laravel Telescope endpoint appears accessible. Without authentication it logs every request, query, and exception.",
        "remediation": "Laravel Telescope is publicly reachable and logs every request, query, and error. Lock it behind authentication with a Telescope gate, or disable it in production by setting TELESCOPE_ENABLED=false.",
    },
]

_PATH_GROUP: dict[str, str] = {
    "/.env":             "env",
    "/.env.production":  "env",
    "/.env.local":       "env",
    "/.git/HEAD":        "git",
    "/phpmyadmin/":      "db_admin",
    "/adminer.php":      "db_admin",
    "/_profiler":        "debug_panel",
    "/telescope":        "debug_panel",
    "/debug":            "debug_panel",
    "/admin":            "admin",
    "/admin/":           "admin",
    "/wp-admin/":        "admin",
    "/wp-login.php":     "admin",
    "/server-status":    "server_info",
    "/server-info":      "server_info",
    "/":                 "dir_listing",
}

_GROUP_SPEC: dict[str, dict] = {
    "env":         {"severity": "high",   "trigger": "env_exposed"},
    "git":         {"severity": "high",   "trigger": "git_exposed"},
    "db_admin":    {"severity": "high",   "trigger": "db_admin_exposed"},
    "debug_panel": {"severity": "high",   "trigger": "debug_panel_exposed"},
    "admin":       {"severity": "medium", "trigger": None},
    "server_info": {"severity": "medium", "trigger": None},
    "dir_listing": {"severity": "medium", "trigger": None},
    "other":       {"severity": "medium", "trigger": None},
}

_DIRECTORY_LISTING_MARKERS = (
    "Index of /", "Directory listing for", "<title>Index of", "Parent Directory",
)

_ENV_PATTERN = re.compile(r'(?m)^[A-Z_][A-Z0-9_]*\s*=\S', re.MULTILINE)

_CONFIRMED_SIGNATURES: dict[str, list[str]] = {
    "/.git/HEAD":     ["ref: refs/heads/", "ref: refs/"],
    "/_profiler":     ["Symfony", "sf-toolbar", "Profiler"],
    "/telescope":     ["Telescope", "telescope"],
    "/phpmyadmin/":   ["phpMyAdmin", "PMA_"],
    "/server-status": ["requests/sec", "Apache Status", "Server Version:"],
    "/server-info":   ["Apache Server Information", "Server Settings"],
}

_POSSIBLE_ONLY_PATHS = {"/admin", "/admin/", "/wp-admin/", "/wp-login.php", "/adminer.php", "/debug"}


def _confidence(path: str, body: str) -> str:
    if path in ("/.env", "/.env.production", "/.env.local"):
        return "confirmed" if _ENV_PATTERN.search(body[:3000]) else "likely"
    sigs = _CONFIRMED_SIGNATURES.get(path)
    if sigs and any(s in body for s in sigs):
        return "confirmed"
    if path in _POSSIBLE_ONLY_PATHS:
        return "possible"
    return "likely"


# Paths that cannot plausibly exist. If the server answers 200 for these it is
# serving a catch-all route (a single-page app, or a framework that renders its
# own 404 page with a 200 status). On such a server a 200 proves nothing, so
# status code alone must not be treated as evidence of an exposed file.
_CATCH_ALL_PROBES = (
    "/sekura-catchall-check-9f3a2b",
    "/sekura-catchall-check-9f3a2b/index.html",
)


async def _detect_catch_all(client: httpx.AsyncClient, base_url: str) -> bool:
    for path in _CATCH_ALL_PROBES:
        try:
            resp = await client.get(base_url.rstrip("/") + path)
        except httpx.RequestError:
            continue
        if resp.status_code == 200:
            return True
    return False


async def _probe(
    client: httpx.AsyncClient,
    base_url: str,
    probe: dict,
    catch_all: bool = False,
) -> ExposureFinding | None:
    url = base_url.rstrip("/") + probe["path"]
    try:
        resp = await client.get(url)
    except httpx.RequestError:
        return None

    status_code = resp.status_code

    if status_code == 200:
        body = resp.text[:4000]
        conf = _confidence(probe["path"], body)
        sev = probe["severity"]

        # On a catch-all server every path returns 200, so only a positive
        # content signature counts. Without one, report nothing rather than
        # accusing the site of exposing a file it does not serve.
        if catch_all and conf != "confirmed":
            return None

        return ExposureFinding(
            path=probe["path"],
            label=probe["label"],
            status_code=status_code,
            exposed=True,
            severity=sev,
            description=probe["description"],
            remediation=probe.get("remediation"),
            confidence=conf,
            penalty=PENALTY[sev] if sev != "info" else 0,
        )

    if status_code == 403:
        # Path exists but access is correctly restricted — informational only, no penalty.
        # Only report 403 for high-severity paths so the user can see the check ran.
        if probe["severity"] in ("high", "medium"):
            return ExposureFinding(
                path=probe["path"],
                label=probe["label"] + " (blocked)",
                status_code=status_code,
                exposed=False,
                severity="info",
                description=f"Access to {probe['path']} is correctly blocked (HTTP 403).",
                remediation=None,
                confidence="confirmed",
                penalty=0,
            )

    return None


async def _check_directory_listing(client: httpx.AsyncClient, base_url: str) -> ExposureFinding | None:
    try:
        resp = await client.get(base_url + "/")
    except httpx.RequestError:
        return None
    if resp.status_code == 200 and any(m in resp.text for m in _DIRECTORY_LISTING_MARKERS):
        return ExposureFinding(
            path="/",
            label="Open directory listing",
            status_code=200,
            exposed=True,
            severity="medium",
            description="The web root returns a directory listing, allowing visitors to browse files.",
            remediation="Your web server is showing a browsable list of your files. Turn it off. On Nginx: autoindex off; On Apache: Options -Indexes. Then add an index page such as index.html so the folder is no longer browsable.",
            confidence="confirmed",
            penalty=PENALTY["medium"],
        )
    return None


async def scan_exposure(domain: str) -> ExposureScanResult:
    base_url = f"https://{domain}"

    async with httpx.AsyncClient(follow_redirects=False, timeout=_TIMEOUT, headers=_HEADERS) as client:
        catch_all = await _detect_catch_all(client, base_url)
        tasks = [_probe(client, base_url, p, catch_all) for p in _PROBES]
        tasks.append(_check_directory_listing(client, base_url))
        results = await asyncio.gather(*tasks, return_exceptions=True)

    findings: list[ExposureFinding] = [r for r in results if isinstance(r, ExposureFinding)]

    if catch_all:
        findings.append(ExposureFinding(
            path="/",
            label="Server returns 200 for every path",
            status_code=200,
            exposed=False,
            severity="info",
            description=(
                "This site answers HTTP 200 for URLs that do not exist, which is normal for a "
                "single-page app or a framework that renders its own not-found page. Because a "
                "200 response proves nothing here, a path is only reported as exposed when its "
                "content matches the file we were looking for."
            ),
            remediation=(
                "No action needed for security. If you would rather missing pages return a real "
                "404, configure your framework or host to send that status for unmatched routes."
            ),
            confidence="confirmed",
            penalty=0,
        ))

    # Only HTTP 200 findings count toward the grouped penalty and triggers
    group_counts: dict[str, int] = defaultdict(int)
    confirmed_groups: set[str] = set()
    for f in findings:
        if f.exposed and f.status_code == 200 and f.severity != "info":
            group = _PATH_GROUP.get(f.path, "other")
            group_counts[group] += 1
            if f.confidence == "confirmed":
                confirmed_groups.add(group)

    total_penalty = 0
    critical_triggers: list[str] = []
    for group_name, count in group_counts.items():
        spec = _GROUP_SPEC.get(group_name, _GROUP_SPEC["other"])
        total_penalty += PENALTY[spec["severity"]] + max(0, count - 1) * 2
        # A critical trigger floors the whole report's score, so it requires
        # positive evidence from the response body, not just a 200 status.
        if spec["trigger"] and group_name in confirmed_groups and spec["trigger"] not in critical_triggers:
            critical_triggers.append(spec["trigger"])

    risk = scanner_score(total_penalty, "exposure")
    level = risk_level(risk)

    exposed = [f for f in findings if f.exposed and f.severity != "info"]
    info    = [f for f in findings if f.severity == "info" or not f.exposed]

    return ExposureScanResult(
        domain=domain,
        scan_timestamp=utc_now_iso(),
        findings=findings,
        risk_score=risk,
        risk_level=level,
        critical_triggers=critical_triggers,
        summary={
            "paths_checked": len(_PROBES) + 1,
            "exposed": len(exposed),
            "informational": len(info),
            "catch_all_routing": catch_all,
        },
    )
