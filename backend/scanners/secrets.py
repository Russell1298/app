"""
Secret and credential exposure scanner.

Fetches the homepage HTML plus up to 5 linked JavaScript files and
runs regex patterns against the visible content. Only inspects what
any browser would load — no authentication, no crawling, no brute forcing.

Findings are partially redacted before storage so no real credentials
are ever written to the database.
"""

import re
import httpx
import asyncio
from urllib.parse import urljoin, urlparse
from models.scan import SecretFinding, SecretScanResult, utc_now_iso

_TIMEOUT   = 8
_MAX_JS    = 5      # max external JS files to inspect
_MAX_BYTES = 500_000  # 500 KB per file
_HEADERS   = {"User-Agent": "SecurityScanner/1.0 (defensive assessment)"}

# (pattern, label, severity)
_PATTERNS: list[tuple[str, str, str]] = [
    (r"AKIA[0-9A-Z]{16}",                                    "AWS Access Key ID",            "high"),
    (r"(?i)aws.{0,20}secret.{0,20}['\"][A-Za-z0-9/+=]{40}['\"]", "AWS Secret Access Key",   "high"),
    (r"sk_live_[A-Za-z0-9]{24,}",                            "Stripe Live Secret Key",       "high"),
    (r"rk_live_[A-Za-z0-9]{24,}",                            "Stripe Restricted Key",        "high"),
    (r"ghp_[A-Za-z0-9]{36}",                                 "GitHub Personal Access Token", "high"),
    (r"ghs_[A-Za-z0-9]{36}",                                 "GitHub App Token",             "high"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",            "Private Key",                  "high"),
    (r"(?i)password\s*[:=]\s*['\"][^'\"]{8,}['\"]",          "Hardcoded Password",           "high"),
    (r"(?i)api[_-]?key\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]", "API Key",                 "medium"),
    (r"(?i)secret\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",  "Secret Value",                 "medium"),
    (r"(?i)auth[_-]?token\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "Auth Token",            "medium"),
    (r"(?i)access[_-]?token\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "Access Token",        "medium"),
    (r"(?i)private[_-]?key\s*[:=]\s*['\"][A-Za-z0-9_\-/+=]{20,}['\"]", "Private Key Value", "medium"),
    (r"AIza[0-9A-Za-z\-_]{35}",                              "Google API Key",                "medium"),
    (r"ya29\.[0-9A-Za-z\-_]+",                               "Google OAuth Token",            "medium"),
    (r"EAACEdEose0cBA[0-9A-Za-z]+",                          "Facebook Access Token",         "medium"),
    (r"(?i)jdbc:[a-z]+://[^\s\"']+:[^\s\"'@]+@",             "Database Connection String",    "high"),
    (r"mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@",                "MongoDB Connection String",     "high"),
]

_compiled = [(re.compile(p), label, sev) for p, label, sev in _PATTERNS]


def _redact(match: str) -> str:
    """Keep first 6 chars, redact the rest."""
    if len(match) <= 6:
        return "***"
    return match[:6] + "***" + match[-2:]


def _scan_content(content: str, source_url: str, location: str) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    seen: set[str] = set()
    for pattern, label, severity in _compiled:
        for m in pattern.finditer(content):
            key = (label, source_url)
            if key in seen:
                continue
            seen.add(key)
            findings.append(SecretFinding(
                pattern_name=label,
                severity=severity,
                location=location,
                source_url=source_url,
                match_preview=_redact(m.group()),
            ))
    return findings


def _extract_js_urls(html: str, base_url: str) -> list[str]:
    urls = []
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
        src = m.group(1)
        if src.startswith("data:"):
            continue
        full = urljoin(base_url, src)
        if urlparse(full).scheme in ("http", "https"):
            urls.append(full)
    return urls[:_MAX_JS]


async def scan_secrets(domain: str) -> SecretScanResult:
    base_url  = f"https://{domain}"
    findings: list[SecretFinding] = []
    files_scanned = 0

    async with httpx.AsyncClient(
        follow_redirects=True, timeout=_TIMEOUT, headers=_HEADERS,
    ) as client:
        # Scan homepage HTML
        try:
            resp = await client.get(base_url)
            html = resp.text[:_MAX_BYTES]
            files_scanned += 1

            # Inline HTML scan
            findings += _scan_content(html, base_url, "html")

            # Inline <script> blocks
            for m in re.finditer(r"<script[^>]*>(.*?)</script>", html, re.DOTALL | re.IGNORECASE):
                findings += _scan_content(m.group(1), base_url, "inline-script")

            # Fetch and scan external JS
            js_urls = _extract_js_urls(html, base_url)
            js_tasks = [client.get(u) for u in js_urls]
            js_responses = await asyncio.gather(*js_tasks, return_exceptions=True)

            for url, js_resp in zip(js_urls, js_responses):
                if isinstance(js_resp, Exception):
                    continue
                files_scanned += 1
                findings += _scan_content(js_resp.text[:_MAX_BYTES], url, "javascript")

        except httpx.RequestError:
            pass

    # Deduplicate: one finding per (label, location) combination
    seen: set[tuple] = set()
    deduped: list[SecretFinding] = []
    for f in findings:
        key = (f.pattern_name, f.location, f.source_url)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    penalty = {"high": 30, "medium": 15, "low": 5}
    risk_score = min(100, sum(penalty[f.severity] for f in deduped))
    risk_level = (
        "critical" if risk_score >= 75 else
        "high"     if risk_score >= 50 else
        "medium"   if risk_score >= 25 else
        "low"
    )

    return SecretScanResult(
        domain=domain,
        scan_timestamp=utc_now_iso(),
        findings=deduped,
        files_scanned=files_scanned,
        risk_score=risk_score,
        risk_level=risk_level,
        summary={
            "files_scanned": files_scanned,
            "secrets_found": len(deduped),
            "high": sum(1 for f in deduped if f.severity == "high"),
            "medium": sum(1 for f in deduped if f.severity == "medium"),
        },
    )
