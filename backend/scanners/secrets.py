"""
Secret and credential exposure scanner.

Fetches homepage HTML plus up to 5 linked JS files and runs regex patterns
against visible content. Applies false-positive filtering before reporting.
Findings are partially redacted — no real credentials are stored.
"""

import re
import httpx
import asyncio
from urllib.parse import urljoin, urlparse
from models.scan import SecretFinding, SecretScanResult, utc_now_iso
from scoring_config import PENALTY, scanner_score, risk_level

_TIMEOUT   = 8
_MAX_JS    = 5
_MAX_BYTES = 500_000
_HEADERS   = {"User-Agent": "SecurityScanner/1.0 (defensive assessment)"}

_PATTERNS: list[tuple[str, str, str]] = [
    (r"AKIA[0-9A-Z]{16}",                                         "AWS Access Key ID",            "high"),
    (r"(?i)aws.{0,20}secret.{0,20}['\"][A-Za-z0-9/+=]{40}['\"]",  "AWS Secret Access Key",        "high"),
    (r"sk_live_[A-Za-z0-9]{24,}",                                 "Stripe Live Secret Key",       "high"),
    (r"rk_live_[A-Za-z0-9]{24,}",                                 "Stripe Restricted Key",        "high"),
    (r"ghp_[A-Za-z0-9]{36}",                                      "GitHub Personal Access Token", "high"),
    (r"ghs_[A-Za-z0-9]{36}",                                      "GitHub App Token",             "high"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",                 "Private Key",                  "high"),
    (r"ya29\.[0-9A-Za-z\-_]+",                                    "Google OAuth Token",           "high"),
    (r"EAACEdEose0cBA[0-9A-Za-z]+",                               "Facebook Access Token",        "high"),
    (r"mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@",                     "MongoDB Connection String",    "high"),
    (r"(?i)api[_-]?key\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]",  "API Key",                      "medium"),
    (r"(?i)secret\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",       "Secret Value",                 "medium"),
    (r"(?i)auth[_-]?token\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "Auth Token",                "medium"),
    (r"(?i)access[_-]?token\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "Access Token",             "medium"),
    (r"(?i)private[_-]?key\s*[:=]\s*['\"][A-Za-z0-9_\-/+=]{20,}['\"]", "Private Key Value",      "medium"),
    (r"AIza[0-9A-Za-z\-_]{35}",                                   "Google API Key",               "medium"),
    (r"(?i)jdbc:[a-z]+://[^\s\"']+:[^\s\"'@]+@",                  "Database Connection String",   "medium"),
    (r"(?i)password\s*[:=]\s*['\"][^'\"]{8,}['\"]",               "Hardcoded Password",           "medium"),
]

_compiled = [(re.compile(p), label, sev) for p, label, sev in _PATTERNS]

# Patterns whose presence emits the "live_secret" critical trigger
_LIVE_SECRET_LABELS = frozenset({
    "AWS Access Key ID",
    "AWS Secret Access Key",
    "Stripe Live Secret Key",
    "Stripe Restricted Key",
    "GitHub Personal Access Token",
    "GitHub App Token",
    "Google OAuth Token",
    "Facebook Access Token",
    "MongoDB Connection String",
})
_PRIVATE_KEY_LABELS = frozenset({"Private Key"})

_FP_CONTEXT_WORDS = frozenset((
    "example", "sample", "test", "demo", "placeholder",
    "your-key-here", "xxxx", "0000",
))
_FP_URL_SEGMENTS = ("/docs/", "/examples/", "/test/", "/__tests__/", "/spec/")


def _is_false_positive(pattern_name: str, context: str, source_url: str) -> bool:
    url_path = urlparse(source_url).path.lower()
    if any(seg in url_path for seg in _FP_URL_SEGMENTS):
        return True
    if pattern_name == "Google API Key" and "maps.googleapis.com" in source_url:
        return True
    ctx_lower = context.lower()
    return any(word in ctx_lower for word in _FP_CONTEXT_WORDS)


def _redact(match: str) -> str:
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
            # Extract context window for false-positive check
            start = max(0, m.start() - 100)
            end = min(len(content), m.end() + 100)
            context = content[start:end]
            if _is_false_positive(label, context, source_url):
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
        try:
            resp = await client.get(base_url)
            html = resp.text[:_MAX_BYTES]
            files_scanned += 1

            findings += _scan_content(html, base_url, "html")

            for m in re.finditer(r"<script[^>]*>(.*?)</script>", html, re.DOTALL | re.IGNORECASE):
                findings += _scan_content(m.group(1), base_url, "inline-script")

            js_urls = _extract_js_urls(html, base_url)
            js_responses = await asyncio.gather(
                *[client.get(u) for u in js_urls], return_exceptions=True
            )
            for url, js_resp in zip(js_urls, js_responses):
                if isinstance(js_resp, Exception):
                    continue
                files_scanned += 1
                findings += _scan_content(js_resp.text[:_MAX_BYTES], url, "javascript")

        except httpx.RequestError:
            pass

    seen: set[tuple] = set()
    deduped: list[SecretFinding] = []
    for f in findings:
        key = (f.pattern_name, f.location, f.source_url)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    risk_score = scanner_score(
        sum(PENALTY[f.severity] for f in deduped), "secrets"
    )
    level = risk_level(risk_score)

    critical_triggers: list[str] = []
    if any(f.pattern_name in _LIVE_SECRET_LABELS for f in deduped):
        critical_triggers.append("live_secret")
    if any(f.pattern_name in _PRIVATE_KEY_LABELS for f in deduped):
        critical_triggers.append("private_key")

    return SecretScanResult(
        domain=domain,
        scan_timestamp=utc_now_iso(),
        findings=deduped,
        files_scanned=files_scanned,
        risk_score=risk_score,
        risk_level=level,
        critical_triggers=critical_triggers,
        summary={
            "files_scanned": files_scanned,
            "secrets_found": len(deduped),
            "high": sum(1 for f in deduped if f.severity == "high"),
            "medium": sum(1 for f in deduped if f.severity == "medium"),
        },
    )
