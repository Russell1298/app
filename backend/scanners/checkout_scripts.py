"""
Checkout script scanner.

Passive inspection of <script> tags on cart and checkout pages.
Checks for missing Subresource Integrity (SRI), scripts loaded over HTTP,
IP-based script sources, and obfuscation patterns associated with payment
skimmers (Magecart-style eval/atob/document.write abuse).
"""

import re
import hashlib
import asyncio
from html.parser import HTMLParser
import httpx
from models.scan import (
    ScriptEntry, CheckoutScriptFinding, CheckoutScriptScanResult, utc_now_iso
)
from scoring_config import PENALTY, scanner_score, risk_level

_CHECKOUT_PATHS = ["/cart", "/checkout", "/shop/cart", "/bag"]

_SUSPICIOUS_PATTERNS: list[tuple[str, str]] = [
    ("eval_call",       r"\beval\s*\("),
    ("atob_call",       r"\batob\s*\("),
    ("doc_write",       r"document\.write\s*\("),
    ("unescape_call",   r"\bunescape\s*\("),
    ("fromcharcode",    r"String\.fromCharCode\s*\("),
    ("hex_obfuscation", r"(?:\\x[0-9a-fA-F]{2}){6,}"),
]

_IP_SRC_RE = re.compile(r"^https?://(\d{1,3}\.){3}\d{1,3}[:/]?")


class _ScriptTagParser(HTMLParser):
    """Extract all <script> attributes and inline content from HTML."""

    def __init__(self) -> None:
        super().__init__()
        self.scripts: list[dict] = []
        self._current: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "script":
            return
        attr_map = dict(attrs)
        self._current = {
            "src": attr_map.get("src"),
            "integrity": attr_map.get("integrity"),
            "content": "",
        }

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._current is not None:
            self.scripts.append(self._current)
            self._current = None

    def handle_data(self, data: str) -> None:
        if self._current is not None:
            self._current["content"] += data


def _parse_scripts(html: str) -> list[dict]:
    parser = _ScriptTagParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    return parser.scripts


def _is_ip_src(src: str) -> bool:
    return bool(_IP_SRC_RE.match(src))


def _is_http_src(src: str) -> bool:
    return src.startswith("http://")


def _suspicious_in_content(content: str) -> list[str]:
    return [name for name, pattern in _SUSPICIOUS_PATTERNS if re.search(pattern, content)]


def _content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()[:16]


async def _fetch_page(client: httpx.AsyncClient, url: str) -> str | None:
    try:
        resp = await client.get(
            url,
            timeout=10,
            follow_redirects=True,
            headers={
                "User-Agent": (
                    "SiteGuard-Scanner/1.0 (passive security assessment; "
                    "contact: security@siteguard.app)"
                )
            },
        )
        ct = resp.headers.get("content-type", "")
        if resp.status_code == 200 and "text/html" in ct:
            return resp.text
    except Exception:
        pass
    return None


def _build_findings(
    scripts_by_page: dict[str, list[dict]],
    domain: str,
) -> tuple[list[ScriptEntry], list[CheckoutScriptFinding]]:
    entries: list[ScriptEntry] = []
    findings: list[CheckoutScriptFinding] = []

    reported_no_sri: set[str] = set()
    reported_http: set[str] = set()
    reported_ip: set[str] = set()
    reported_patterns: set[str] = set()

    for page_url, raw_scripts in scripts_by_page.items():
        is_checkout_page = any(p in page_url for p in ("/cart", "/checkout", "/bag"))

        for script in raw_scripts:
            src: str | None = script["src"]
            integrity: str | None = script["integrity"]
            content: str = script["content"].strip()
            is_inline = src is None
            is_http = bool(src and _is_http_src(src))
            is_ip = bool(src and _is_ip_src(src))
            has_sri = bool(integrity)
            patterns = _suspicious_in_content(content) if is_inline else []

            entries.append(ScriptEntry(
                src=src,
                is_inline=is_inline,
                has_sri=has_sri,
                is_http=is_http,
                is_ip_src=is_ip,
                suspicious_patterns=patterns,
            ))

            # Script served over plain HTTP
            if is_http and src not in reported_http:
                reported_http.add(src or "")
                findings.append(CheckoutScriptFinding(
                    finding_id="script_over_http",
                    severity="high",
                    description=(
                        f"A JavaScript file is loaded over plain HTTP: {src}. "
                        "An attacker on the same network can silently replace the script "
                        "content in transit — the exact delivery mechanism for payment skimmers."
                    ),
                    remediation=(
                        "Change the script URL to HTTPS. If the provider doesn't support HTTPS, "
                        "replace it with one that does. Every resource on a store page must "
                        "load over an encrypted connection."
                    ),
                    evidence=f"Page: {page_url}\nScript src: {src}",
                    penalty=PENALTY["high"],
                ))

            # Script loaded from a bare IP address
            if is_ip and src not in reported_ip:
                reported_ip.add(src or "")
                findings.append(CheckoutScriptFinding(
                    finding_id="script_from_ip",
                    severity="high",
                    description=(
                        f"A script is loaded directly from an IP address: {src}. "
                        "Legitimate analytics, CDNs, and payment providers always use named "
                        "domains, not bare IPs. This is a strong indicator of a Magecart-style "
                        "payment skimmer injected into the page."
                    ),
                    remediation=(
                        "Remove this script immediately and audit your site for compromise. "
                        "Check your plugins, theme files, and CMS for unexplained recent changes. "
                        "Rotate any admin credentials and consider restoring from a clean backup."
                    ),
                    evidence=f"Page: {page_url}\nScript src: {src}",
                    penalty=PENALTY["high"],
                ))

            # External script on checkout page without SRI
            if (
                is_checkout_page
                and not is_inline
                and not has_sri
                and src
                and src not in reported_no_sri
                and domain.lower() not in src.lower()
            ):
                reported_no_sri.add(src)
                findings.append(CheckoutScriptFinding(
                    finding_id="no_sri_on_checkout_script",
                    severity="high",
                    description=(
                        f"An external script on a checkout page has no Subresource Integrity "
                        f"(SRI) attribute: {src}. "
                        "If the script's host is ever compromised, the browser will silently "
                        "execute the modified code — the exact attack model used by Magecart "
                        "skimmers targeting online stores."
                    ),
                    remediation=(
                        "Add an integrity= attribute to the <script> tag. Generate the hash with: "
                        "curl -s <URL> | openssl dgst -sha384 -binary | openssl base64 -A "
                        "then set: integrity=\"sha384-<hash>\" crossorigin=\"anonymous\". "
                        "Consider a payment-focused CSP that blocks unauthorised script sources."
                    ),
                    evidence=f"Page: {page_url}\nScript src: {src}\nSRI: absent",
                    penalty=PENALTY["high"],
                ))

            # Suspicious inline obfuscation patterns
            for pattern_name in patterns:
                dedup_key = f"{page_url}:{pattern_name}"
                if dedup_key not in reported_patterns:
                    reported_patterns.add(dedup_key)
                    is_severe = pattern_name in ("eval_call", "atob_call", "hex_obfuscation")
                    sev: str = "high" if is_severe else "medium"
                    findings.append(CheckoutScriptFinding(
                        finding_id=f"suspicious_pattern_{pattern_name}",
                        severity=sev,  # type: ignore[arg-type]
                        description=(
                            f"Suspicious JavaScript pattern '{pattern_name}' found on {page_url}. "
                            "This technique is commonly used to hide payment skimmer code from "
                            "simple code review. Legitimate scripts rarely use runtime eval or "
                            "base64 decoding, especially on checkout pages."
                        ),
                        remediation=(
                            "Audit all inline JavaScript on this page. If you didn't write this "
                            "code, treat it as a potential compromise — check your plugins and "
                            "theme files for recent unexplained modifications. "
                            "Consider a CSP that blocks all inline scripts."
                        ),
                        evidence=(
                            f"Page: {page_url}\n"
                            f"Pattern: {pattern_name}\n"
                            f"Inline script content hash: {_content_hash(content)}"
                        ),
                        penalty=PENALTY[sev],
                    ))

    return entries, findings


async def scan_checkout_scripts(domain: str) -> CheckoutScriptScanResult:
    urls = [f"https://{domain}/"] + [f"https://{domain}{p}" for p in _CHECKOUT_PATHS]

    scripts_by_page: dict[str, list[dict]] = {}
    pages_scanned: list[str] = []

    async with httpx.AsyncClient(verify=True) as client:
        results = await asyncio.gather(
            *[_fetch_page(client, url) for url in urls],
            return_exceptions=True,
        )

    for url, result in zip(urls, results):
        if isinstance(result, str) and result:
            pages_scanned.append(url)
            scripts_by_page[url] = _parse_scripts(result)

    entries, findings = _build_findings(scripts_by_page, domain)

    critical_triggers: list[str] = []
    if any(f.finding_id == "script_from_ip" for f in findings):
        critical_triggers.append("skimmer_detected")
    if any(f.finding_id == "script_over_http" for f in findings):
        critical_triggers.append("script_over_http_checkout")

    total_penalty = sum(f.penalty for f in findings)
    score = scanner_score(total_penalty, "checkout_scripts")

    return CheckoutScriptScanResult(
        domain=domain,
        scan_timestamp=utc_now_iso(),
        pages_scanned=pages_scanned,
        scripts=entries,
        findings=findings,
        risk_score=score,
        risk_level=risk_level(score),
        critical_triggers=critical_triggers,
        summary={
            "pages_scanned": len(pages_scanned),
            "scripts_found": len(entries),
            "external_without_sri": sum(
                1 for e in entries if not e.is_inline and not e.has_sri
            ),
            "high_findings": sum(1 for f in findings if f.severity == "high"),
            "medium_findings": sum(1 for f in findings if f.severity == "medium"),
        },
    )
