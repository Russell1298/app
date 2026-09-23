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
from scanners.waf import Access, probe_access, waf_vendor

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

# Providers that document SRI as unsupported. Stripe requires stripe.js to be
# loaded directly from its CDN for PCI DSS compliance and Radar fraud detection,
# and updates the file frequently, so a pinned hash is not possible. Telling a
# merchant to "add integrity=" on these is advice they cannot act on, so the
# finding is reported without the high penalty and with remediation that works.
_SRI_UNSUPPORTED_HOSTS = (
    # Payments — vendors generate these per-merchant/currency/locale and update
    # them without notice. Pinning a hash breaks checkout the next time they ship.
    "js.stripe.com",
    "checkout.stripe.com",
    "www.paypal.com",
    "paypal.com/sdk",
    "paypalobjects.com",
    "js.braintreegateway.com",
    "web.squarecdn.com",
    "js.squareup.com",
    "pay.google.com",
    "applepay.cdn-apple.com",
    "checkout.klarna.com",
    "x.klarnacdn.net",
    "cdn.shopify.com",          # Shopify's own checkout assets
    "checkout.shopifycs.com",
    # SHOPLINE, like Shopify, renders checkout itself. A merchant cannot edit
    # the platform's own script tags, so telling them to add integrity= is
    # advice they cannot act on.
    "myshopline.com",
    "myshopline.shop",
    "shoplineapp.com",
    "shoplineimg.com",
    # Fraud / risk bootstraps — deliberately rotating payloads.
    "songbird.cardinalcommerce.com",
    "centinelapi.cardinalcommerce.com",
    "riskified.com",
    "signifyd.com",
    # Bot / consent — same rotation problem.
    "www.google.com/recaptcha",
    "www.gstatic.com/recaptcha",
    "hcaptcha.com",
)


# Tag managers, analytics and marketing pixels. Continuously updated by the
# vendor, so SRI cannot be used; the right advice is keeping them off payment pages.
_MARKETING_TAG_HOSTS = (
    "googletagmanager.com", "google-analytics.com", "connect.facebook.net", "static.hotjar.com",
    "js.hs-scripts.com", "js.hsforms.net", "js.hs-analytics.net", "snap.licdn.com",
    "analytics.tiktok.com", "bat.bing.com", "cdn.segment.com", "static.klaviyo.com",
    "widget.intercom.io", "js.intercomcdn.com", "cdn.cookielaw.org", "consent.cookiebot.com",
    "clarity.ms",
)


def _is_marketing_tag(src: str) -> bool:
    low = src.lower()
    return any(h in low for h in _MARKETING_TAG_HOSTS)


def _sri_unsupported(src: str) -> bool:
    low = src.lower()
    return any(h in low for h in _SRI_UNSUPPORTED_HOSTS)


# Evidence that a page actually takes payment details. A URL is not evidence:
# on hosted platforms /checkout often redirects elsewhere, and /cart is usually
# a basket page with no payment fields on it at all. Findings about "checkout
# scripts" are only defensible on a page where one of these is present.
# Evidence that a page actually takes payment details. A URL is not evidence:
# on hosted platforms /checkout often redirects elsewhere, and /cart is usually
# a basket page with no payment fields on it at all.
#
# Structural markers are a payment field, a payment iframe or a payment SDK -
# things that only appear where money is taken. Wording is supporting evidence
# only: "payment method" and "billing address" appear in basket footers, FAQs
# and policy pages, so on its own it would re-create the false positive this
# check exists to remove.
_PAYMENT_MARKERS_STRUCTURAL: list[tuple[str, str]] = [
    ("card_autocomplete",  r'autocomplete\s*=\s*["\']?cc-(?:number|exp|csc|name)'),
    ("card_field_name",    r'(?:name|id)\s*=\s*["\']?(?:card[-_]?number|cardnumber|cc[-_]?num|creditcard)'),
    ("cvv_field",          r'(?:name|id)\s*=\s*["\']?(?:cvv|cvc|csc|security[-_]?code)'),
    ("payment_iframe",     r'<iframe[^>]+src\s*=\s*["\']?https?://(?:[^"\'>\s/]*\.)?'
                           r'(?:stripe\.com|paypal\.com|braintreegateway\.com|squarecdn\.com|'
                           r'klarna\.com|adyen\.com|checkout\.shopifycs\.com|myshopline\.com)'),
    ("payment_sdk",        r'<script[^>]+src\s*=\s*["\']?https?://(?:js\.stripe\.com|'
                           r'www\.paypal\.com/sdk|js\.braintreegateway\.com|web\.squarecdn\.com|'
                           r'x\.klarnacdn\.net|checkout\.klarna\.com)'),
]

_PAYMENT_MARKERS_SUPPORTING: list[tuple[str, str]] = [
    ("payment_wording",    r'(?i)\b(?:card number|expiry date|security code|payment method|'
                           r'billing address)\b'),
]


def _payment_evidence(html: str) -> list[str]:
    """
    Return the payment markers present in *html*, or nothing at all.

    A page qualifies only on a structural marker. Supporting wording is listed
    alongside once it qualifies, and never qualifies a page by itself.
    """
    structural = [name for name, pattern in _PAYMENT_MARKERS_STRUCTURAL if re.search(pattern, html)]
    if not structural:
        return []
    supporting = [name for name, pattern in _PAYMENT_MARKERS_SUPPORTING if re.search(pattern, html)]
    return structural + supporting


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


async def _fetch_page(client: httpx.AsyncClient, url: str) -> tuple[str, str] | None:
    """
    Fetch *url* and return (final_url, html).

    The final URL matters: redirects are followed, and on a hosted platform the
    checkout usually lives on the platform's own hostname. Labelling those
    scripts with the URL we requested would name a page that never served them.
    """
    try:
        resp = await client.get(url, timeout=10, follow_redirects=True)
        ct = resp.headers.get("content-type", "")
        # A WAF challenge is not the checkout; its scripts are the vendor's.
        if resp.status_code == 200 and "text/html" in ct and not waf_vendor(resp):
            return str(resp.url), resp.text
    except Exception:
        pass
    return None


def _build_findings(
    scripts_by_page: dict[str, list[dict]],
    domain: str,
    payment_pages: dict[str, list[str]],
    requested_by_final: dict[str, str],
) -> tuple[list[ScriptEntry], list[CheckoutScriptFinding]]:
    entries: list[ScriptEntry] = []
    findings: list[CheckoutScriptFinding] = []

    reported_no_sri: set[str] = set()
    reported_http: set[str] = set()
    reported_ip: set[str] = set()
    reported_patterns: set[str] = set()

    for page_url, raw_scripts in scripts_by_page.items():
        # Only a page carrying payment-field evidence counts as a checkout page.
        payment_markers = payment_pages.get(page_url, [])
        is_checkout_page = bool(payment_markers)
        requested = requested_by_final.get(page_url, page_url)
        page_evidence = f"Page: {page_url}"
        if requested != page_url:
            page_evidence = f"Requested: {requested}\nServed by: {page_url}"

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
            if is_http and src not in reported_http and page_url.startswith("https://"):
                # Browsers refuse to run an http:// script on an https:// page, so it
                # cannot be swapped in transit: it simply never loads.
                reported_http.add(src or "")
                findings.append(CheckoutScriptFinding(
                    finding_id="script_over_http_blocked",
                    severity="medium",
                    description=(
                        f"A script on {page_url} is requested over plain HTTP: {src}. Browsers block "
                        "it on an HTTPS page, so it does not run: whatever it was added for is "
                        "currently broken."
                    ),
                    remediation=(
                        "Change the script URL to https://, or remove the tag if it is no longer "
                        "needed. If the provider has no HTTPS version, replace it."
                    ),
                    evidence=f"{page_evidence}\nScript src: {src}",
                    penalty=PENALTY["medium"],
                ))
            elif is_http and src not in reported_http:
                reported_http.add(src or "")
                findings.append(CheckoutScriptFinding(
                    finding_id="script_over_http",
                    severity="high",
                    description=(
                        f"A JavaScript file is loaded over plain HTTP: {src}. "
                        "An attacker on the same network can silently replace the script "
                        "content in transit. This is how payment skimmers get delivered."
                    ),
                    remediation=(
                        "Change the script URL to HTTPS. If the provider doesn't support HTTPS, "
                        "replace it with one that does. Every resource on a store page must "
                        "load over an encrypted connection."
                    ),
                    evidence=f"{page_evidence}\nScript src: {src}",
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
                        "domains. A bare IP here is a strong indicator of a Magecart-style "
                        "payment skimmer injected into the page."
                    ),
                    remediation=(
                        "Remove this script immediately and audit your site for compromise. "
                        "Check your plugins, theme files, and CMS for unexplained recent changes. "
                        "Rotate any admin credentials and consider restoring from a clean backup."
                    ),
                    evidence=f"{page_evidence}\nScript src: {src}",
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
                if _is_marketing_tag(src):
                    findings.append(CheckoutScriptFinding(
                        finding_id="third_party_tag_on_checkout",
                        severity="medium",
                        description=(
                            f"An analytics or marketing tag runs on a page that takes payment details: {src}. "
                            "The vendor changes this file continuously, so an integrity attribute cannot be "
                            "used; but any script on the page can read what is typed into it, which makes "
                            "these tags a known route for card-skimming when a vendor is compromised."
                        ),
                        remediation=(
                            "Remove analytics and marketing tags from payment pages, or fire them only after "
                            "payment completes. Keep any that must stay in a written script inventory with "
                            "the reason (PCI DSS 6.4.3), and limit script-src in a Content-Security-Policy."
                        ),
                        evidence=(f"{page_evidence}\nScript src: {src}\n"
                                  f"Payment page evidence: {', '.join(payment_markers)}"),
                        penalty=PENALTY["medium"],
                    ))
                elif _sri_unsupported(src):
                    findings.append(CheckoutScriptFinding(
                        finding_id="sri_unsupported_payment_script",
                        severity="low",
                        description=(
                            f"A payment provider script on a checkout page has no Subresource "
                            f"Integrity (SRI) attribute: {src}. This provider does not support "
                            "SRI. The script must be loaded directly from their CDN to keep PCI "
                            "DSS compliance and live fraud detection working, and it changes too "
                            "often for a pinned hash. The residual risk is real and accepted "
                            "across the industry."
                        ),
                        remediation=(
                            "Leave the script as it is. Adding an integrity attribute would break "
                            "payments. Reduce the risk another way: set a Content-Security-Policy "
                            "that limits script-src to the exact payment domains you use, and keep "
                            "a written inventory of every script on your checkout pages, which PCI "
                            "DSS 6.4.3 requires."
                        ),
                        evidence=(f"{page_evidence}\nScript src: {src}\n"
                                  f"Payment page evidence: {', '.join(payment_markers)}\n"
                                  "SRI: not supported by provider"),
                        penalty=PENALTY["low"],
                    ))
                else:
                  findings.append(CheckoutScriptFinding(
                    finding_id="no_sri_on_checkout_script",
                    severity="high",
                    description=(
                        f"An external script on a checkout page has no Subresource Integrity "
                        f"(SRI) attribute: {src}. "
                        "If the script's host is ever compromised, the browser will silently "
                        "execute the modified code. This is the attack model Magecart uses "
                        "skimmers targeting online stores."
                    ),
                    remediation=(
                        "Add an integrity= attribute to the <script> tag. Generate the hash with: "
                        "curl -s <URL> | openssl dgst -sha384 -binary | openssl base64 -A "
                        "then set: integrity=\"sha384-<hash>\" crossorigin=\"anonymous\". "
                        "Consider a payment-focused CSP that blocks unauthorized script sources."
                    ),
                    evidence=(f"{page_evidence}\nScript src: {src}\n"
                           f"Payment page evidence: {', '.join(payment_markers)}\n"
                           "SRI: absent"),
                    penalty=PENALTY["high"],
                ))

            # Obfuscation-style calls. Themes, tag managers and consent tools use these
            # routinely, so they are only worth raising where card details are entered,
            # and even there they are a prompt to review, not evidence of compromise.
            if not is_checkout_page:
                patterns = []
            for pattern_name in patterns:
                dedup_key = f"{page_url}:{pattern_name}"
                if dedup_key not in reported_patterns:
                    reported_patterns.add(dedup_key)
                    sev: str = "medium" if pattern_name in ("eval_call", "hex_obfuscation") else "low"
                    findings.append(CheckoutScriptFinding(
                        finding_id=f"suspicious_pattern_{pattern_name}",
                        severity=sev,  # type: ignore[arg-type]
                        description=(
                            f"An inline script on a payment page ({page_url}) uses '{pattern_name}'. "
                            "Legitimate code uses this too, and payment skimmers use it to hide, so it "
                            "is worth confirming where the script comes from. On its own it is not "
                            "evidence of compromise."
                        ),
                        remediation=(
                            "Ask your developer to identify which theme, plugin or tag added this "
                            "inline script. If nobody recognises it, compare it with a clean backup and "
                            "check for recent unexplained changes to plugins and theme files."
                        ),
                        evidence=(
                            f"{page_evidence}\n"
                            f"Pattern: {pattern_name}\n"
                            f"Inline script content hash: {_content_hash(content)}"
                        ),
                        penalty=PENALTY[sev],
                    ))

    return entries, findings


async def scan_checkout_scripts(domain: str, access: Access | None = None) -> CheckoutScriptScanResult:
    access = access or await probe_access(domain)
    urls = [f"https://{domain}/"] + [f"https://{domain}{p}" for p in _CHECKOUT_PATHS]

    scripts_by_page: dict[str, list[dict]] = {}
    pages_scanned: list[str] = []
    payment_pages: dict[str, list[str]] = {}
    requested_by_final: dict[str, str] = {}

    results: list = []
    if not access.blocked:
        async with httpx.AsyncClient(verify=True, headers=access.request_headers) as client:
            results = await asyncio.gather(
                *[_fetch_page(client, url) for url in urls],
                return_exceptions=True,
            )

    for url, result in zip(urls, results):
        if not isinstance(result, tuple):
            continue
        final_url, html = result
        if not html or final_url in scripts_by_page:
            continue            # a redirect can land several requests on one page
        pages_scanned.append(final_url)
        requested_by_final[final_url] = url
        scripts_by_page[final_url] = _parse_scripts(html)
        markers = _payment_evidence(html)
        if markers:
            payment_pages[final_url] = markers

    entries, findings = _build_findings(scripts_by_page, domain, payment_pages, requested_by_final)

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
            **({"error": access.blocked, "verified": False} if access.blocked else {"verified": True}),
            "pages_scanned": len(pages_scanned),
            # A page is only a checkout page when it carries payment evidence.
            # Zero here means no payment page was reached, which is a gap in the
            # scan, not a clean checkout.
            "payment_pages_confirmed": len(payment_pages),
            "payment_page_urls": sorted(payment_pages),
            "scripts_found": len(entries),
            "external_without_sri": sum(
                1 for e in entries if not e.is_inline and not e.has_sri
            ),
            "high_findings": sum(1 for f in findings if f.severity == "high"),
            "medium_findings": sum(1 for f in findings if f.severity == "medium"),
        },
    )
