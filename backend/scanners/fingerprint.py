"""
Website fingerprinting scanner.

Performs a single passive GET to the homepage and infers the technology
stack from response headers and HTML meta tags only. No active probing,
no path guessing beyond the homepage.

Detects:
  - CMS (WordPress, Drupal, Joomla, Ghost, Shopify, Squarespace, Wix)
  - Frameworks (Next.js, Nuxt, Laravel, Django, Rails, ASP.NET)
  - CDN / hosting provider (Cloudflare, Fastly, Akamai, Vercel, Netlify)
  - Web server (nginx, Apache, Caddy, IIS, LiteSpeed)
  - JavaScript libraries from script src tags
"""

import re
import httpx
from models.scan import FingerprintMatch, FingerprintScanResult, utc_now_iso
from scanners import SCAN_HEADERS

_TIMEOUT = 10
_HEADERS = dict(SCAN_HEADERS)

# ---------------------------------------------------------------------------
# Detection rules
# Each rule has:
#   source  : "header" | "header_value" | "html" | "cookie"
#   key     : header name (for header/header_value) or regex (for html/cookie)
#   pattern : regex applied to the value (for header_value) or key (for header)
#   name    : technology name
#   category: cms | framework | cdn | server | library
#   confidence: "high" | "medium" | "low"
# ---------------------------------------------------------------------------

_RULES: list[dict] = [
    # --- Web servers ---
    {"source": "header_value", "key": "server", "pattern": r"nginx",       "name": "nginx",       "category": "server",    "confidence": "high"},
    {"source": "header_value", "key": "server", "pattern": r"apache",      "name": "Apache",      "category": "server",    "confidence": "high"},
    {"source": "header_value", "key": "server", "pattern": r"caddy",       "name": "Caddy",       "category": "server",    "confidence": "high"},
    {"source": "header_value", "key": "server", "pattern": r"IIS",         "name": "IIS",         "category": "server",    "confidence": "high"},
    {"source": "header_value", "key": "server", "pattern": r"LiteSpeed",   "name": "LiteSpeed",   "category": "server",    "confidence": "high"},
    {"source": "header_value", "key": "server", "pattern": r"openresty",   "name": "OpenResty",   "category": "server",    "confidence": "high"},
    {"source": "header_value", "key": "server", "pattern": r"cloudflare",  "name": "Cloudflare",  "category": "cdn",       "confidence": "high"},

    # --- CDN / hosting ---
    {"source": "header",       "key": "cf-ray",                            "name": "Cloudflare",  "category": "cdn",       "confidence": "high"},
    {"source": "header",       "key": "x-vercel-id",                       "name": "Vercel",      "category": "cdn",       "confidence": "high"},
    {"source": "header",       "key": "x-netlify",                         "name": "Netlify",     "category": "cdn",       "confidence": "high"},
    {"source": "header",       "key": "x-nf-request-id",                   "name": "Netlify",     "category": "cdn",       "confidence": "high"},
    {"source": "header",       "key": "x-amz-cf-id",                       "name": "AWS CloudFront","category": "cdn",     "confidence": "high"},
    {"source": "header",       "key": "x-amz-request-id",                  "name": "AWS",         "category": "cdn",       "confidence": "medium"},
    {"source": "header_value", "key": "via",        "pattern": r"fastly",  "name": "Fastly",      "category": "cdn",       "confidence": "high"},
    {"source": "header_value", "key": "via",        "pattern": r"akamai",  "name": "Akamai",      "category": "cdn",       "confidence": "high"},
    {"source": "header",       "key": "x-github-request-id",               "name": "GitHub Pages","category": "cdn",       "confidence": "high"},
    {"source": "header",       "key": "fly-request-id",                    "name": "Fly.io",      "category": "cdn",       "confidence": "high"},
    {"source": "header",       "key": "x-render-origin-server",            "name": "Render",      "category": "cdn",       "confidence": "high"},

    # --- CMS ---
    {"source": "header_value", "key": "x-powered-by",  "pattern": r"WordPress",  "name": "WordPress",  "category": "cms", "confidence": "high"},
    {"source": "html",         "key": r"/wp-content/", "pattern": None,           "name": "WordPress",  "category": "cms", "confidence": "high"},
    {"source": "html",         "key": r'content="WordPress', "pattern": None,     "name": "WordPress",  "category": "cms", "confidence": "high"},
    {"source": "cookie",       "key": r"wordpress_",   "pattern": None,           "name": "WordPress",  "category": "cms", "confidence": "high"},

    {"source": "html",         "key": r'content="Drupal', "pattern": None,        "name": "Drupal",     "category": "cms", "confidence": "high"},
    {"source": "header",       "key": "x-drupal-cache",                           "name": "Drupal",     "category": "cms", "confidence": "high"},
    {"source": "header",       "key": "x-generator",                              "name": "Drupal",     "category": "cms", "confidence": "medium"},

    {"source": "html",         "key": r'content="Joomla', "pattern": None,        "name": "Joomla",     "category": "cms", "confidence": "high"},

    {"source": "html",         "key": r'content="Ghost', "pattern": None,         "name": "Ghost",      "category": "cms", "confidence": "high"},
    {"source": "header_value", "key": "x-powered-by", "pattern": r"Ghost",        "name": "Ghost",      "category": "cms", "confidence": "high"},

    {"source": "header_value", "key": "x-shopify-stage", "pattern": r".*",        "name": "Shopify",    "category": "cms", "confidence": "high"},
    {"source": "cookie",       "key": r"_shopify_",       "pattern": None,         "name": "Shopify",    "category": "cms", "confidence": "high"},

    {"source": "html",         "key": r'Squarespace',  "pattern": None,           "name": "Squarespace","category": "cms", "confidence": "medium"},
    {"source": "html",         "key": r'static\.squarespace\.com', "pattern": None,"name": "Squarespace","category": "cms","confidence": "high"},

    {"source": "html",         "key": r'wix\.com',     "pattern": None,           "name": "Wix",        "category": "cms", "confidence": "high"},
    {"source": "html",         "key": r'X-Wix-',       "pattern": None,           "name": "Wix",        "category": "cms", "confidence": "high"},

    {"source": "html",         "key": r'webflow\.com', "pattern": None,           "name": "Webflow",    "category": "cms", "confidence": "high"},

    # --- Frameworks ---
    {"source": "header",       "key": "x-nextjs-cache",                           "name": "Next.js",    "category": "framework", "confidence": "high"},
    {"source": "header",       "key": "x-nextjs-matched-path",                    "name": "Next.js",    "category": "framework", "confidence": "high"},
    {"source": "html",         "key": r'__NEXT_DATA__',  "pattern": None,         "name": "Next.js",    "category": "framework", "confidence": "high"},

    {"source": "html",         "key": r'__nuxt',        "pattern": None,          "name": "Nuxt.js",    "category": "framework", "confidence": "high"},

    {"source": "header_value", "key": "x-powered-by", "pattern": r"Laravel",      "name": "Laravel",    "category": "framework", "confidence": "high"},
    {"source": "cookie",       "key": r"laravel_session", "pattern": None,         "name": "Laravel",    "category": "framework", "confidence": "high"},

    {"source": "header_value", "key": "x-powered-by", "pattern": r"Express",      "name": "Express.js", "category": "framework", "confidence": "high"},

    {"source": "header_value", "key": "x-powered-by", "pattern": r"Django",       "name": "Django",     "category": "framework", "confidence": "high"},
    {"source": "cookie",       "key": r"csrftoken",     "pattern": None,           "name": "Django",     "category": "framework", "confidence": "medium"},
    {"source": "cookie",       "key": r"sessionid",     "pattern": None,           "name": "Django",     "category": "framework", "confidence": "low"},

    {"source": "header_value", "key": "x-powered-by", "pattern": r"PHP",          "name": "PHP",        "category": "framework", "confidence": "high"},
    {"source": "header",       "key": "x-php-version",                            "name": "PHP",        "category": "framework", "confidence": "high"},

    {"source": "header_value", "key": "x-powered-by", "pattern": r"ASP\.NET",     "name": "ASP.NET",    "category": "framework", "confidence": "high"},
    {"source": "header",       "key": "x-aspnet-version",                         "name": "ASP.NET",    "category": "framework", "confidence": "high"},

    {"source": "header_value", "key": "x-powered-by", "pattern": r"Ruby on Rails","name": "Ruby on Rails","category":"framework","confidence": "high"},

    # --- JS libraries (from HTML) ---
    {"source": "html",         "key": r'jquery[.-](\d[\d.]+)\.min\.js', "pattern": None, "name": "jQuery", "category": "library", "confidence": "high"},
    {"source": "html",         "key": r'react\.production\.min\.js',    "pattern": None, "name": "React",  "category": "library", "confidence": "high"},
    {"source": "html",         "key": r'vue(?:\.min)?\.js',             "pattern": None, "name": "Vue.js", "category": "library", "confidence": "high"},
    {"source": "html",         "key": r'angular(?:\.min)?\.js',         "pattern": None, "name": "Angular","category": "library", "confidence": "high"},
    {"source": "html",         "key": r'bootstrap(?:\.min)?\.(?:js|css)',"pattern": None,"name": "Bootstrap","category":"library","confidence": "medium"},
]


def _dedupe(matches: list[FingerprintMatch]) -> list[FingerprintMatch]:
    seen: set[str] = set()
    out: list[FingerprintMatch] = []
    for m in matches:
        if m.name not in seen:
            seen.add(m.name)
            out.append(m)
    return out


async def scan_fingerprint(domain: str) -> FingerprintScanResult:
    url = f"https://{domain}"
    headers_received: dict[str, str] = {}
    body = ""
    cookies_received: dict[str, str] = {}

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=_TIMEOUT,
            headers=_HEADERS,
        ) as client:
            resp = await client.get(url)
            headers_received = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.text[:200_000]  # cap at 200 KB to avoid memory issues
            cookies_received = {k.lower(): v for k, v in resp.cookies.items()}
    except httpx.RequestError:
        pass

    matches: list[FingerprintMatch] = []

    for rule in _RULES:
        source = rule["source"]
        name = rule["name"]
        category = rule["category"]
        confidence = rule["confidence"]
        evidence = None

        if source == "header":
            if rule["key"].lower() in headers_received:
                evidence = f"Header present: {rule['key']}"

        elif source == "header_value":
            val = headers_received.get(rule["key"].lower(), "")
            if val and re.search(rule["pattern"], val, re.IGNORECASE):
                evidence = f"{rule['key']}: {val}"

        elif source == "html":
            if body and re.search(rule["key"], body, re.IGNORECASE):
                evidence = f"Detected in page source: {rule['key']}"

        elif source == "cookie":
            for cname in cookies_received:
                if re.search(rule["key"], cname, re.IGNORECASE):
                    evidence = f"Cookie: {cname}"
                    break

        if evidence:
            matches.append(FingerprintMatch(
                name=name,
                category=category,
                confidence=confidence,
                evidence=evidence,
            ))

    matches = _dedupe(matches)

    categories: dict[str, list[str]] = {}
    for m in matches:
        categories.setdefault(m.category, []).append(m.name)

    return FingerprintScanResult(
        domain=domain,
        scan_timestamp=utc_now_iso(),
        matches=matches,
        summary={
            "total_detected": len(matches),
            "by_category": categories,
        },
    )
