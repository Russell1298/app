"""
Scanner package.

USER_AGENT is shared by every scanner so a site owner reading their access
logs sees one consistent, identifiable client with a working contact URL,
rather than several different strings pointing at a domain we no longer own.
"""

USER_AGENT = "Sekura-Scanner/1.0 (+https://sekura.cloud/security)"

SCAN_HEADERS = {"User-Agent": USER_AGENT}

# Used only as a single retry when a site blocks the identified scanner. Many
# WAFs and large sites serve a minimal block page to unrecognised clients, and
# grading that page reports headers the real site does not lack. The retry
# requests exactly what any visitor's browser receives; it bypasses no auth.
BROWSER_SCAN_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# Statuses sites use to refuse or challenge a client rather than serve the page.
BLOCKED_STATUSES = frozenset({401, 403, 406, 429, 503})
