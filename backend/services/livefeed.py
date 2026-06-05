"""Live security news feed aggregator.

Aggregates from CISA KEV, NVD 2.0, and WPScan (if WPSCAN_API_TOKEN is set).
Results are stored in an in-memory list. The /api/v1/livefeed endpoint reads
from cache only — upstream is never hit on a user request.

Refresh runs on startup and every 30 minutes via APScheduler.
"""

import asyncio
import hashlib
import html
import logging
import os
import re
from datetime import datetime, timezone, timedelta

import httpx

log = logging.getLogger(__name__)

_cache: list[dict] = []
_CACHE_POPULATED = False

_USER_AGENT = "SiteGuard-SecurityScanner/1.0 (contact: hello@siteguard.app)"
_MAX_AGE_DAYS = 14
_MAX_ITEMS = 10
_NVD_KEYWORDS = ["shopify", "wordpress", "woocommerce", "magento", "bigcommerce"]

WPSCAN_TOKEN = os.getenv("WPSCAN_API_TOKEN", "")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def _strip_html(text: str) -> str:
    text = html.unescape(text)
    return re.sub(r"<[^>]+>", "", text).strip()


def _normalize(text: str) -> str:
    text = _strip_html(text)[:140].strip()
    if text and text[-1] not in ".!?":
        text += "."
    return text


def _is_recent(dt: datetime) -> bool:
    cutoff = datetime.now(timezone.utc) - timedelta(days=_MAX_AGE_DAYS)
    return dt >= cutoff


# ---------------------------------------------------------------------------
# Source fetchers — each wrapped in its own try/except
# ---------------------------------------------------------------------------

async def _fetch_cisa_kev(client: httpx.AsyncClient) -> list[dict]:
    """Download the full CISA KEV catalogue and return items added in the last 14 days."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        resp = await client.get(url, timeout=20)
        resp.raise_for_status()
        items = []
        for vuln in resp.json().get("vulnerabilities", []):
            date_str = vuln.get("dateAdded", "")
            try:
                dt = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if not _is_recent(dt):
                continue
            cve_id = vuln.get("cveID", "")
            vendor = vuln.get("vendorProject", "")
            product = vuln.get("product", "")
            name = vuln.get("vulnerabilityName", "")
            headline = f"{cve_id}: {name} ({vendor} {product}) is actively exploited."
            items.append({
                "id": f"cisa-{cve_id}",
                "headline": _normalize(headline),
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "published_at": dt.isoformat(),
            })
        log.info("CISA KEV: %d recent items", len(items))
        return items
    except Exception as exc:
        log.error("CISA KEV fetch failed: %s", exc)
        return []


async def _fetch_nvd(client: httpx.AsyncClient) -> list[dict]:
    """Query NVD 2.0 for recent CVEs matching store-platform keywords."""
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers: dict[str, str] = {"User-Agent": _USER_AGENT}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    seen: set[str] = set()
    items: list[dict] = []

    for keyword in _NVD_KEYWORDS:
        try:
            # Stay within the unauthenticated NVD rate limit (5 req / 30 s)
            await asyncio.sleep(2)
            resp = await client.get(
                base_url,
                params={"keywordSearch": keyword, "resultsPerPage": 5},
                headers=headers,
                timeout=25,
            )
            resp.raise_for_status()
            for vuln in resp.json().get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id or cve_id in seen:
                    continue
                seen.add(cve_id)
                published = cve.get("published", "")
                try:
                    dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    continue
                if not _is_recent(dt):
                    continue
                descriptions = cve.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), cve_id)
                items.append({
                    "id": f"nvd-{cve_id}",
                    "headline": _normalize(f"{cve_id}: {desc}"),
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "published_at": dt.isoformat(),
                })
        except Exception as exc:
            log.error("NVD fetch failed for keyword '%s': %s", keyword, exc)

    log.info("NVD: %d recent items", len(items))
    return items


async def _fetch_wpscan(client: httpx.AsyncClient) -> list[dict]:
    """Fetch WPScan plugin vulnerability feed. Requires WPSCAN_API_TOKEN env var."""
    if not WPSCAN_TOKEN:
        return []
    url = "https://wpscan.com/api/v3/vulnerabilities/plugins"
    try:
        resp = await client.get(
            url,
            headers={"Authorization": f"Token token={WPSCAN_TOKEN}", "User-Agent": _USER_AGENT},
            params={"page": 1, "per_page": 10},
            timeout=15,
        )
        if resp.status_code in (401, 403):
            log.warning("WPScan: invalid or missing API token")
            return []
        resp.raise_for_status()
        data = resp.json()
        entries = data if isinstance(data, list) else data.get("vulnerabilities", [])
        items = []
        for entry in entries:
            title = entry.get("title", "")
            refs = entry.get("references", {}).get("url", []) if entry.get("references") else []
            link = refs[0] if refs else "https://wpscan.com/"
            date_str = entry.get("created_at", "")
            try:
                dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                continue
            if not _is_recent(dt):
                continue
            item_id = hashlib.md5(title.encode()).hexdigest()[:12]
            items.append({
                "id": f"wpscan-{item_id}",
                "headline": _normalize(f"WordPress plugin vulnerability: {title}"),
                "url": link,
                "published_at": dt.isoformat(),
            })
        log.info("WPScan: %d items", len(items))
        return items
    except Exception as exc:
        log.error("WPScan fetch failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Merge + cache update
# ---------------------------------------------------------------------------

def _merge(sources: list[list[dict]]) -> list[dict]:
    seen: set[str] = set()
    merged: list[dict] = []
    for source in sources:
        for item in source:
            if item["id"] not in seen:
                seen.add(item["id"])
                merged.append(item)
    merged.sort(key=lambda x: x["published_at"], reverse=True)
    return merged[:_MAX_ITEMS]


async def refresh() -> None:
    """Pull all sources, merge, dedupe, and update the in-memory cache.
    If all sources fail, the existing cache is preserved unchanged.
    """
    global _cache, _CACHE_POPULATED
    log.info("livefeed: starting refresh")

    async with httpx.AsyncClient(headers={"User-Agent": _USER_AGENT}) as client:
        results = await asyncio.gather(
            _fetch_cisa_kev(client),
            _fetch_nvd(client),
            _fetch_wpscan(client),
            return_exceptions=True,
        )

    sources: list[list[dict]] = []
    for label, result in zip(("cisa", "nvd", "wpscan"), results):
        if isinstance(result, Exception):
            log.error("livefeed source '%s' raised: %s", label, result)
        elif isinstance(result, list):
            sources.append(result)

    if not any(sources):
        log.warning("livefeed: all sources failed — keeping last good cache")
        return

    merged = _merge(sources)
    if merged:
        _cache = merged
        _CACHE_POPULATED = True
        log.info("livefeed: cache updated with %d items", len(merged))


def get_items() -> list[dict]:
    """Return the cached feed. Always returns a list (empty on cold start)."""
    return list(_cache)
