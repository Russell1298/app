"""Live security news feed aggregator.

Aggregates from:
  - The Hacker News RSS
  - BleepingComputer RSS
  - CISA Known Exploited Vulnerabilities (KEV)
  - WPScan (optional, requires WPSCAN_API_TOKEN)

Results are stored in an in-memory list and served by /api/livefeed.
Upstream sources are never hit on a user request — only during the
scheduled refresh (startup + every 30 minutes via APScheduler).
"""

import asyncio
import hashlib
import html
import logging
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime as rfc2822_parse

import httpx

log = logging.getLogger(__name__)

_cache: list[dict] = []
_CACHE_POPULATED = False

_USER_AGENT = "SiteGuard-SecurityScanner/1.0 (contact: hello@siteguard.app)"
_MAX_AGE_DAYS = 14
_MAX_ITEMS = 10

WPSCAN_TOKEN = os.getenv("WPSCAN_API_TOKEN", "")

_RSS_FEEDS = [
    ("https://feeds.feedburner.com/TheHackersNews", "The Hacker News"),
    ("https://www.bleepingcomputer.com/feed/", "BleepingComputer"),
]


# ---------------------------------------------------------------------------
# Helpers
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
# Source fetchers
# ---------------------------------------------------------------------------

async def _fetch_rss(client: httpx.AsyncClient, feed_url: str, source_name: str) -> list[dict]:
    """Fetch and parse an RSS 2.0 feed, returning recent items."""
    try:
        resp = await client.get(feed_url, timeout=15)
        resp.raise_for_status()
        root = ET.fromstring(resp.content)
        items = []
        for item in root.findall(".//item")[:20]:
            title = (item.findtext("title") or "").strip()
            link = (item.findtext("link") or "").strip()
            pub_date = (item.findtext("pubDate") or "").strip()
            if not title or not link:
                continue
            try:
                dt = rfc2822_parse(pub_date).astimezone(timezone.utc)
            except Exception:
                dt = datetime.now(timezone.utc)
            if not _is_recent(dt):
                continue
            item_id = hashlib.md5(link.encode()).hexdigest()[:12]
            items.append({
                "id": f"rss-{item_id}",
                "headline": _normalize(title),
                "url": link,
                "published_at": dt.isoformat(),
            })
        log.info("%s RSS: %d recent items", source_name, len(items))
        return items
    except Exception as exc:
        log.error("%s RSS fetch failed: %s", source_name, exc)
        return []


async def _fetch_cisa_kev(client: httpx.AsyncClient) -> list[dict]:
    """Download the CISA KEV catalogue and return items added in the last 14 days."""
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
            headline = f"{cve_id}: {name} in {vendor} {product} is actively exploited."
            items.append({
                "id": f"cisa-{cve_id}",
                "headline": _normalize(headline),
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "published_at": dt.isoformat(),
            })
        log.info("CISA KEV: %d recent items", len(items))
        return items
    except Exception as exc:
        log.error("CISA KEV fetch failed: %s", exc)
        return []


async def _fetch_wpscan(client: httpx.AsyncClient) -> list[dict]:
    """Fetch WPScan plugin vulnerability feed. Skipped if WPSCAN_API_TOKEN is not set."""
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
        rss_coros = [_fetch_rss(client, url, name) for url, name in _RSS_FEEDS]
        results = await asyncio.gather(
            _fetch_cisa_kev(client),
            *rss_coros,
            _fetch_wpscan(client),
            return_exceptions=True,
        )

    source_names = ["cisa"] + [name for _, name in _RSS_FEEDS] + ["wpscan"]
    sources: list[list[dict]] = []
    for label, result in zip(source_names, results):
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
