#!/usr/bin/env python3
"""
Phase 1 — Build research target list.

Downloads the Cisco Umbrella top-1M list (or uses a cached copy), filters to
apex domains only (skipping CDN subdomains, IP-arpa entries, infrastructure),
then async-fingerprints to find Shopify and WordPress e-commerce stores.

Key improvements over naïve approach:
  • Skip ranks 1-10k (mega-corporations/pure infrastructure)
  • Filter to apex domains (≤2 meaningful parts) — discards CDN subdomains
  • 5 s HTTP timeout instead of 8 s
  • 100 concurrent workers
  • Umbrella CSV is cached to disk so re-runs are instant

Output: data/targets.csv  (rank, domain, platform)
"""
import asyncio
import csv
import io
import sys
import zipfile
from pathlib import Path

import httpx

DATA_DIR      = Path(__file__).resolve().parents[2] / "data"
OUT_CSV       = DATA_DIR / "targets.csv"
CACHE_CSV     = DATA_DIR / "_umbrella_cache.csv"

QUOTA         = {"shopify": 250, "wordpress": 250}
START_RANK    = 10_000   # skip ranks 1-10k (Google, Akamai, Facebook, etc.)
WORKERS       = 100
TIMEOUT       = 5.0
UA            = "SiteGuard-Research/1.0 (+https://siteguard-trust.lovable.app/methodology)"

# TLDs that are never e-commerce stores
SKIP_TLDS     = {"gov", "mil", "edu", "int", "arpa", "local", "internal"}

# Substrings that flag infrastructure/CDN domains
INFRA_KWORDS  = {
    "akamai", "akamaitech", "akadns", "edgekey", "edgesuite",
    "cloudfront", "googleusercontent", "googlevideo", "googlesyndication",
    "gstatic", "doubleclick", "fbcdn", "fbsbx", "twimg",
    "amazonaws", "azurewebsites", "icloud", "in-addr", "ip6",
    "msecnd", "mimecast", "spamhaus", "barracuda",
}


# ── Domain filtering ─────────────────────────────────────────────────────────

# Second-level TLDs that form 2-part country-code domains (e.g. domain.co.uk)
_CC2 = {"co", "com", "org", "net", "gov", "edu", "ac", "ne", "or"}

def is_website_domain(domain: str) -> bool:
    """
    Return True if the domain looks like an actual website (not CDN/infra).
    Accepts apex domains (domain.tld) and 2-part country-code TLDs (domain.co.uk).
    Rejects subdomains and infrastructure entries.
    """
    domain = domain.lower().strip()
    if not domain:
        return False

    # Reject obvious infrastructure keywords anywhere in the domain
    if any(kw in domain for kw in INFRA_KWORDS):
        return False

    parts = domain.split(".")
    if len(parts) < 2:
        return False

    tld = parts[-1]
    if tld in SKIP_TLDS:
        return False

    # Apex domain — exactly 2 parts
    if len(parts) == 2:
        return True

    # 3-part: allow domain.co.uk style, reject obvious subdomains
    if len(parts) == 3:
        return parts[-2] in _CC2  # e.g. domain.co.uk → parts[-2]="co"

    # 4+ parts → almost always a subdomain or CDN entry
    return False


# ── Download / cache Umbrella list ───────────────────────────────────────────

async def _get_umbrella_lines() -> list[str]:
    if CACHE_CSV.exists() and CACHE_CSV.stat().st_size > 1_000_000:
        print(f"   Using cached list ({CACHE_CSV.stat().st_size // 1_048_576} MB)", flush=True)
        return CACHE_CSV.read_text(errors="replace").splitlines()

    print("⬇  Downloading Cisco Umbrella top-1M …", flush=True)
    async with httpx.AsyncClient(
        timeout=120,
        headers={"User-Agent": UA},
        follow_redirects=True,
    ) as client:
        r = await client.get(
            "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
        )
        r.raise_for_status()

    content = r.content
    if content[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            csv_name = next(n for n in zf.namelist() if not n.endswith("/"))
            content = zf.read(csv_name)

    text = content.decode("utf-8", errors="replace")
    CACHE_CSV.parent.mkdir(parents=True, exist_ok=True)
    CACHE_CSV.write_text(text)
    print(f"   Downloaded and cached {len(content) // 1_048_576} MB", flush=True)
    return text.splitlines()


# ── HTTP fingerprinting ──────────────────────────────────────────────────────

async def _fingerprint(domain: str, client: httpx.AsyncClient) -> str | None:
    """
    Returns 'shopify', 'wordpress', or None.

    Runs three checks in parallel:
      1. Homepage HTML / headers  (most sites)
      2. /wp-login.php            (reliable WordPress signal)
      3. /products.json           (reliable Shopify signal)
    """
    async def _homepage() -> str | None:
        for scheme in ("https", "http"):
            try:
                r = await client.get(
                    f"{scheme}://{domain}/",
                    follow_redirects=True,
                    timeout=TIMEOUT,
                )
                text = r.text.lower()
                hdrs = {k.lower(): v.lower() for k, v in r.headers.items()}

                if "cdn.shopify.com" in text:
                    return "shopify"
                if "x-shopify-stage" in hdrs or "x-shopify-shop-api-call-limit" in hdrs:
                    return "shopify"
                if ".myshopify.com" in str(r.url):
                    return "shopify"
                if "wp-content/uploads/" in text or "wp-includes/js/" in text:
                    return "wordpress"
                if 'name="generator" content="wordpress' in text:
                    return "wordpress"
                if "wordpress" in hdrs.get("x-powered-by", ""):
                    return "wordpress"
                return None
            except Exception:
                if scheme == "https":
                    continue
        return None

    async def _wp_login() -> bool:
        """GET /wp-login.php — 200 with 'wordpress' in body is definitive."""
        for scheme in ("https", "http"):
            try:
                r = await client.get(
                    f"{scheme}://{domain}/wp-login.php",
                    follow_redirects=True,
                    timeout=TIMEOUT,
                )
                if r.status_code == 200 and "wordpress" in r.text.lower():
                    return True
            except Exception:
                if scheme == "https":
                    continue
        return False

    async def _shopify_products() -> bool:
        """GET /products.json — Shopify-specific storefront API."""
        for scheme in ("https", "http"):
            try:
                r = await client.get(
                    f"{scheme}://{domain}/products.json",
                    follow_redirects=True,
                    timeout=TIMEOUT,
                )
                if r.status_code == 200:
                    ct = r.headers.get("content-type", "").lower()
                    if "json" in ct:
                        body = r.text
                        if '"products"' in body or '"handle"' in body:
                            return True
            except Exception:
                if scheme == "https":
                    continue
        return False

    # Run all three in parallel
    hp, wp, sf = await asyncio.gather(
        _homepage(), _wp_login(), _shopify_products(),
        return_exceptions=True,
    )

    if hp == "shopify" or sf is True:
        return "shopify"
    if hp == "wordpress" or wp is True:
        return "wordpress"
    return None


# ── Worker ───────────────────────────────────────────────────────────────────

async def _worker(
    queue:    asyncio.Queue,
    found:    dict,
    lock:     asyncio.Lock,
    results:  list,
    stop:     asyncio.Event,
    sem:      asyncio.Semaphore,
    client:   httpx.AsyncClient,
    counter:  list,
) -> None:
    while not stop.is_set():
        try:
            rank, domain = queue.get_nowait()
        except asyncio.QueueEmpty:
            await asyncio.sleep(0.05)
            continue

        async with sem:
            platform = await _fingerprint(domain, client)

        async with lock:
            counter[0] += 1
            if platform and found.get(platform, 0) < QUOTA.get(platform, 0):
                found[platform] += 1
                results.append((rank, domain, platform))
                s = found.get("shopify", 0)
                w = found.get("wordpress", 0)
                print(
                    f"\r   [{counter[0]:>6} checked]"
                    f"  Shopify {s:>3}/250"
                    f"  WordPress {w:>3}/250"
                    f"  {domain:<40}",
                    end="", flush=True,
                )
                if all(found.get(p, 0) >= q for p, q in QUOTA.items()):
                    stop.set()
                    return

        queue.task_done()


# ── Main ─────────────────────────────────────────────────────────────────────

async def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    raw_lines = await _get_umbrella_lines()

    # Build filtered candidate list
    candidates: list[tuple[int, str]] = []
    for line in raw_lines:
        parts = line.strip().split(",", 1)
        if len(parts) != 2:
            continue
        try:
            rank   = int(parts[0])
            domain = parts[1].strip().lower()
        except ValueError:
            continue
        if rank < START_RANK:
            continue
        if is_website_domain(domain):
            candidates.append((rank, domain))

    total = len(candidates)
    print(
        f"   {total:,} apex-domain candidates"
        f" (after filtering CDN subdomains, starting rank {START_RANK:,})",
        flush=True,
    )

    found   = {"shopify": 0, "wordpress": 0}
    results = []
    lock    = asyncio.Lock()
    stop    = asyncio.Event()
    sem     = asyncio.Semaphore(WORKERS)
    counter = [0]
    queue   = asyncio.Queue()

    for item in candidates:
        queue.put_nowait(item)

    limits = httpx.Limits(
        max_connections=WORKERS + 20,
        max_keepalive_connections=WORKERS,
    )
    print(
        f"🔍 Fingerprinting with {WORKERS} concurrent workers"
        f" (timeout={TIMEOUT}s) …",
        flush=True,
    )

    async with httpx.AsyncClient(
        limits=limits,
        headers={"User-Agent": UA},
        follow_redirects=True,
    ) as client:
        tasks = [
            asyncio.create_task(
                _worker(queue, found, lock, results, stop, sem, client, counter)
            )
            for _ in range(WORKERS)
        ]
        try:
            await asyncio.wait_for(stop.wait(), timeout=7200)
        except asyncio.TimeoutError:
            print("\n⚠  Timeout — using what was found", flush=True)
        finally:
            stop.set()
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    print(f"\n\n✅ Found: {found}", flush=True)
    print(f"   Checked {counter[0]:,} of {total:,} candidates", flush=True)

    if not results:
        print("ERROR: no targets found.", file=sys.stderr)
        sys.exit(1)

    results.sort(key=lambda x: x[0])
    with open(OUT_CSV, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["rank", "domain", "platform"])
        w.writerows(results)

    print(f"📄 Saved {len(results)} targets → {OUT_CSV}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
