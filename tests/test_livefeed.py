"""Tests for the livefeed aggregator."""
import pytest
from unittest.mock import AsyncMock, patch
from services import livefeed as lf


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

CISA_ITEMS = [
    {"id": "cisa-CVE-2024-1000", "headline": "CVE-2024-1000: RCE in WordPress Plugin.", "url": "https://cisa.gov", "published_at": "2026-05-20T00:00:00+00:00"},
    {"id": "cisa-CVE-2024-1001", "headline": "CVE-2024-1001: SQLi in WooCommerce.", "url": "https://cisa.gov", "published_at": "2026-05-19T00:00:00+00:00"},
]
NVD_ITEMS = [
    {"id": "nvd-CVE-2024-9999", "headline": "CVE-2024-9999: Critical Shopify API flaw.", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-9999", "published_at": "2026-05-21T00:00:00+00:00"},
]
WPSCAN_ITEMS = [
    {"id": "wpscan-abc123", "headline": "WordPress plugin vulnerability: Contact Form 7 XSS.", "url": "https://wpscan.com", "published_at": "2026-05-18T00:00:00+00:00"},
]


def _reset_cache():
    lf._cache = []
    lf._CACHE_POPULATED = False


# ---------------------------------------------------------------------------
# Successful merge from all sources
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_successful_merge_all_sources():
    """All sources succeed — merged items sorted newest-first, capped at 10."""
    _reset_cache()
    with patch.object(lf, "_fetch_cisa_kev", AsyncMock(return_value=CISA_ITEMS)), \
         patch.object(lf, "_fetch_nvd", AsyncMock(return_value=NVD_ITEMS)), \
         patch.object(lf, "_fetch_wpscan", AsyncMock(return_value=WPSCAN_ITEMS)):
        await lf.refresh()

    items = lf.get_items()
    assert lf._CACHE_POPULATED is True
    assert len(items) == 4
    # Newest first
    assert items[0]["id"] == "nvd-CVE-2024-9999"
    # No duplicates
    ids = [i["id"] for i in items]
    assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# One source failing
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_one_source_failing_nvd():
    """NVD raises an exception — cache still populated from CISA + WPScan."""
    _reset_cache()
    with patch.object(lf, "_fetch_cisa_kev", AsyncMock(return_value=CISA_ITEMS)), \
         patch.object(lf, "_fetch_nvd", AsyncMock(side_effect=Exception("NVD timeout"))), \
         patch.object(lf, "_fetch_wpscan", AsyncMock(return_value=WPSCAN_ITEMS)):
        await lf.refresh()

    assert lf._CACHE_POPULATED is True
    ids = {i["id"] for i in lf.get_items()}
    assert "cisa-CVE-2024-1000" in ids
    assert "wpscan-abc123" in ids
    assert not any("nvd" in i for i in ids)


@pytest.mark.asyncio
async def test_one_source_failing_cisa():
    """CISA returns empty — NVD items still make it into the cache."""
    _reset_cache()
    with patch.object(lf, "_fetch_cisa_kev", AsyncMock(return_value=[])), \
         patch.object(lf, "_fetch_nvd", AsyncMock(return_value=NVD_ITEMS)), \
         patch.object(lf, "_fetch_wpscan", AsyncMock(return_value=[])):
        await lf.refresh()

    assert lf._CACHE_POPULATED is True
    assert lf.get_items()[0]["id"] == "nvd-CVE-2024-9999"


# ---------------------------------------------------------------------------
# All sources failing
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_all_sources_failing_preserves_cache():
    """All sources fail — existing cache must NOT be overwritten."""
    original = [{"id": "cisa-CVE-2024-OLD", "headline": "Old item.", "url": "https://cisa.gov", "published_at": "2026-05-01T00:00:00+00:00"}]
    lf._cache = list(original)
    lf._CACHE_POPULATED = True

    with patch.object(lf, "_fetch_cisa_kev", AsyncMock(return_value=[])), \
         patch.object(lf, "_fetch_nvd", AsyncMock(return_value=[])), \
         patch.object(lf, "_fetch_wpscan", AsyncMock(return_value=[])):
        await lf.refresh()

    assert lf.get_items() == original


@pytest.mark.asyncio
async def test_all_sources_raise_preserves_cache():
    """All sources raise exceptions — cache unchanged."""
    original = [{"id": "nvd-CVE-2024-KEEP", "headline": "Keep me.", "url": "https://nvd.nist.gov", "published_at": "2026-05-15T00:00:00+00:00"}]
    lf._cache = list(original)
    lf._CACHE_POPULATED = True

    with patch.object(lf, "_fetch_cisa_kev", AsyncMock(side_effect=Exception("err"))), \
         patch.object(lf, "_fetch_nvd", AsyncMock(side_effect=Exception("err"))), \
         patch.object(lf, "_fetch_wpscan", AsyncMock(side_effect=Exception("err"))):
        await lf.refresh()

    assert lf.get_items() == original


# ---------------------------------------------------------------------------
# Cache hit vs miss
# ---------------------------------------------------------------------------

def test_cache_hit_returns_stored_items():
    """get_items() returns whatever is in _cache without touching upstream."""
    lf._cache = list(CISA_ITEMS)
    result = lf.get_items()
    assert result == CISA_ITEMS
    assert result is not lf._cache  # returns a copy


def test_cache_miss_returns_empty_list():
    """Cold start: get_items() returns [] not an error."""
    _reset_cache()
    assert lf.get_items() == []


# ---------------------------------------------------------------------------
# Normalisation unit tests
# ---------------------------------------------------------------------------

def test_normalize_strips_html():
    assert lf._normalize("<b>Critical</b> flaw in &amp;plugin") == "Critical flaw in &plugin."


def test_normalize_trims_to_140_chars():
    long_text = "x" * 200
    result = lf._normalize(long_text)
    assert len(result) <= 141  # 140 + period


def test_normalize_adds_period_when_missing():
    assert lf._normalize("No punctuation at end") == "No punctuation at end."


def test_normalize_preserves_existing_punctuation():
    assert lf._normalize("Already done.") == "Already done."
    assert lf._normalize("A question?") == "A question?"
    assert lf._normalize("An exclamation!") == "An exclamation!"


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def test_merge_deduplicates_by_id():
    """Same ID appearing in two sources should only appear once."""
    dup = {"id": "cisa-CVE-2024-1000", "headline": "Dup.", "url": "https://cisa.gov", "published_at": "2026-05-20T00:00:00+00:00"}
    result = lf._merge([CISA_ITEMS, [dup]])
    ids = [i["id"] for i in result]
    assert ids.count("cisa-CVE-2024-1000") == 1


def test_merge_caps_at_10_items():
    many = [{"id": f"cisa-CVE-2024-{i}", "headline": f"Item {i}.", "url": "https://cisa.gov", "published_at": f"2026-05-{i+1:02d}T00:00:00+00:00"} for i in range(15)]
    result = lf._merge([many])
    assert len(result) == 10
