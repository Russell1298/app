"""
Hosted platforms set headers and cookies for every site they host. Reports must
not tell a Shopify merchant to change settings only Shopify can change.
The Mira Boutique case is the regression: a real Shopify store whose report
asked the owner to raise HSTS max-age and add cookie flags to Shopify's cookies.
"""
import asyncio

import httpx
import pytest

from scanners.headers import scan_headers
from scanners.platform import hosted_platform
from scanners.waf import Access
from reports.action_plan import build_action_plan
from reports.generator import build_full_report

# Response headers as a Shopify storefront returns them (from a real scan).
SHOPIFY_HEADERS = [
    ("content-type", "text/html; charset=utf-8"),
    ("content-security-policy", "block-all-mixed-content; frame-ancestors 'none'; upgrade-insecure-requests;"),
    ("strict-transport-security", "max-age=7889238"),
    ("x-frame-options", "DENY"),
    ("x-content-type-options", "nosniff"),
    ("set-cookie", "_shopify_y=abc; path=/; expires=Thu, 23 Sep 2027 08:42:00 GMT"),
    ("set-cookie", "localization=US; path=/"),
    ("set-cookie", "cart_currency=USD; path=/"),
]
PLAIN_HEADERS = [("content-type", "text/html"), ("server", "nginx")]


def _resp(headers):
    return httpx.Response(200, headers=headers, text="<html></html>",
                          request=httpx.Request("GET", "https://store.test/"))


@pytest.mark.parametrize("headers, platform", [
    (SHOPIFY_HEADERS, "Shopify"),
    ([("powered-by", "Shopify")], "Shopify"),
    ([("x-shopid", "123")], "Shopify"),
    ([("server", "Pepyaka/1.19.10")], "Wix"),
    ([("x-wix-request-id", "1")], "Wix"),
    ([("server", "Squarespace")], "Squarespace"),
    (PLAIN_HEADERS, None),
    # A site that only embeds a Shopify buy button sets no Shopify cookie itself.
    ([("content-type", "text/html"), ("set-cookie", "session=abc; Secure; HttpOnly")], None),
])
def test_platform_detection(headers, platform):
    assert hosted_platform(_resp(headers)) == platform


def _scan(headers):
    return asyncio.run(scan_headers("store.test", Access(_resp(headers), {}, "browser", None)))


def test_shopify_header_and_cookie_findings_are_attributed_not_scored():
    result = _scan(SHOPIFY_HEADERS)
    flagged = [f for f in result.findings if f.status in ("missing", "weak")]
    assert flagged, "findings stay visible for context"
    assert all(f.platform_controlled and f.penalty == 0 for f in flagged)
    assert all(f.description.startswith("Set by Shopify") for f in flagged)
    assert result.risk_score == 0
    assert result.summary["platform"] == "Shopify"


def test_a_self_hosted_site_is_still_scored():
    result = _scan(PLAIN_HEADERS)
    assert result.risk_score > 0
    assert not any(f.platform_controlled for f in result.findings)
    assert result.summary["platform"] is None


def test_the_report_asks_a_shopify_merchant_to_fix_nothing_shopify_controls():
    import test_action_plan as ta
    base = ta.make_result()
    full = build_full_report(domain="store.test", headers=_scan(SHOPIFY_HEADERS), dns=base.dns, ssl=base.ssl,
                             exposure=base.exposure, fingerprint=base.fingerprint)
    assert full.platform == "Shopify"
    assert not [t for t in full.top_findings if t["scanner"] == "headers"]
    plan = build_action_plan(full)
    assert "headers" not in [a.key for a in plan.actions]
    row = next(r for r in plan.evidence_rows if r.area.startswith("Headers"))
    assert "hosted on Shopify" in row.note
