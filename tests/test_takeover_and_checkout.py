"""
Tests for dangling-record detection and checkout-page identification.

Both of these decide what goes into a report a client reads, so the tests are
written around the ways each check can embarrass us: a wildcard reported as
twenty findings, a basket page described as a checkout, advice to edit a tag
the merchant does not control.
"""
from unittest.mock import patch

import dns.resolver
import pytest

from scanners import dns as dnsscan
from scanners import checkout_scripts as cs

DOMAIN = "example.test"
DEAD_ELB = "celebritylb-726422670.us-east-1.elb.amazonaws.com"
LIVE_CDN = "d111111abcdef8.cloudfront.net"


# ---------------------------------------------------------------------------
# Dangling records
# ---------------------------------------------------------------------------

def _patch_dns(cname_map: dict[str, list[str]], resolving: set[str]):
    """cname_map: host -> CNAME targets. resolving: names that exist in DNS."""
    def fake_targets(name: str) -> list[str]:
        # An exact record beats a wildcard, the same way real DNS resolves it.
        if name in cname_map:
            return cname_map[name]
        for host, targets in cname_map.items():
            if host.startswith("*.") and name.endswith(host[1:]):
                return targets
        return []

    def fake_resolves(target: str) -> bool:
        return target in resolving

    return patch.object(dnsscan, "_cname_targets", side_effect=fake_targets), \
           patch.object(dnsscan, "_cname_target_resolves", side_effect=fake_resolves)


def test_elb_target_is_recognised_as_cloud_infrastructure():
    """The original pattern list only matched .s3.amazonaws.com."""
    assert dnsscan._is_cloud_cname(DEAD_ELB) is True
    assert dnsscan._is_cloud_cname("d111111abcdef8.cloudfront.net") is True
    assert dnsscan._is_cloud_cname("vip.myshopline.shop") is False


def test_wildcard_is_reported_once_not_once_per_guessed_hostname():
    """
    A single "*.domain CNAME dead-target" record answers for every name we
    probe. Reporting it per hostname turns one misconfiguration into twenty
    findings and discredits the report.
    """
    targets, resolves = _patch_dns({f"*.{DOMAIN}": [DEAD_ELB]}, resolving=set())
    with targets, resolves:
        findings = dnsscan._check_subdomain_takeovers(DOMAIN)

    assert len(findings) == 1
    assert findings[0].check == f"Dangling wildcard DNS record: *.{DOMAIN}"
    assert DEAD_ELB in findings[0].description
    # It must not claim a takeover it has not confirmed.
    assert "rather than a confirmed" in findings[0].description


def test_distinct_dangling_record_is_still_reported_alongside_a_wildcard():
    targets, resolves = _patch_dns(
        {f"*.{DOMAIN}": [DEAD_ELB], f"shop.{DOMAIN}": ["gone.herokuapp.com"]},
        resolving=set(),
    )
    with targets, resolves:
        findings = dnsscan._check_subdomain_takeovers(DOMAIN)

    checks = {f.check for f in findings}
    assert f"Dangling wildcard DNS record: *.{DOMAIN}" in checks
    assert f"Dangling DNS record: shop.{DOMAIN}" in checks


def test_live_target_produces_no_finding():
    targets, resolves = _patch_dns({f"cdn.{DOMAIN}": [LIVE_CDN]}, resolving={LIVE_CDN})
    with targets, resolves:
        assert dnsscan._check_subdomain_takeovers(DOMAIN) == []


def test_resolver_trouble_never_reports_a_dangling_record():
    """A timeout is not evidence. Guessing here puts a false finding in a client's inbox."""
    with patch.object(dnsscan._TAKEOVER_RESOLVER, "resolve",
                      side_effect=dns.exception.Timeout):
        assert dnsscan._cname_target_resolves(DEAD_ELB) is True


def test_name_that_exists_without_an_a_record_is_not_dangling():
    with patch.object(dnsscan._TAKEOVER_RESOLVER, "resolve",
                      side_effect=dns.resolver.NoAnswer):
        assert dnsscan._cname_target_resolves("mail.example.com") is True


def test_nxdomain_target_is_dangling():
    with patch.object(dnsscan._TAKEOVER_RESOLVER, "resolve",
                      side_effect=dns.resolver.NXDOMAIN):
        assert dnsscan._cname_target_resolves(DEAD_ELB) is False


# ---------------------------------------------------------------------------
# Checkout page identification
# ---------------------------------------------------------------------------

BASKET_HTML = """
<html><body><h1>Your cart</h1>
<script src="https://cdn.example.net/cart.js"></script>
<a href="/checkout">Proceed to checkout</a></body></html>
"""

PAYMENT_HTML = """
<html><body><h1>Payment</h1>
<form><input autocomplete="cc-number" name="cardnumber">
<input name="cvv"></form>
<script src="https://cdn.example.net/track.js"></script>
</body></html>
"""

PLATFORM_HTML = """
<html><body><form><input autocomplete="cc-number"></form>
<script src="https://cdn.myshopline.com/checkout.bundle.js"></script>
</body></html>
"""


def test_a_basket_page_is_not_a_checkout_page():
    assert cs._payment_evidence(BASKET_HTML) == []


def test_a_page_with_card_fields_is_a_checkout_page():
    markers = cs._payment_evidence(PAYMENT_HTML)
    assert "card_autocomplete" in markers
    assert "cvv_field" in markers


def test_no_sri_finding_is_raised_on_a_page_without_payment_evidence():
    """
    The old check matched "/cart" in the URL and reported basket scripts as
    checkout findings. Nothing on this page takes payment details.
    """
    page = f"https://{DOMAIN}/cart"
    _, findings = cs._build_findings(
        {page: cs._parse_scripts(BASKET_HTML)}, DOMAIN,
        payment_pages={}, requested_by_final={page: page},
    )
    assert [f for f in findings if "sri" in f.finding_id] == []


def test_sri_finding_names_the_page_that_actually_served_the_script():
    requested = f"https://{DOMAIN}/checkout"
    served = "https://checkout.myshopline.com/abc123"
    _, findings = cs._build_findings(
        {served: cs._parse_scripts(PAYMENT_HTML)}, DOMAIN,
        payment_pages={served: ["card_autocomplete", "cvv_field"]},
        requested_by_final={served: requested},
    )
    sri = next(f for f in findings if f.finding_id == "no_sri_on_checkout_script")
    assert f"Requested: {requested}" in sri.evidence
    assert f"Served by: {served}" in sri.evidence
    assert "card_autocomplete" in sri.evidence


def test_platform_script_is_not_given_advice_the_merchant_cannot_follow():
    """SHOPLINE renders checkout itself; the merchant cannot add integrity=."""
    served = "https://checkout.myshopline.com/abc123"
    _, findings = cs._build_findings(
        {served: cs._parse_scripts(PLATFORM_HTML)}, DOMAIN,
        payment_pages={served: ["card_autocomplete"]},
        requested_by_final={served: served},
    )
    sri = next(f for f in findings if "sri" in f.finding_id)
    assert sri.finding_id == "sri_unsupported_payment_script"
    assert sri.severity == "low"
    assert "Leave the script as it is" in sri.remediation
    assert "integrity=" not in sri.remediation


def test_shopline_is_recognised_as_its_own_platform():
    names = {sig["name"] for sig in cs_signatures()}
    assert "SHOPLINE" in names


def cs_signatures():
    from scanners import fingerprint
    for attr in dir(fingerprint):
        value = getattr(fingerprint, attr)
        if isinstance(value, list) and value and isinstance(value[0], dict) and "name" in value[0]:
            return value
    raise AssertionError("fingerprint signature table not found")


FOOTER_WORDING_HTML = """
<html><body><h1>Your cart</h1>
<footer>Payment method: we accept all major cards. Billing address required.</footer>
<script src="https://cdn.example.net/cart.js"></script></body></html>
"""


def test_payment_wording_alone_does_not_make_a_page_a_checkout():
    """
    A basket footer listing accepted payment methods is not a payment page.
    Qualifying on wording alone would rebuild the false positive this check
    exists to remove.
    """
    assert cs._payment_evidence(FOOTER_WORDING_HTML) == []


def test_wording_is_listed_as_supporting_evidence_once_a_page_qualifies():
    html = '<form><input autocomplete="cc-number"></form><p>Card number</p>'
    markers = cs._payment_evidence(html)
    assert "card_autocomplete" in markers
    assert "payment_wording" in markers


def test_payment_iframe_marker_is_not_fooled_by_a_lookalike_path():
    html = '<iframe src="https://evil.example/pay/stripe.com/frame"></iframe>'
    assert "payment_iframe" not in cs._payment_evidence(html)
