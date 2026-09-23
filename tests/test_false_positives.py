"""
Regression tests for findings that told customers something untrue:

- "www.shop.com" input had SPF, DMARC, MX, CAA, NS and DNSSEC checked on the www
  host, reporting records missing that exist on shop.com.
- A PEM header string inside a crypto library read as a leaked private key and
  floored the whole score at 90.
- Ordinary inline scripts using atob/eval anywhere on the site, homepage included,
  were reported HIGH as a skimmer technique to "treat as a potential compromise".
"""
from unittest.mock import patch

import dns.resolver
import pytest

import scanners.dns as dnsscan
import scanners.dns_hijack as dh
from scanners.checkout_scripts import _build_findings
from scanners.secrets import _scan_content

APEX = "shop.test"
WWW = f"www.{APEX}"


# ---------------------------------------------------------------------------
# www input
# ---------------------------------------------------------------------------

def test_mail_domain_strips_only_a_leading_www():
    assert dnsscan.mail_domain(WWW) == APEX
    assert dnsscan.mail_domain(APEX) == APEX
    assert dnsscan.mail_domain("www.io") == "www.io"          # "www" is the name itself
    assert dnsscan.mail_domain("blog.shop.test") == "blog.shop.test"


def test_climb_walks_to_two_labels():
    assert list(dnsscan.climb("a.b.shop.test")) == ["a.b.shop.test", "b.shop.test", "shop.test"]
    assert list(dnsscan.climb(APEX)) == [APEX]


# Records exist on the apex only, as they do for a real site.
APEX_TXT = {APEX: ["v=spf1 include:_spf.google.com -all"], f"_dmarc.{APEX}": ["v=DMARC1; p=reject"]}
APEX_RECORDS = {(APEX, "CAA"): ['0 issue "letsencrypt.org"'], (APEX, "NS"): ["ns1.host.test."],
                (APEX, "MX"): ["10 mx.host.test."]}


def _apex_only_dns():
    return (
        patch.object(dnsscan, "_txt_records", lambda name: APEX_TXT.get(name, [])),
        patch.object(dnsscan, "_query", lambda name, rdtype: APEX_RECORDS.get((name, rdtype), [])),
    )


def test_email_and_zone_records_are_found_when_the_customer_types_www():
    txt, query = _apex_only_dns()
    with txt, query:
        _, dmarc = dnsscan._check_dmarc(dnsscan.mail_domain(WWW))
        spf = dnsscan._check_spf(dnsscan.mail_domain(WWW))
        _, caa = dnsscan._check_caa(WWW)
        _, ns = dnsscan._check_ns(WWW)
    assert dmarc.status == "pass"
    assert spf.status == "pass"
    assert caa.status == "pass"
    assert ns.status == "info" and ns.penalty == 0


def test_dmarc_on_a_subdomain_falls_back_to_the_organizational_domain():
    txt, query = _apex_only_dns()
    with txt, query:
        _, dmarc = dnsscan._check_dmarc(f"blog.{APEX}")
    assert dmarc.status == "pass"


def test_dmarc_missing_everywhere_is_still_reported():
    with patch.object(dnsscan, "_txt_records", lambda name: []):
        _, dmarc = dnsscan._check_dmarc(APEX)
    assert dmarc.status == "fail" and dmarc.severity == "high"


def test_dnssec_is_found_at_the_zone_apex_not_the_www_host():
    def resolve(self, name, rdtype):
        if name == APEX and rdtype == "DS":
            return ["12345 13 2 ABCDEF"]
        raise dns.resolver.NoAnswer()
    with patch.object(dns.resolver.Resolver, "resolve", resolve):
        assert dh._check_dnssec(WWW).status == "pass"


# ---------------------------------------------------------------------------
# Private key
# ---------------------------------------------------------------------------

KEY_BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj"


def _names(content):
    return [f.pattern_name for f in _scan_content(content, "https://shop.test/app.js", "javascript")]


def test_pem_header_constant_in_a_library_is_not_a_leaked_key():
    lib = 'var H={priv:"-----BEGIN PRIVATE KEY-----",pub:"-----BEGIN PUBLIC KEY-----"};'
    assert "Private Key" not in _names(lib)


@pytest.mark.parametrize("content", [
    f"-----BEGIN RSA PRIVATE KEY-----\n{KEY_BODY}\n-----END RSA PRIVATE KEY-----",   # real line breaks
    f'const k="-----BEGIN PRIVATE KEY-----\\n{KEY_BODY}\\n-----END PRIVATE KEY-----";',  # escaped in JS
])
def test_real_key_material_is_still_caught(content):
    assert "Private Key" in _names(content)


def test_private_key_preview_reveals_no_key_material():
    content = f"-----BEGIN RSA PRIVATE KEY-----\n{KEY_BODY}\n-----END RSA PRIVATE KEY-----"
    finding = next(f for f in _scan_content(content, "https://shop.test/k.pem", "javascript")
                   if f.pattern_name == "Private Key")
    assert not any(chunk in finding.match_preview for chunk in (KEY_BODY[:4], KEY_BODY[-4:], "Kj"))


# ---------------------------------------------------------------------------
# Checkout obfuscation patterns
# ---------------------------------------------------------------------------

INLINE_ATOB = {"src": None, "integrity": None, "content": "var cfg=JSON.parse(atob(window.__CFG__));"}
INLINE_EVAL = {"src": None, "integrity": None, "content": "eval(payload);"}


def test_obfuscation_calls_on_a_non_payment_page_are_not_reported():
    _, findings = _build_findings({f"https://{APEX}/": [INLINE_ATOB, INLINE_EVAL]}, APEX, {}, {})
    assert not [f for f in findings if f.finding_id.startswith("suspicious_pattern_")]


def test_obfuscation_calls_on_a_payment_page_are_a_review_prompt_not_a_compromise():
    page = f"https://{APEX}/checkout"
    _, findings = _build_findings({page: [INLINE_ATOB, INLINE_EVAL]}, APEX, {page: ["card_autocomplete"]}, {})
    by_id = {f.finding_id: f for f in findings}
    assert by_id["suspicious_pattern_atob_call"].severity == "low"
    assert by_id["suspicious_pattern_eval_call"].severity == "medium"
    for f in by_id.values():
        assert "treat it as a potential compromise" not in f.remediation
        assert "not evidence of compromise" in f.description
