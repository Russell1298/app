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


# ---------------------------------------------------------------------------
# Batch 3
# ---------------------------------------------------------------------------

import asyncio
import httpx
from models.scan import DNSHijackFinding
from scanners import exposure
from scanners.checkout_scripts import _build_findings as build_checkout
from scanners.headers import LEAK_HEADERS, _VERSION_RE, _PLATFORM_SERVERS, _check_cookies


def _resp(status, text="", headers=None):
    return httpx.Response(status, text=text, headers={"content-type": "text/html", **(headers or {})},
                          request=httpx.Request("GET", f"https://{APEX}/"))


class _Client:
    def __init__(self, response):
        self.response = response

    async def get(self, url):
        return self.response


def _probe(path, response):
    probe = next(p for p in exposure._PROBES if p["path"] == path)
    return asyncio.run(exposure._probe(_Client(response), f"https://{APEX}", probe, refused=[]))


WP_LOGIN = "<html><head>" + "<style>x{}</style>" * 400 + '</head><form><input type="password" name="pwd"></form></html>'


def test_wordpress_login_page_is_context_not_an_exposure():
    f = _probe("/wp-login.php", _resp(200, WP_LOGIN))
    assert f.exposed is False and f.severity == "info" and f.penalty == 0


def test_admin_path_without_a_login_form_is_still_flagged():
    f = _probe("/admin", _resp(200, "<html><h1>Orders</h1><table>...</table></html>"))
    assert f.exposed is True and f.severity == "medium"


def test_firebase_key_is_not_a_generic_api_key():
    fb = 'firebaseConfig={apiKey:"AIzaSyD4x9kQ2mTz8pLw3vNc7rXyB1aHk0qEwJs",authDomain:"shop.firebaseapp.com"}'
    assert _names(fb) == []


def test_non_google_api_key_is_still_caught():
    assert "API Key" in _names('const api_key = "sk9f8a7d6c5b4a3e2f1g0h9i8j7k6";')


def _leak_flagged(header, value):
    spec = next(s for s in LEAK_HEADERS if s["header"] == header)
    if spec.get("versioned_only") and not _VERSION_RE.search(value):
        return False
    return not any(p in value.lower() for p in _PLATFORM_SERVERS)


@pytest.mark.parametrize("header, value, flagged", [
    ("server", "AmazonS3", False),
    ("server", "Pepyaka/1.19.10", False),       # Wix's own server
    ("x-powered-by", "Next.js", False),
    ("x-powered-by", "WP Engine", False),
    ("server", "nginx/1.18.0", True),
    ("x-powered-by", "PHP/7.4.3", True),
])
def test_only_real_versions_the_customer_controls_are_leaks(header, value, flagged):
    assert _leak_flagged(header, value) is flagged


def test_cloudflare_cookies_are_not_the_customers_findings():
    findings = _check_cookies(["__cf_bm=abc; path=/; expires=x; domain=.shop.test; HttpOnly; Secure; SameSite=None"])
    assert findings == []


def test_http_script_on_https_page_is_broken_not_a_skimmer_route():
    page = f"https://{APEX}/"
    script = {"src": "http://cdn.example.net/widget.js", "integrity": None, "content": ""}
    _, findings = build_checkout({page: [script]}, APEX, {}, {})
    assert [f.finding_id for f in findings] == ["script_over_http_blocked"]
    assert findings[0].severity == "medium"


def test_marketing_tag_on_payment_page_gets_actionable_advice():
    page = f"https://{APEX}/checkout"
    script = {"src": "https://www.googletagmanager.com/gtm.js?id=GTM-X", "integrity": None, "content": ""}
    _, findings = build_checkout({page: [script]}, APEX, {page: ["card_autocomplete"]}, {})
    assert [f.finding_id for f in findings] == ["third_party_tag_on_checkout"]
    assert "integrity=" not in findings[0].remediation


def test_directory_listing_needs_a_listing_not_a_mention():
    async def check(text):
        return await exposure._check_directory_listing(_Client(_resp(200, text)), f"https://{APEX}")
    assert asyncio.run(check("<html><p>Click Parent Directory to go up. Index of /docs</p></html>")) is None
    assert asyncio.run(check("<html><title>Index of /</title></html>")) is not None


def test_dnssec_warning_does_not_become_a_resolver_disagreement_action():
    import test_action_plan as ta
    from reports.action_plan import build_action_plan
    from models.scan import DNSHijackScanResult
    hijack = DNSHijackScanResult(
        domain=APEX, scan_timestamp=ta.TS, resolver_results={"a": ["1.2.3.4"], "b": ["1.2.3.4"]},
        findings=[DNSHijackFinding(check="Cross-resolver consistency", status="pass", severity=None,
                                   description="agree", remediation=None),
                  DNSHijackFinding(check="DNSSEC", status="warn", severity="low",
                                   description="unsigned", remediation="enable")],
        risk_score=3, risk_level="low", summary={})
    keys = [a.key for a in build_action_plan(ta.make_result(dns_hijack=hijack)).actions]
    assert "dns_hijack" not in keys


# ---------------------------------------------------------------------------
# CSP: judge what the policy restricts, not whether the header exists
# ---------------------------------------------------------------------------

from scanners.headers import _check_csp_value


@pytest.mark.parametrize("policy", [
    "upgrade-insecure-requests",                                    # jobcopilot.com: restricts no scripts
    "frame-ancestors 'self'; upgrade-insecure-requests",
    "default-src 'self'; script-src 'self' 'unsafe-inline'",        # inline scripts run
    "default-src *",                                                # any source
    "script-src 'self' https:",                                     # any https site
])
def test_policies_that_do_not_restrict_scripts_are_weak(policy):
    finding = _check_csp_value(policy)
    assert finding is not None and finding.status == "weak"


@pytest.mark.parametrize("policy", [
    "default-src 'self'",
    "default-src 'self'; script-src 'self' https://www.googletagmanager.com",
    # Browsers ignore 'unsafe-inline' when a nonce or hash is present (CSP2+)...
    "script-src 'self' 'unsafe-inline' 'nonce-r4nd0m'",
    # ...and ignore host/scheme allowlists when 'strict-dynamic' is present (CSP3).
    "script-src 'nonce-r4nd0m' 'strict-dynamic' https: 'unsafe-inline'",
    # script-src governs scripts even when default-src is permissive.
    "default-src *; script-src 'self'",
])
def test_policies_that_restrict_scripts_pass(policy):
    assert _check_csp_value(policy) is None


def test_first_directive_wins_like_in_browsers():
    assert _check_csp_value("script-src 'self'; script-src *") is None
