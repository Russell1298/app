"""Tests for the Action Plan report: prioritisation, evidence gating, redaction."""
import pytest

from models.scan import (
    FullScanResult, HeaderScanResult, HeaderFinding, DNSScanResult, DNSRecord, DNSFinding,
    SSLScanResult, CertInfo, TLSVersionCheck, ExposureScanResult, ExposureFinding,
    FingerprintScanResult, SecretScanResult, SecretFinding, CheckoutScriptScanResult,
    DNSHijackScanResult,
)
from reports.action_plan import build_action_plan, _wrap_mono, _redact, _dmarc_value
from reports.html_report import generate_action_plan_html

TS = "2026-09-21T02:14:55+00:00"
DMARC = "v=DMARC1; p=none; rua=mailto:dmarc@sekura.cloud; sp=none; adkim=r; aspf=r; pct=100"


def make_result(**overrides) -> FullScanResult:
    domain = overrides.pop("domain", "sekura.cloud")
    base = dict(
        domain=domain, scan_timestamp=TS,
        headers=HeaderScanResult(domain=domain, scanned_url=f"https://{domain}", scan_timestamp=TS,
                                 findings=[], information_leaks=[], risk_score=0,
                                 risk_level="low", summary={}),
        dns=DNSScanResult(domain=domain, scan_timestamp=TS,
                          records=[DNSRecord(record_type="TXT", values=[
                              "v=spf1 include:zoho.com ~all", DMARC])],
                          findings=[
                              DNSFinding(check="DMARC policy", status="warn", severity="medium",
                                         description="Monitoring only.", remediation="Enforce."),
                              DNSFinding(check="CAA record", status="warn", severity="low",
                                         description="No CAA record.", remediation="Publish CAA."),
                          ],
                          risk_score=12, risk_level="low", summary={}),
        ssl=SSLScanResult(domain=domain, port=443, scan_timestamp=TS,
                          certificate=CertInfo(subject=f"CN={domain}", issuer="R3, O=Let's Encrypt",
                                               not_before="2026-08-01", not_after="2027-02-01",
                                               days_until_expiry=133, is_self_signed=False,
                                               sans=[domain], serial_number="01"),
                          tls_versions=[TLSVersionCheck(version="TLS 1.3", supported=True)],
                          findings=[], risk_score=0, risk_level="low", summary={}),
        exposure=ExposureScanResult(domain=domain, scan_timestamp=TS,
                                    findings=[ExposureFinding(path="/.git/config", label="Git directory",
                                                              status_code=404, exposed=False, severity="high",
                                                              description="Not found.", remediation=None)],
                                    risk_score=0, risk_level="low", summary={}),
        fingerprint=FingerprintScanResult(domain=domain, scan_timestamp=TS, matches=[], summary={}),
        overall_risk_score=7, overall_risk_level="low", top_findings=[],
    )
    base.update(overrides)
    return FullScanResult(**base)


# ---------------------------------------------------------------------------
# Evidence blocks
# ---------------------------------------------------------------------------

def test_wrap_mono_preserves_every_character():
    """These blocks are evidence: a developer pastes them back into a terminal."""
    lines = _wrap_mono(DMARC, width=60)
    assert "".join(lines).replace(" ", "") == DMARC.replace(" ", "")
    assert "rua=mailto:dmarc@sekura.cloud;" in " ".join(lines)
    assert all(len(line) <= 66 for line in lines)


def test_wrap_mono_short_value_is_untouched():
    assert _wrap_mono("v=spf1 -all") == ["v=spf1 -all"]


def test_redact_never_emits_the_full_secret():
    preview = "sk_live_51MxAbCdEfGhIjKlMnOpQr"
    redacted = _redact(preview)
    assert preview not in redacted
    assert "MxAbCdEfGhIjKlMnOp" not in redacted
    assert redacted.startswith("sk_l")


def test_secret_value_never_reaches_the_rendered_page():
    preview = "sk_live_51MxAbCdEfGhIjKlMnOpQr"
    result = make_result(secrets=SecretScanResult(
        domain="sekura.cloud", scan_timestamp=TS, files_scanned=9,
        findings=[SecretFinding(pattern_name="Stripe Secret Key", severity="high",
                                location="inline script",
                                source_url="https://sekura.cloud/checkout.js",
                                match_preview=preview)],
        risk_score=80, risk_level="critical", summary={}))
    assert preview not in generate_action_plan_html(result)


# ---------------------------------------------------------------------------
# Prioritisation and layout
# ---------------------------------------------------------------------------

def test_plan_caps_at_three_actions_numbered_in_order():
    result = make_result(
        headers=HeaderScanResult(
            domain="sekura.cloud", scanned_url="https://sekura.cloud", scan_timestamp=TS,
            findings=[HeaderFinding(header="Content-Security-Policy", status="missing", severity="high",
                                    value=None, description="No CSP.", remediation="Add one.")],
            information_leaks=[], risk_score=20, risk_level="medium", summary={}),
        exposure=ExposureScanResult(
            domain="sekura.cloud", scan_timestamp=TS,
            findings=[ExposureFinding(path="/.env", label=".env file", status_code=200, exposed=True,
                                      severity="high", description="Readable.", remediation="Block it.",
                                      confidence="confirmed")],
            risk_score=90, risk_level="critical", summary={}),
    )
    plan = build_action_plan(result)
    assert len(plan.actions) == 3
    assert [a.number for a in plan.actions] == ["01", "02", "03"]
    # A path answering publicly outranks email policy, which outranks a missing
    # header; CAA is real but ranks below all three and is dropped from the brief.
    assert [a.key for a in plan.actions] == ["exposure", "email_auth", "headers"]
    assert plan.page_total == 4
    assert [s.kind for s in plan.sheets] == ["brief", "detail_full", "detail_compact", "evidence"]
    assert plan.actions[0].page == 2 and plan.actions[1].page == 3


def test_page_references_on_the_brief_match_the_sheets():
    plan = build_action_plan(make_result())
    for action in plan.actions:
        sheet = next(s for s in plan.sheets if s.page_no == action.page)
        assert action in sheet.actions


def test_no_actions_produces_a_two_page_report():
    result = make_result(dns=DNSScanResult(domain="sekura.cloud", scan_timestamp=TS,
                                           records=[DNSRecord(record_type="TXT", values=["v=spf1 -all"])],
                                           findings=[], risk_score=0, risk_level="low", summary={}))
    plan = build_action_plan(result)
    assert plan.actions == []
    assert plan.page_total == 2


# ---------------------------------------------------------------------------
# Evidence gating: a missing result is not a pass
# ---------------------------------------------------------------------------

def test_rating_withheld_when_a_scanner_returned_nothing():
    plan = build_action_plan(make_result())          # no secrets / checkout / hijack modules
    assert plan.rating_withheld is True
    assert "withholds an overall rating" in plan.withheld_reason
    assert any(not row.complete for row in plan.evidence_rows)


def test_rating_issued_when_every_area_has_evidence():
    domain = "sekura.cloud"
    result = make_result(
        headers=HeaderScanResult(domain=domain, scanned_url=f"https://{domain}", scan_timestamp=TS,
                                 findings=[HeaderFinding(header="Referrer-Policy", status="present",
                                                         severity="low", value="no-referrer",
                                                         description="Set.", remediation="")],
                                 information_leaks=[], risk_score=0, risk_level="low", summary={}),
        fingerprint=FingerprintScanResult(domain=domain, scan_timestamp=TS, matches=[], summary={}),
        secrets=SecretScanResult(domain=domain, scan_timestamp=TS, findings=[], files_scanned=12,
                                 risk_score=0, risk_level="low", summary={}),
        checkout_scripts=CheckoutScriptScanResult(domain=domain, scan_timestamp=TS,
                                                  pages_scanned=["/checkout"], scripts=[], findings=[],
                                                  risk_score=0, risk_level="low", summary={}),
        dns_hijack=DNSHijackScanResult(domain=domain, scan_timestamp=TS,
                                       resolver_results={"1.1.1.1": ["1.2.3.4"], "8.8.8.8": ["1.2.3.4"]},
                                       findings=[], risk_score=0, risk_level="low", summary={}),
        subdomains=None,
    )
    # Discovery needs at least one match or subdomain to count as evidence.
    result.fingerprint.matches = []
    plan = build_action_plan(result)
    discovery = next(r for r in plan.evidence_rows if r.area.startswith("Discovery"))
    assert discovery.complete is False        # nothing discovered is still nothing observed
    assert plan.rating_withheld is True


def test_intercepted_certificate_is_not_treated_as_evidence():
    result = make_result(ssl=SSLScanResult(
        domain="sekura.cloud", port=443, scan_timestamp=TS,
        certificate=CertInfo(subject="CN=sekura.cloud",
                             issuer="Egress Gateway SDS Issuing CA (production), O=Anthropic",
                             not_before="2026-07-23", not_after="2026-10-21", days_until_expiry=29,
                             is_self_signed=False, sans=["sekura.cloud"], serial_number="04"),
        tls_versions=[], findings=[], risk_score=0, risk_level="low", summary={}))
    plan = build_action_plan(result)
    tls_row = next(r for r in plan.evidence_rows if r.area.startswith("TLS"))
    assert tls_row.complete is False
    cert_action = next(a for a in plan.actions if a.key == "certificate")
    assert cert_action.band == "VERIFY FIRST"


def test_html_renders_for_every_shape():
    for result in (make_result(), make_result(dns=DNSScanResult(
            domain="sekura.cloud", scan_timestamp=TS, records=[], findings=[],
            risk_score=0, risk_level="low", summary={}))):
        html = generate_action_plan_html(result, client_name="Acme Ltd")
        assert "Sekura" in html and "sekura.cloud" in html


def test_dmarc_is_read_from_its_own_record_type():
    """
    The DNS scanner publishes the _dmarc lookup as a "DMARC" record, not inside
    TXT. Reading only TXT reported a published policy as missing.
    """
    result = make_result(dns=DNSScanResult(
        domain="sekura.cloud", scan_timestamp=TS,
        records=[
            DNSRecord(record_type="TXT", values=["v=spf1 include:zoho.com ~all"]),
            DNSRecord(record_type="DMARC", values=[DMARC]),
        ],
        findings=[DNSFinding(check="DMARC", status="warn", severity="medium",
                             description="Policy is none.", remediation="Enforce.")],
        risk_score=12, risk_level="low", summary={}))

    assert _dmarc_value(result) == DMARC
    plan = build_action_plan(result)
    assert "DMARC p=none" in plan.evidence_rows[0].note
    observed = "\n".join(plan.actions[0].observed.lines)
    assert "rua=mailto:dmarc@sekura.cloud" in observed
