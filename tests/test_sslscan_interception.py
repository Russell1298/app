"""
Tests for TLS-interception handling in the SSL scanner.

A proxy that terminates TLS presents its own certificate. Before this was
detected, the scanner recorded the proxy's certificate as the customer's and
reported the proxy's protocol support as theirs. These tests pin the rule:
what we cannot see, we do not claim.
"""
import asyncio
import json
from unittest.mock import patch

import pytest

from scanners import sslscan

DOMAIN = "sekura.cloud"
PUBLIC_FAIL = "unable to get local issuer certificate"


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def test_public_chain_is_not_flagged_as_intercepted():
    with patch.object(sslscan, "_handshake", return_value=(b"der", ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), None)) as hs:
        der, cipher, error, intercepted = sslscan._get_cert_and_cipher(DOMAIN)
    assert (der, error, intercepted) == (b"der", None, False)
    assert hs.call_count == 1, "a trusted chain must not cost a second handshake"


def test_locally_trusted_but_not_publicly_trusted_is_interception():
    """The exact shape of a corporate proxy or egress gateway."""
    def fake(domain, port, cafile, verify):
        if verify and cafile == sslscan.PUBLIC_ROOTS:
            return None, None, PUBLIC_FAIL       # public roots reject it
        return b"proxy-der", ("X", "TLSv1.3", 256), None   # the local store accepts it

    with patch.object(sslscan, "_handshake", side_effect=fake):
        der, cipher, error, intercepted = sslscan._get_cert_and_cipher(DOMAIN)
    assert intercepted is True
    assert der == b"proxy-der"
    assert error is None


def test_untrusted_everywhere_is_a_site_problem_not_interception():
    """A genuinely broken or self-signed site certificate must still be reported."""
    def fake(domain, port, cafile, verify):
        if verify:
            return None, None, PUBLIC_FAIL
        return b"site-der", None, None

    with patch.object(sslscan, "_handshake", side_effect=fake):
        der, cipher, error, intercepted = sslscan._get_cert_and_cipher(DOMAIN)
    assert intercepted is False
    assert der == b"site-der"
    assert error == PUBLIC_FAIL


# ---------------------------------------------------------------------------
# Certificate transparency fallback
# ---------------------------------------------------------------------------

CT_ENTRIES = [
    {   # expired: must be ignored
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3", "common_name": DOMAIN,
        "name_value": f"{DOMAIN}\nwww.{DOMAIN}",
        "not_before": "2025-01-01T00:00:00", "not_after": "2025-04-01T00:00:00",
        "serial_number": "aa",
    },
    {   # another domain entirely: must be ignored
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3", "common_name": "other.test",
        "name_value": "other.test",
        "not_before": "2026-09-01T00:00:00", "not_after": "2099-01-01T00:00:00",
        "serial_number": "bb",
    },
    {   # valid, expiring latest
        "issuer_name": "C=US, O=Let's Encrypt, CN=R11", "common_name": DOMAIN,
        "name_value": f"{DOMAIN}\n*.{DOMAIN}",
        "not_before": "2026-09-01T00:00:00", "not_after": "2099-06-01T00:00:00",
        "serial_number": "cc",
    },
    {   # valid, expiring soonest: this is the one in use
        "issuer_name": "C=US, O=Let's Encrypt, CN=R10", "common_name": DOMAIN,
        "name_value": f"{DOMAIN}\nwww.{DOMAIN}",
        "not_before": "2026-09-10T00:00:00", "not_after": "2099-02-01T00:00:00",
        "serial_number": "dd",
    },
]


class _FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, response=None, error=None):
        self._response, self._error = response, error

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url):
        if self._error:
            raise self._error
        return self._response


def _run_ct(response=None, error=None):
    with patch.object(sslscan.httpx, "AsyncClient", lambda *a, **k: _FakeClient(response, error)):
        return asyncio.run(sslscan._cert_from_ct_log(DOMAIN))


def test_ct_fallback_picks_the_valid_certificate_expiring_soonest():
    cert = _run_ct(_FakeResponse(CT_ENTRIES))
    assert cert is not None
    assert cert.source == "ct_log"
    assert cert.issuer == "C=US, O=Let's Encrypt, CN=R10"
    assert cert.serial_number == "dd"
    assert cert.days_until_expiry > 0
    assert DOMAIN in cert.sans and f"www.{DOMAIN}" in cert.sans


def test_ct_fallback_returns_nothing_when_no_entry_is_current():
    assert _run_ct(_FakeResponse([CT_ENTRIES[0], CT_ENTRIES[1]])) is None


def test_ct_fallback_survives_an_unreachable_log():
    assert _run_ct(error=RuntimeError("403 from the network")) is None
    assert _run_ct(_FakeResponse([], status_code=502)) is None


# ---------------------------------------------------------------------------
# End to end: an intercepted scan claims nothing about the site
# ---------------------------------------------------------------------------

def _scan_intercepted(ct_cert):
    # _cert_from_ct_log is async, so patch.object hands back an AsyncMock:
    # return_value is what the await resolves to.
    with patch.object(sslscan, "_get_cert_and_cipher", return_value=(b"proxy-der", None, None, True)), \
         patch.object(sslscan, "_probe_tls_version", side_effect=AssertionError("must not probe through a proxy")), \
         patch.object(sslscan, "_cert_from_ct_log", return_value=ct_cert):
        return asyncio.run(sslscan.scan_ssl(DOMAIN))


def test_intercepted_scan_does_not_probe_protocols_or_score_the_site():
    cert = _run_ct(_FakeResponse(CT_ENTRIES))
    result = _scan_intercepted(cert)

    assert result.intercepted is True
    assert "TLS interception detected" in result.interception_note
    # Protocol support through a proxy describes the proxy. Report it as untested.
    assert all(v.supported is None for v in result.tls_versions)
    # An intercepted scan must not move the customer's score or trip a cap.
    assert result.risk_score == 0
    assert result.critical_triggers == []
    assert all(f.penalty == 0 for f in result.findings)
    # The certificate shown is labelled as log-derived, not handshake-derived.
    assert result.certificate is not None and result.certificate.source == "ct_log"
    assert result.summary["certificate_source"] == "ct_log"


def test_intercepted_scan_with_no_log_record_reports_no_certificate():
    result = _scan_intercepted(None)
    assert result.certificate is None
    assert result.intercepted is True
    assert result.risk_score == 0
    assert any(f.check == "Certificate" for f in result.findings)


def test_untested_protocol_versions_produce_no_findings():
    checks = [sslscan.TLSVersionCheck(version=v, supported=None)
              for v in ("TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3")]
    assert sslscan._findings_from_tls_versions(checks) == []
