"""
Regression tests for two checks that silently reported the wrong thing:

- dns_hijack read the TTL off individual records (which have none), so every real
  lookup crashed, the crash was swallowed, and the resolver and fast-flux checks
  never ran. Every PDF then withheld its rating for "0 resolvers compared".
- sslscan could not offer TLS 1.0/1.1 under OpenSSL 3 defaults, so it reported
  them "correctly disabled" on servers that still accept them.
"""
import asyncio
import shutil
import socket
import ssl
import subprocess
import threading
from unittest.mock import patch

import dns.resolver
import dns.rrset
import pytest

import scanners.dns_hijack as dh
import scanners.sslscan as sslscan

DOMAIN = "shop.test"


class _Answer:
    """Behaves like dns.resolver.Answer: iterating yields records; TTL lives on .rrset."""
    def __init__(self, ttl: int, ips: list[str]):
        self.rrset = dns.rrset.from_text(f"{DOMAIN}.", ttl, "IN", "A", *ips)

    def __iter__(self):
        return iter(self.rrset)


def _dns(ttl: int, ips: list[str]):
    def resolve(self, name, rdtype):
        if rdtype == "A":
            return _Answer(ttl, ips)
        raise dns.resolver.NoAnswer()
    return patch.object(dns.resolver.Resolver, "resolve", resolve)


def test_ttl_is_read_from_the_record_set():
    with _dns(137, ["104.16.1.1", "104.16.2.1"]):
        assert dh._query_a_with_ttl(DOMAIN, dh._make_resolver("8.8.8.8")) == (["104.16.1.1", "104.16.2.1"], 137)


def test_resolver_comparison_actually_runs_and_feeds_the_report():
    import test_action_plan as ta
    from reports.action_plan import build_action_plan

    with _dns(300, ["104.16.1.1", "104.16.2.1"]):
        result = asyncio.run(dh.scan_dns_hijack(DOMAIN))
    consistency = next(f for f in result.findings if f.check == "Cross-resolver consistency")
    assert consistency.status == "pass"
    assert len(result.resolver_results) == 3

    row = next(r for r in build_action_plan(ta.make_result(dns_hijack=result)).evidence_rows
               if r.area == "DNS consistency")
    assert row.complete


CLOUDFRONT_IPS = [f"13.33.{i}.10" for i in range(8)]


@pytest.mark.parametrize("ttl, ips, asns", [
    (60, CLOUDFRONT_IPS, {ip: "16509" for ip in CLOUDFRONT_IPS}),      # CloudFront / AWS ALB
    (20, ["23.1.1.1", "23.1.1.2", "23.1.1.3"], {"23.1.1.1": "20940", "23.1.1.2": "20940", "23.1.1.3": "20940"}),  # Akamai
])
def test_cdn_load_balancing_is_not_fast_flux(ttl, ips, asns):
    with _dns(ttl, ips), patch.object(dh, "_asns_for_ips", return_value=asns):
        finding = dh._check_fast_flux(DOMAIN)
    assert finding.status == "pass" and finding.penalty == 0


def test_low_ttl_alone_is_not_flagged():
    # Resolvers report remaining cache time, so a 300s Cloudflare record reads as ~137s.
    with _dns(137, ["104.16.1.1", "104.16.2.1"]):
        finding = dh._check_fast_flux(DOMAIN)
    assert finding.status == "pass" and finding.penalty == 0


def test_ips_across_many_unrelated_networks_is_fast_flux():
    ips = ["5.1.1.1", "31.2.2.2", "77.3.3.3", "91.4.4.4"]
    asns = {"5.1.1.1": "1111", "31.2.2.2": "2222", "77.3.3.3": "3333", "91.4.4.4": "4444"}
    with _dns(30, ips), patch.object(dh, "_asns_for_ips", return_value=asns):
        finding = dh._check_fast_flux(DOMAIN)
    assert finding.status == "fail" and finding.severity == "high"


def test_unknown_ownership_makes_no_claim():
    with _dns(60, CLOUDFRONT_IPS), patch.object(dh, "_asns_for_ips", return_value={}):
        finding = dh._check_fast_flux(DOMAIN)
    assert finding.status == "info" and finding.penalty == 0


# ---------------------------------------------------------------------------
# TLS legacy protocol detection, against a real local TLS server
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    if not shutil.which("openssl"):
        pytest.skip("openssl CLI not available")
    d = tmp_path_factory.mktemp("cert")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", d / "k.pem",
                    "-out", d / "c.pem", "-days", "1", "-subj", "/CN=localhost"], check=True, capture_output=True)
    return d / "c.pem", d / "k.pem"


def _serve(cert, minimum: ssl.TLSVersion) -> int:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(*cert)
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    ctx.minimum_version = minimum
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)

    def loop():
        while True:
            conn, _ = sock.accept()
            try:
                ctx.wrap_socket(conn, server_side=True).close()
            except Exception:
                conn.close()
    threading.Thread(target=loop, daemon=True).start()
    return sock.getsockname()[1]


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_legacy_tls_is_detected_when_the_server_accepts_it(cert, monkeypatch):
    monkeypatch.setattr(sslscan, "PORT", _serve(cert, ssl.TLSVersion.TLSv1))
    assert sslscan._probe_tls_version("127.0.0.1", ssl.TLSVersion.TLSv1) is True
    assert sslscan._probe_tls_version("127.0.0.1", ssl.TLSVersion.TLSv1_1) is True


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_legacy_tls_is_reported_off_when_the_server_refuses_it(cert, monkeypatch):
    monkeypatch.setattr(sslscan, "PORT", _serve(cert, ssl.TLSVersion.TLSv1_2))
    assert sslscan._probe_tls_version("127.0.0.1", ssl.TLSVersion.TLSv1) is False
    assert sslscan._probe_tls_version("127.0.0.1", ssl.TLSVersion.TLSv1_2) is True
