"""
SSL/TLS scanner.

Uses the stdlib ssl module and the cryptography library to perform a
passive handshake-level inspection of the target's TLS configuration.
No traffic decryption, no exploitation — only inspects what the server
advertises during a normal TLS handshake.

Checks:
  - Certificate presence and reachability
  - Certificate expiry (expired / expiring soon)
  - Self-signed certificate detection
  - Hostname coverage (SAN / CN match)
  - TLS 1.0 and 1.1 support (deprecated, should be disabled)
  - TLS 1.2 and 1.3 support (required)
  - Weak cipher suite detection on the negotiated connection
"""

import ssl
import socket
import asyncio
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from models.scan import CertInfo, TLSVersionCheck, SSLFinding, SSLScanResult, utc_now_iso

PORT = 443
CONNECT_TIMEOUT = 8

# Days-until-expiry thresholds
EXPIRY_CRITICAL_DAYS = 14
EXPIRY_WARN_DAYS = 30

# Cipher substrings considered weak
WEAK_CIPHER_PATTERNS = (
    "RC4", "DES", "3DES", "EXPORT", "NULL", "ANON", "MD5", "ADH", "AECDH",
)


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _get_cert_and_cipher(domain: str) -> tuple[bytes | None, tuple | None, str | None]:
    """
    Open a TLS connection with full certificate verification and return
    (DER cert bytes, cipher tuple, error string).
    """
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, PORT), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                der = tls.getpeercert(binary_form=True)
                cipher = tls.cipher()
                return der, cipher, None
    except ssl.SSLCertVerificationError as e:
        # Cert is present but fails verification — still grab it without checks
        ctx_noverify = ssl.create_default_context()
        ctx_noverify.check_hostname = False
        ctx_noverify.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((domain, PORT), timeout=CONNECT_TIMEOUT) as sock:
                with ctx_noverify.wrap_socket(sock, server_hostname=domain) as tls:
                    der = tls.getpeercert(binary_form=True)
                    cipher = tls.cipher()
                    return der, cipher, str(e)
        except Exception:
            pass
        return None, None, str(e)
    except Exception as e:
        return None, None, str(e)


def _probe_tls_version(domain: str, version: ssl.TLSVersion) -> bool | None:
    """
    Try a TLS handshake restricted to exactly `version`.
    Returns True if the server accepted it, False if refused, None if the
    local OpenSSL build does not support that version at all.
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (AttributeError, ssl.SSLError):
        return None  # OS/OpenSSL does not support setting this version

    try:
        with socket.create_connection((domain, PORT), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain):
                return True
    except ssl.SSLError:
        return False
    except OSError:
        return False


def _parse_cert(der: bytes) -> CertInfo:
    cert = x509.load_der_x509_certificate(der)

    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    is_self_signed = cert.subject == cert.issuer

    not_before = cert.not_valid_before_utc.isoformat()
    not_after = cert.not_valid_after_utc.isoformat()
    days_until_expiry = (cert.not_valid_after_utc - datetime.now(timezone.utc)).days

    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [n.value for n in san_ext.value]
    except x509.ExtensionNotFound:
        pass

    serial = format(cert.serial_number, "x")

    return CertInfo(
        subject=subject,
        issuer=issuer,
        not_before=not_before,
        not_after=not_after,
        days_until_expiry=days_until_expiry,
        is_self_signed=is_self_signed,
        sans=sans,
        serial_number=serial,
    )


def _domain_covered_by_cert(domain: str, cert: CertInfo) -> bool:
    """Check whether the domain matches any SAN entry (supports wildcards)."""
    for san in cert.sans:
        if san == domain:
            return True
        if san.startswith("*."):
            wildcard_base = san[2:]
            # *.example.com covers sub.example.com but NOT example.com
            host_parts = domain.split(".")
            if len(host_parts) >= 2 and ".".join(host_parts[1:]) == wildcard_base:
                return True
    return False


# ---------------------------------------------------------------------------
# Finding builders
# ---------------------------------------------------------------------------

def _findings_from_cert(cert: CertInfo, domain: str, verify_error: str | None) -> list[SSLFinding]:
    findings: list[SSLFinding] = []

    # Self-signed
    if cert.is_self_signed:
        findings.append(SSLFinding(
            check="Self-signed certificate",
            status="fail",
            severity="high",
            description=(
                "The certificate is self-signed and will not be trusted by browsers. "
                "Visitors will see a security warning and many will leave."
            ),
            remediation=(
                "Replace with a certificate from a trusted CA. "
                "Let's Encrypt provides free, auto-renewing certificates via Certbot."
            ),
        ))
    else:
        findings.append(SSLFinding(
            check="Certificate authority",
            status="pass",
            severity=None,
            description=f"Certificate issued by a trusted CA: {cert.issuer}",
            remediation=None,
        ))

    # Verification failure (not self-signed, but still failing — e.g. wrong hostname in chain)
    if verify_error and not cert.is_self_signed:
        findings.append(SSLFinding(
            check="Certificate verification",
            status="fail",
            severity="high",
            description=f"Certificate failed verification: {verify_error}",
            remediation=(
                "Check that the certificate chain is complete and that the certificate "
                "matches the hostname. Renew or reissue if necessary."
            ),
        ))

    # Expiry
    if cert.days_until_expiry < 0:
        findings.append(SSLFinding(
            check="Certificate expiry",
            status="fail",
            severity="high",
            description=(
                f"Certificate expired {abs(cert.days_until_expiry)} day(s) ago. "
                "Browsers block access to sites with expired certificates."
            ),
            remediation=(
                "Renew the certificate immediately. If using Let's Encrypt, run: "
                "certbot renew --force-renewal"
            ),
        ))
    elif cert.days_until_expiry <= EXPIRY_CRITICAL_DAYS:
        findings.append(SSLFinding(
            check="Certificate expiry",
            status="fail",
            severity="high",
            description=f"Certificate expires in {cert.days_until_expiry} day(s) — renewal is urgent.",
            remediation="Renew immediately to avoid browser warnings.",
        ))
    elif cert.days_until_expiry <= EXPIRY_WARN_DAYS:
        findings.append(SSLFinding(
            check="Certificate expiry",
            status="warn",
            severity="medium",
            description=f"Certificate expires in {cert.days_until_expiry} day(s).",
            remediation="Renew within the next week to avoid disruption.",
        ))
    else:
        findings.append(SSLFinding(
            check="Certificate expiry",
            status="pass",
            severity=None,
            description=f"Certificate is valid for {cert.days_until_expiry} more day(s).",
            remediation=None,
        ))

    # Hostname coverage
    covered = _domain_covered_by_cert(domain, cert)
    if not covered and cert.sans:
        findings.append(SSLFinding(
            check="Hostname coverage",
            status="fail",
            severity="high",
            description=(
                f"The certificate does not cover '{domain}'. "
                f"SANs present: {', '.join(cert.sans[:5])}."
            ),
            remediation=(
                "Reissue the certificate including this domain as a SAN entry."
            ),
        ))
    elif cert.sans:
        findings.append(SSLFinding(
            check="Hostname coverage",
            status="pass",
            severity=None,
            description=f"Certificate covers '{domain}' via SAN.",
            remediation=None,
        ))

    return findings


def _findings_from_tls_versions(checks: list[TLSVersionCheck]) -> list[SSLFinding]:
    findings: list[SSLFinding] = []
    version_map = {c.version: c.supported for c in checks}

    if version_map.get("TLS 1.0") is True:
        findings.append(SSLFinding(
            check="TLS 1.0",
            status="fail",
            severity="high",
            description=(
                "TLS 1.0 is supported. This protocol was deprecated in 2020 and has "
                "known vulnerabilities (POODLE, BEAST). PCI-DSS compliance requires "
                "it to be disabled."
            ),
            remediation=(
                "Disable TLS 1.0 in your web server config.\n"
                "nginx:  ssl_protocols TLSv1.2 TLSv1.3;\n"
                "Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3"
            ),
        ))
    elif version_map.get("TLS 1.0") is False:
        findings.append(SSLFinding(
            check="TLS 1.0",
            status="pass",
            severity=None,
            description="TLS 1.0 is correctly disabled.",
            remediation=None,
        ))

    if version_map.get("TLS 1.1") is True:
        findings.append(SSLFinding(
            check="TLS 1.1",
            status="fail",
            severity="medium",
            description=(
                "TLS 1.1 is supported. This protocol was deprecated in 2020 and "
                "lacks modern cipher suite support."
            ),
            remediation="Disable TLS 1.1 alongside TLS 1.0 using the same server config change.",
        ))
    elif version_map.get("TLS 1.1") is False:
        findings.append(SSLFinding(
            check="TLS 1.1",
            status="pass",
            severity=None,
            description="TLS 1.1 is correctly disabled.",
            remediation=None,
        ))

    if version_map.get("TLS 1.2") is True:
        findings.append(SSLFinding(
            check="TLS 1.2",
            status="pass",
            severity=None,
            description="TLS 1.2 is supported.",
            remediation=None,
        ))
    elif version_map.get("TLS 1.2") is False:
        findings.append(SSLFinding(
            check="TLS 1.2",
            status="fail",
            severity="high",
            description=(
                "TLS 1.2 is not supported. Many clients require TLS 1.2 as a minimum "
                "and will be unable to connect."
            ),
            remediation="Enable TLS 1.2 in your server configuration.",
        ))

    if version_map.get("TLS 1.3") is True:
        findings.append(SSLFinding(
            check="TLS 1.3",
            status="pass",
            severity=None,
            description="TLS 1.3 is supported — best available protocol.",
            remediation=None,
        ))
    elif version_map.get("TLS 1.3") is False:
        findings.append(SSLFinding(
            check="TLS 1.3",
            status="warn",
            severity="low",
            description=(
                "TLS 1.3 is not supported. TLS 1.3 is faster and more secure than "
                "TLS 1.2 and is supported by all modern clients."
            ),
            remediation=(
                "Enable TLS 1.3. Most modern web servers support it out of the box "
                "when updated to a recent OpenSSL version."
            ),
        ))

    return findings


def _finding_from_cipher(cipher: tuple | None) -> SSLFinding | None:
    if not cipher:
        return None
    cipher_name = cipher[0]
    if any(w in cipher_name.upper() for w in WEAK_CIPHER_PATTERNS):
        return SSLFinding(
            check="Negotiated cipher suite",
            status="fail",
            severity="high",
            description=(
                f"The negotiated cipher suite is considered weak: {cipher_name}. "
                "Weak ciphers can be broken, exposing the connection to decryption."
            ),
            remediation=(
                "Configure your server to prefer strong cipher suites such as "
                "AES-GCM and ChaCha20-Poly1305. Remove all RC4, 3DES, and EXPORT ciphers."
            ),
        )
    return SSLFinding(
        check="Negotiated cipher suite",
        status="pass",
        severity=None,
        description=f"Negotiated cipher suite is acceptable: {cipher_name} ({cipher[1]})",
        remediation=None,
    )


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

_SEVERITY_PENALTY = {"high": 25, "medium": 12, "low": 5}


def _score(findings: list[SSLFinding]) -> tuple[int, str]:
    total = sum(
        _SEVERITY_PENALTY[f.severity]
        for f in findings
        if f.status in ("fail", "warn") and f.severity
    )
    total = min(total, 100)
    if total < 25:
        return total, "low"
    if total < 50:
        return total, "medium"
    if total < 75:
        return total, "high"
    return total, "critical"


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def scan_ssl(domain: str, port: int = PORT) -> SSLScanResult:
    """
    Inspect the TLS configuration of a domain. All socket I/O runs in a
    thread pool so the FastAPI event loop is never blocked.
    """
    loop = asyncio.get_event_loop()

    def _run_all():
        der, cipher, verify_error = _get_cert_and_cipher(domain)

        tls_version_results: list[TLSVersionCheck] = []
        for label, version in [
            ("TLS 1.0", ssl.TLSVersion.TLSv1),
            ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
            ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
            ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
        ]:
            supported = _probe_tls_version(domain, version)
            tls_version_results.append(TLSVersionCheck(version=label, supported=supported))

        return der, cipher, verify_error, tls_version_results

    der, cipher, verify_error, tls_version_results = await loop.run_in_executor(None, _run_all)

    findings: list[SSLFinding] = []
    cert_info: CertInfo | None = None

    if der is None:
        findings.append(SSLFinding(
            check="TLS reachability",
            status="fail",
            severity="high",
            description=f"Could not establish a TLS connection to {domain}:{port}. Error: {verify_error}",
            remediation="Ensure HTTPS is enabled and the server is reachable on port 443.",
        ))
    else:
        cert_info = _parse_cert(der)
        findings += _findings_from_cert(cert_info, domain, verify_error)
        cipher_finding = _finding_from_cipher(cipher)
        if cipher_finding:
            findings.append(cipher_finding)

    findings += _findings_from_tls_versions(tls_version_results)

    risk_score, risk_level = _score(findings)

    fail_count = sum(1 for f in findings if f.status == "fail")
    warn_count = sum(1 for f in findings if f.status == "warn")
    pass_count = sum(1 for f in findings if f.status == "pass")

    return SSLScanResult(
        domain=domain,
        port=port,
        scan_timestamp=utc_now_iso(),
        certificate=cert_info,
        tls_versions=tls_version_results,
        findings=findings,
        risk_score=risk_score,
        risk_level=risk_level,
        summary={
            "checks_run": len(findings),
            "fail": fail_count,
            "warn": warn_count,
            "pass": pass_count,
            "certificate_present": cert_info is not None,
        },
    )
