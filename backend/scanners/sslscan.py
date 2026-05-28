"""
SSL/TLS scanner.

Passive TLS handshake inspection. No traffic decryption, no exploitation.
"""

import ssl
import socket
import asyncio
from datetime import datetime, timezone
from cryptography import x509
from models.scan import CertInfo, TLSVersionCheck, SSLFinding, SSLScanResult, utc_now_iso
from scoring_config import PENALTY, scanner_score, risk_level

PORT = 443
CONNECT_TIMEOUT = 8

EXPIRY_CRITICAL_DAYS = 7
EXPIRY_WARN_DAYS = 30

WEAK_CIPHER_PATTERNS = (
    "RC4", "DES", "3DES", "EXPORT", "NULL", "ANON", "MD5", "ADH", "AECDH",
)


def _get_cert_and_cipher(domain: str) -> tuple[bytes | None, tuple | None, str | None]:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, PORT), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                return tls.getpeercert(binary_form=True), tls.cipher(), None
    except ssl.SSLCertVerificationError as e:
        ctx_noverify = ssl.create_default_context()
        ctx_noverify.check_hostname = False
        ctx_noverify.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((domain, PORT), timeout=CONNECT_TIMEOUT) as sock:
                with ctx_noverify.wrap_socket(sock, server_hostname=domain) as tls:
                    return tls.getpeercert(binary_form=True), tls.cipher(), str(e)
        except Exception:
            pass
        return None, None, str(e)
    except Exception as e:
        return None, None, str(e)


def _probe_tls_version(domain: str, version: ssl.TLSVersion) -> bool | None:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (AttributeError, ssl.SSLError):
        return None
    try:
        with socket.create_connection((domain, PORT), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain):
                return True
    except (ssl.SSLError, OSError):
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
    return CertInfo(
        subject=subject,
        issuer=issuer,
        not_before=not_before,
        not_after=not_after,
        days_until_expiry=days_until_expiry,
        is_self_signed=is_self_signed,
        sans=sans,
        serial_number=format(cert.serial_number, "x"),
    )


def _domain_covered_by_cert(domain: str, cert: CertInfo) -> bool:
    for san in cert.sans:
        if san == domain:
            return True
        if san.startswith("*."):
            wildcard_base = san[2:]
            host_parts = domain.split(".")
            if len(host_parts) >= 2 and ".".join(host_parts[1:]) == wildcard_base:
                return True
    return False


def _findings_from_cert(
    cert: CertInfo, domain: str, verify_error: str | None
) -> tuple[list[SSLFinding], list[str]]:
    findings: list[SSLFinding] = []
    triggers: list[str] = []

    if cert.is_self_signed:
        findings.append(SSLFinding(
            check="Self-signed certificate",
            status="fail",
            severity="high",
            description=(
                "The certificate is self-signed and will not be trusted by browsers. "
                "Visitors will see a security warning."
            ),
            remediation=(
                "Replace with a certificate from a trusted CA. "
                "Let's Encrypt provides free, auto-renewing certificates via Certbot."
            ),
        ))
        triggers.append("cert_self_signed")
    else:
        findings.append(SSLFinding(
            check="Certificate authority",
            status="pass",
            severity=None,
            description=f"Certificate issued by a trusted CA: {cert.issuer}",
            remediation=None,
        ))

    if verify_error and not cert.is_self_signed:
        findings.append(SSLFinding(
            check="Certificate verification",
            status="fail",
            severity="high",
            description=f"Certificate failed verification: {verify_error}",
            remediation="Check that the certificate chain is complete and matches the hostname.",
        ))

    if cert.days_until_expiry < 0:
        findings.append(SSLFinding(
            check="Certificate expiry",
            status="fail",
            severity="high",
            description=(
                f"Certificate expired {abs(cert.days_until_expiry)} day(s) ago. "
                "Browsers block access to sites with expired certificates."
            ),
            remediation="Renew the certificate immediately.",
        ))
        triggers.append("cert_expired")
    elif cert.days_until_expiry <= EXPIRY_CRITICAL_DAYS:
        findings.append(SSLFinding(
            check="Certificate expiry",
            status="fail",
            severity="high",
            description=f"Certificate expires in {cert.days_until_expiry} day(s) — renewal is urgent.",
            remediation="Renew immediately to avoid browser warnings.",
        ))
        triggers.append("cert_expired")
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
            remediation="Reissue the certificate including this domain as a SAN entry.",
        ))
        triggers.append("cert_hostname_mismatch")
    elif cert.sans:
        findings.append(SSLFinding(
            check="Hostname coverage",
            status="pass",
            severity=None,
            description=f"Certificate covers '{domain}' via SAN.",
            remediation=None,
        ))

    return findings, triggers


def _findings_from_tls_versions(checks: list[TLSVersionCheck]) -> list[SSLFinding]:
    findings: list[SSLFinding] = []
    version_map = {c.version: c.supported for c in checks}

    if version_map.get("TLS 1.0") is True:
        findings.append(SSLFinding(
            check="TLS 1.0",
            status="fail",
            severity="high",
            description=(
                "TLS 1.0 is supported. This deprecated protocol has known vulnerabilities "
                "(POODLE, BEAST) and is required to be disabled for PCI-DSS compliance."
            ),
            remediation=(
                "Disable TLS 1.0: "
                "nginx: ssl_protocols TLSv1.2 TLSv1.3; "
                "Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3"
            ),
        ))
    elif version_map.get("TLS 1.0") is False:
        findings.append(SSLFinding(check="TLS 1.0", status="pass", severity=None, description="TLS 1.0 is correctly disabled.", remediation=None))

    if version_map.get("TLS 1.1") is True:
        findings.append(SSLFinding(
            check="TLS 1.1",
            status="fail",
            severity="medium",
            description="TLS 1.1 is supported. This deprecated protocol lacks modern cipher support.",
            remediation="Disable TLS 1.1 alongside TLS 1.0.",
        ))
    elif version_map.get("TLS 1.1") is False:
        findings.append(SSLFinding(check="TLS 1.1", status="pass", severity=None, description="TLS 1.1 is correctly disabled.", remediation=None))

    tls12 = version_map.get("TLS 1.2")
    tls13 = version_map.get("TLS 1.3")

    if tls12 is False and tls13 is False:
        # Group into one HIGH finding per v2 spec
        findings.append(SSLFinding(
            check="Modern TLS",
            status="fail",
            severity="high",
            description="Neither TLS 1.2 nor TLS 1.3 is supported. Most clients require TLS 1.2 as a minimum.",
            remediation="Enable TLS 1.2 and TLS 1.3 in your server configuration.",
        ))
    else:
        if tls12 is True:
            findings.append(SSLFinding(check="TLS 1.2", status="pass", severity=None, description="TLS 1.2 is supported.", remediation=None))
        elif tls12 is False:
            findings.append(SSLFinding(
                check="TLS 1.2",
                status="fail",
                severity="high",
                description="TLS 1.2 is not supported. Many clients require TLS 1.2 as a minimum.",
                remediation="Enable TLS 1.2 in your server configuration.",
            ))

        if tls13 is True:
            findings.append(SSLFinding(check="TLS 1.3", status="pass", severity=None, description="TLS 1.3 is supported — best available protocol.", remediation=None))
        elif tls13 is False:
            findings.append(SSLFinding(
                check="TLS 1.3",
                status="warn",
                severity="low",
                description="TLS 1.3 is not supported. TLS 1.3 is faster and more secure than TLS 1.2.",
                remediation="Enable TLS 1.3. Most modern servers support it with a recent OpenSSL version.",
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
            description=f"The negotiated cipher suite is considered weak: {cipher_name}.",
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


def _score(findings: list[SSLFinding]) -> tuple[int, str]:
    total = sum(
        PENALTY[f.severity]
        for f in findings
        if f.status in ("fail", "warn") and f.severity
    )
    risk = scanner_score(total, "ssl")
    return risk, risk_level(risk)


async def scan_ssl(domain: str, port: int = PORT) -> SSLScanResult:
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
    critical_triggers: list[str] = []
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
        cert_findings, cert_triggers = _findings_from_cert(cert_info, domain, verify_error)
        findings += cert_findings
        critical_triggers += cert_triggers
        cipher_finding = _finding_from_cipher(cipher)
        if cipher_finding:
            findings.append(cipher_finding)

    findings += _findings_from_tls_versions(tls_version_results)

    risk_score, level = _score(findings)

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
        risk_level=level,
        critical_triggers=critical_triggers,
        summary={
            "checks_run": len(findings),
            "fail": fail_count,
            "warn": warn_count,
            "pass": pass_count,
            "certificate_present": cert_info is not None,
        },
    )
