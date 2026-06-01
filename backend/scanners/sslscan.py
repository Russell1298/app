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
WEAK_CIPHER_PATTERNS = ("RC4", "DES", "3DES", "EXPORT", "NULL", "ANON", "MD5", "ADH", "AECDH")


def _get_cert_and_cipher(domain: str) -> tuple[bytes | None, tuple | None, str | None]:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, PORT), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                return tls.getpeercert(binary_form=True), tls.cipher(), None
    except ssl.SSLCertVerificationError as e:
        ctx_nv = ssl.create_default_context()
        ctx_nv.check_hostname = False
        ctx_nv.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((domain, PORT), timeout=CONNECT_TIMEOUT) as sock:
                with ctx_nv.wrap_socket(sock, server_hostname=domain) as tls:
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
    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [n.value for n in san_ext.value]
    except x509.ExtensionNotFound:
        pass
    return CertInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=cert.not_valid_after_utc.isoformat(),
        days_until_expiry=(cert.not_valid_after_utc - datetime.now(timezone.utc)).days,
        is_self_signed=cert.subject == cert.issuer,
        sans=sans,
        serial_number=format(cert.serial_number, "x"),
    )


def _domain_covered_by_cert(domain: str, cert: CertInfo) -> bool:
    for san in cert.sans:
        if san == domain:
            return True
        if san.startswith("*."):
            parts = domain.split(".")
            if len(parts) >= 2 and ".".join(parts[1:]) == san[2:]:
                return True
    return False


def _findings_from_cert(
    cert: CertInfo, domain: str, verify_error: str | None
) -> tuple[list[SSLFinding], list[str]]:
    findings: list[SSLFinding] = []
    triggers: list[str] = []

    if cert.is_self_signed:
        findings.append(SSLFinding(
            check="Self-signed certificate", status="fail", severity="high",
            description="The certificate is self-signed and will not be trusted by browsers.",
            remediation="Replace with a certificate from a trusted CA (e.g. Let's Encrypt).",
            penalty=PENALTY["high"],
        ))
        triggers.append("cert_self_signed")
    else:
        findings.append(SSLFinding(
            check="Certificate authority", status="pass", severity=None,
            description=f"Certificate issued by a trusted CA: {cert.issuer}",
            remediation=None, penalty=0,
        ))

    if verify_error and not cert.is_self_signed:
        findings.append(SSLFinding(
            check="Certificate verification", status="fail", severity="high",
            description=f"Certificate failed verification: {verify_error}",
            remediation="Check that the certificate chain is complete and matches the hostname.",
            penalty=PENALTY["high"],
        ))

    if cert.days_until_expiry < 0:
        findings.append(SSLFinding(
            check="Certificate expiry", status="fail", severity="high",
            description=f"Certificate expired {abs(cert.days_until_expiry)} day(s) ago.",
            remediation="Renew the certificate immediately.",
            penalty=PENALTY["high"],
        ))
        triggers.append("cert_expired")
    elif cert.days_until_expiry <= EXPIRY_CRITICAL_DAYS:
        findings.append(SSLFinding(
            check="Certificate expiry", status="fail", severity="high",
            description=f"Certificate expires in {cert.days_until_expiry} day(s) — renewal is urgent.",
            remediation="Renew immediately to avoid browser warnings.",
            penalty=PENALTY["high"],
        ))
        triggers.append("cert_expired")
    elif cert.days_until_expiry <= EXPIRY_WARN_DAYS:
        findings.append(SSLFinding(
            check="Certificate expiry", status="warn", severity="medium",
            description=f"Certificate expires in {cert.days_until_expiry} day(s).",
            remediation="Renew within the next week to avoid disruption.",
            penalty=PENALTY["medium"],
        ))
    else:
        findings.append(SSLFinding(
            check="Certificate expiry", status="pass", severity=None,
            description=f"Certificate is valid for {cert.days_until_expiry} more day(s).",
            remediation=None, penalty=0,
        ))

    covered = _domain_covered_by_cert(domain, cert)
    if not covered and cert.sans:
        findings.append(SSLFinding(
            check="Hostname coverage", status="fail", severity="high",
            description=f"Certificate does not cover '{domain}'. SANs: {', '.join(cert.sans[:5])}.",
            remediation="Reissue the certificate including this domain as a SAN.",
            penalty=PENALTY["high"],
        ))
        triggers.append("cert_hostname_mismatch")
    elif cert.sans:
        findings.append(SSLFinding(
            check="Hostname coverage", status="pass", severity=None,
            description=f"Certificate covers '{domain}' via SAN.",
            remediation=None, penalty=0,
        ))

    return findings, triggers


def _findings_from_tls_versions(checks: list[TLSVersionCheck]) -> list[SSLFinding]:
    findings: list[SSLFinding] = []
    version_map = {c.version: c.supported for c in checks}

    if version_map.get("TLS 1.0") is True:
        findings.append(SSLFinding(
            check="TLS 1.0", status="fail", severity="high",
            description="TLS 1.0 is supported. Deprecated protocol with known vulnerabilities (POODLE, BEAST).",
            remediation="nginx: ssl_protocols TLSv1.2 TLSv1.3; Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3",
            penalty=PENALTY["high"],
        ))
    elif version_map.get("TLS 1.0") is False:
        findings.append(SSLFinding(check="TLS 1.0", status="pass", severity=None,
                                   description="TLS 1.0 is correctly disabled.", remediation=None, penalty=0))

    if version_map.get("TLS 1.1") is True:
        findings.append(SSLFinding(
            check="TLS 1.1", status="fail", severity="medium",
            description="TLS 1.1 is supported. Deprecated protocol lacking modern cipher support.",
            remediation="Disable TLS 1.1 alongside TLS 1.0.",
            penalty=PENALTY["medium"],
        ))
    elif version_map.get("TLS 1.1") is False:
        findings.append(SSLFinding(check="TLS 1.1", status="pass", severity=None,
                                   description="TLS 1.1 is correctly disabled.", remediation=None, penalty=0))

    # Aggregate "Legacy TLS" finding when either TLS 1.0 or TLS 1.1 is accepted.
    # This is a separate, lower-penalty signal that groups both deprecated versions
    # into a single actionable remediation note independent of the per-version findings.
    if version_map.get("TLS 1.0") is True or version_map.get("TLS 1.1") is True:
        legacy = []
        if version_map.get("TLS 1.0") is True:
            legacy.append("TLS 1.0")
        if version_map.get("TLS 1.1") is True:
            legacy.append("TLS 1.1")
        findings.append(SSLFinding(
            check="Legacy TLS supported",
            status="fail",
            severity="medium",
            description=(
                f"This server accepts connections using {' and '.join(legacy)}, "
                "which are deprecated and vulnerable to downgrade attacks. "
                "Disable them in your web server config."
            ),
            remediation=(
                "TLS 1.0/1.1 are deprecated and vulnerable to downgrade attacks. "
                "Disable them in your web server config."
            ),
            penalty=10,
        ))

    tls12 = version_map.get("TLS 1.2")
    tls13 = version_map.get("TLS 1.3")

    if tls12 is False and tls13 is False:
        findings.append(SSLFinding(
            check="Modern TLS", status="fail", severity="high",
            description="Neither TLS 1.2 nor TLS 1.3 is supported. Most clients require TLS 1.2 minimum.",
            remediation="Enable TLS 1.2 and TLS 1.3 in your server configuration.",
            penalty=PENALTY["high"],
        ))
    else:
        if tls12 is True:
            findings.append(SSLFinding(check="TLS 1.2", status="pass", severity=None,
                                       description="TLS 1.2 is supported.", remediation=None, penalty=0))
        elif tls12 is False:
            findings.append(SSLFinding(
                check="TLS 1.2", status="fail", severity="high",
                description="TLS 1.2 is not supported. Many clients require TLS 1.2 as a minimum.",
                remediation="Enable TLS 1.2 in your server configuration.",
                penalty=PENALTY["high"],
            ))
        if tls13 is True:
            findings.append(SSLFinding(check="TLS 1.3", status="pass", severity=None,
                                       description="TLS 1.3 is supported — best available protocol.",
                                       remediation=None, penalty=0))
        elif tls13 is False:
            findings.append(SSLFinding(
                check="TLS 1.3", status="warn", severity="low",
                description="TLS 1.3 is not supported. TLS 1.3 is faster and more secure than TLS 1.2.",
                remediation="Enable TLS 1.3 — most modern servers support it with a recent OpenSSL version.",
                penalty=PENALTY["low"],
            ))

    return findings


def _finding_from_cipher(cipher: tuple | None) -> SSLFinding | None:
    if not cipher:
        return None
    name = cipher[0]
    if any(w in name.upper() for w in WEAK_CIPHER_PATTERNS):
        return SSLFinding(
            check="Negotiated cipher suite", status="fail", severity="high",
            description=f"Weak cipher suite negotiated: {name}.",
            remediation="Prefer AES-GCM and ChaCha20-Poly1305. Remove RC4, 3DES, and EXPORT ciphers.",
            penalty=PENALTY["high"],
        )
    return SSLFinding(check="Negotiated cipher suite", status="pass", severity=None,
                     description=f"Cipher suite is acceptable: {name} ({cipher[1]})",
                     remediation=None, penalty=0)


def _score(findings: list[SSLFinding]) -> tuple[int, str]:
    total = sum(f.penalty for f in findings)
    risk = scanner_score(total, "ssl")
    return risk, risk_level(risk)


async def scan_ssl(domain: str, port: int = PORT) -> SSLScanResult:
    loop = asyncio.get_event_loop()

    def _run_all():
        der, cipher, verify_error = _get_cert_and_cipher(domain)
        tls_results = []
        for label, version in [
            ("TLS 1.0", ssl.TLSVersion.TLSv1),
            ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
            ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
            ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
        ]:
            tls_results.append(TLSVersionCheck(version=label, supported=_probe_tls_version(domain, version)))
        return der, cipher, verify_error, tls_results

    der, cipher, verify_error, tls_version_results = await loop.run_in_executor(None, _run_all)

    findings: list[SSLFinding] = []
    critical_triggers: list[str] = []
    cert_info: CertInfo | None = None

    if der is None:
        findings.append(SSLFinding(
            check="TLS reachability", status="fail", severity="high",
            description=f"Could not establish a TLS connection to {domain}:{port}. Error: {verify_error}",
            remediation="Ensure HTTPS is enabled and the server is reachable on port 443.",
            penalty=PENALTY["high"],
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

    return SSLScanResult(
        domain=domain, port=port,
        scan_timestamp=utc_now_iso(),
        certificate=cert_info,
        tls_versions=tls_version_results,
        findings=findings,
        risk_score=risk_score,
        risk_level=level,
        critical_triggers=critical_triggers,
        summary={
            "checks_run": len(findings),
            "fail": sum(1 for f in findings if f.status == "fail"),
            "warn": sum(1 for f in findings if f.status == "warn"),
            "pass": sum(1 for f in findings if f.status == "pass"),
            "certificate_present": cert_info is not None,
        },
    )
