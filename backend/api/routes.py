from fastapi import APIRouter, HTTPException
from models.scan import (
    ScanRequest, HeaderScanResult, DNSScanResult, SSLScanResult,
    ExposureScanResult, FingerprintScanResult, FullScanResult,
)
from scanners.headers import scan_headers
from scanners.dns import scan_dns
from scanners.sslscan import scan_ssl
from scanners.exposure import scan_exposure
from scanners.fingerprint import scan_fingerprint
from services.scan_orchestrator import run_full_scan

router = APIRouter(prefix="/api/v1", tags=["scan"])


@router.post("/scan/headers", response_model=HeaderScanResult)
async def scan_security_headers(request: ScanRequest) -> HeaderScanResult:
    """
    Accept a domain name and return a structured security header report.

    Only performs a passive HTTP GET — no exploitation or intrusion.
    """
    try:
        result = await scan_headers(request.domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
    return result


@router.post("/scan/dns", response_model=DNSScanResult)
async def scan_dns_records(request: ScanRequest) -> DNSScanResult:
    """
    Perform passive DNS lookups for the domain: A/AAAA, MX, NS, TXT,
    SPF, DMARC, CAA, and DNSSEC. No zone transfers or enumeration.
    """
    try:
        result = await scan_dns(request.domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DNS scan failed: {str(e)}")
    return result


@router.post("/scan/ssl", response_model=SSLScanResult)
async def scan_ssl_tls(request: ScanRequest) -> SSLScanResult:
    """
    Inspect TLS configuration: certificate validity, expiry, self-signed
    detection, hostname coverage, TLS version support, and cipher suite.
    Passive handshake inspection only — no traffic decryption.
    """
    try:
        result = await scan_ssl(request.domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SSL scan failed: {str(e)}")
    return result


@router.post("/scan/exposure", response_model=ExposureScanResult)
async def scan_exposure_paths(request: ScanRequest) -> ExposureScanResult:
    """
    Check well-known paths for dangerous public exposure: .git, .env,
    admin panels, debug endpoints, directory listings. Passive GET only —
    no fuzzing or enumeration.
    """
    try:
        result = await scan_exposure(request.domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Exposure scan failed: {str(e)}")
    return result


@router.post("/scan/fingerprint", response_model=FingerprintScanResult)
async def scan_fingerprint_tech(request: ScanRequest) -> FingerprintScanResult:
    """
    Detect CMS, framework, CDN, server software, and JS libraries from
    HTTP headers and homepage HTML. Single passive GET, no active probing.
    """
    try:
        result = await scan_fingerprint(request.domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fingerprint scan failed: {str(e)}")
    return result


@router.post("/scan/full", response_model=FullScanResult)
async def scan_full(request: ScanRequest) -> FullScanResult:
    """
    Run all five scanners concurrently and return a single unified report
    with an aggregated risk score and prioritised top findings.
    """
    try:
        result = await run_full_scan(request.domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Full scan failed: {str(e)}")
    return result


@router.get("/health")
async def health() -> dict:
    return {"status": "ok"}
