from fastapi import APIRouter, HTTPException
from models.scan import ScanRequest, HeaderScanResult, DNSScanResult, SSLScanResult
from scanners.headers import scan_headers
from scanners.dns import scan_dns
from scanners.sslscan import scan_ssl

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


@router.get("/health")
async def health() -> dict:
    return {"status": "ok"}
