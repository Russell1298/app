from fastapi import APIRouter, HTTPException
from models.scan import ScanRequest, HeaderScanResult
from scanners.headers import scan_headers

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


@router.get("/health")
async def health() -> dict:
    return {"status": "ok"}
