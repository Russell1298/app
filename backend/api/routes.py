import uuid
from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from models.scan import (
    ScanRequest, HeaderScanResult, DNSScanResult, SSLScanResult,
    ExposureScanResult, FingerprintScanResult, FullScanResult, ScanHistoryItem,
)
from scanners.headers import scan_headers
from scanners.dns import scan_dns
from scanners.sslscan import scan_ssl
from scanners.exposure import scan_exposure
from scanners.fingerprint import scan_fingerprint
from services.scan_orchestrator import run_full_scan
from reports.html_report import generate_html, generate_pdf
from db.session import get_db
from db.models import ScanJob

router = APIRouter(prefix="/api/v1", tags=["scan"])


# ---------------------------------------------------------------------------
# Individual scanners
# ---------------------------------------------------------------------------

@router.post("/scan/headers", response_model=HeaderScanResult)
async def scan_security_headers(request: ScanRequest) -> HeaderScanResult:
    try:
        return await scan_headers(request.domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/scan/dns", response_model=DNSScanResult)
async def scan_dns_records(request: ScanRequest) -> DNSScanResult:
    try:
        return await scan_dns(request.domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DNS scan failed: {str(e)}")


@router.post("/scan/ssl", response_model=SSLScanResult)
async def scan_ssl_tls(request: ScanRequest) -> SSLScanResult:
    try:
        return await scan_ssl(request.domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SSL scan failed: {str(e)}")


@router.post("/scan/exposure", response_model=ExposureScanResult)
async def scan_exposure_paths(request: ScanRequest) -> ExposureScanResult:
    try:
        return await scan_exposure(request.domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Exposure scan failed: {str(e)}")


@router.post("/scan/fingerprint", response_model=FingerprintScanResult)
async def scan_fingerprint_tech(request: ScanRequest) -> FingerprintScanResult:
    try:
        return await scan_fingerprint(request.domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fingerprint scan failed: {str(e)}")


# ---------------------------------------------------------------------------
# Full scan — runs all scanners concurrently and persists the result
# ---------------------------------------------------------------------------

@router.post("/scan/full", response_model=FullScanResult)
async def scan_full(
    request: ScanRequest,
    db: AsyncSession | None = Depends(get_db),
) -> FullScanResult:
    try:
        result = await run_full_scan(request.domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Full scan failed: {str(e)}")

    if db is not None:
        job = ScanJob(
            id=uuid.uuid4(),
            domain=result.domain,
            overall_risk_score=result.overall_risk_score,
            overall_risk_level=result.overall_risk_level,
            result=result.model_dump(),
        )
        db.add(job)
        await db.commit()
        await db.refresh(job)
        result.scan_id = str(job.id)

    return result


# ---------------------------------------------------------------------------
# Scan history
# ---------------------------------------------------------------------------

@router.get("/scans", response_model=list[ScanHistoryItem])
async def list_scans(
    domain: str | None = Query(default=None, description="Filter by domain"),
    limit: int = Query(default=20, le=100),
    db: AsyncSession | None = Depends(get_db),
) -> list[ScanHistoryItem]:
    if db is None:
        raise HTTPException(status_code=503, detail="Database not configured")

    stmt = select(ScanJob).order_by(desc(ScanJob.created_at)).limit(limit)
    if domain:
        stmt = stmt.where(ScanJob.domain == domain.lower())

    rows = await db.execute(stmt)
    jobs = rows.scalars().all()

    return [
        ScanHistoryItem(
            scan_id=str(j.id),
            domain=j.domain,
            scan_timestamp=j.created_at.isoformat(),
            overall_risk_score=j.overall_risk_score or 0,
            overall_risk_level=j.overall_risk_level or "unknown",
        )
        for j in jobs
    ]


@router.get("/scans/{scan_id}", response_model=FullScanResult)
async def get_scan(
    scan_id: str,
    db: AsyncSession | None = Depends(get_db),
) -> FullScanResult:
    if db is None:
        raise HTTPException(status_code=503, detail="Database not configured")

    try:
        job_id = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    row = await db.get(ScanJob, job_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = FullScanResult.model_validate(row.result)
    result.scan_id = str(row.id)
    return result


# ---------------------------------------------------------------------------
# Business reports (HTML + PDF)
# ---------------------------------------------------------------------------

async def _load_scan(scan_id: str, db: AsyncSession | None) -> FullScanResult:
    if db is None:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        job_id = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID")
    row = await db.get(__import__("db.models", fromlist=["ScanJob"]).ScanJob, job_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return FullScanResult.model_validate(row.result)


@router.get("/scans/{scan_id}/report", response_class=HTMLResponse)
async def download_html_report(
    scan_id: str,
    client_name: str = Query(default="", description="Client or company name for the cover page"),
    db: AsyncSession | None = Depends(get_db),
) -> HTMLResponse:
    """Return a self-contained HTML business report for the scan."""
    result = await _load_scan(scan_id, db)
    html = generate_html(result, client_name=client_name)
    filename = f"security-report-{result.domain}.html"
    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/scans/{scan_id}/report.pdf")
async def download_pdf_report(
    scan_id: str,
    client_name: str = Query(default="", description="Client or company name for the cover page"),
    db: AsyncSession | None = Depends(get_db),
) -> Response:
    """Return a PDF business report for the scan."""
    result = await _load_scan(scan_id, db)
    import asyncio
    loop = asyncio.get_event_loop()
    pdf_bytes = await loop.run_in_executor(None, generate_pdf, result, client_name)
    filename = f"security-report-{result.domain}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@router.get("/health")
async def health(db: AsyncSession | None = Depends(get_db)) -> dict:
    return {
        "status": "ok",
        "database": "connected" if db is not None else "not configured",
    }
