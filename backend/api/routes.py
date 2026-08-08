import uuid
import asyncio
from fastapi import APIRouter, HTTPException, Depends, Query, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func, cast, Date
from datetime import datetime, timezone, date
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
from auth.deps import get_optional_user_id, require_user_id, get_is_owner
from api.livefeed_router import limiter
from netguard import assert_public_host_async, UnsafeTargetError

router = APIRouter(prefix="/api/v1", tags=["scan"])


async def _ensure_public(domain: str) -> None:
    """SSRF guard — reject targets that resolve to private/internal IPs."""
    try:
        await assert_public_host_async(domain)
    except UnsafeTargetError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------------------------------------------------------------------------
# Individual scanners
# ---------------------------------------------------------------------------

@router.post("/scan/headers", response_model=HeaderScanResult)
@limiter.limit("20/minute")
async def scan_security_headers(http_request: Request, request: ScanRequest) -> HeaderScanResult:
    await _ensure_public(request.domain)
    try:
        return await scan_headers(request.domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/scan/dns", response_model=DNSScanResult)
@limiter.limit("20/minute")
async def scan_dns_records(http_request: Request, request: ScanRequest) -> DNSScanResult:
    await _ensure_public(request.domain)
    try:
        return await scan_dns(request.domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DNS scan failed: {str(e)}")


@router.post("/scan/ssl", response_model=SSLScanResult)
@limiter.limit("20/minute")
async def scan_ssl_tls(http_request: Request, request: ScanRequest) -> SSLScanResult:
    await _ensure_public(request.domain)
    try:
        return await scan_ssl(request.domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SSL scan failed: {str(e)}")


@router.post("/scan/exposure", response_model=ExposureScanResult)
@limiter.limit("20/minute")
async def scan_exposure_paths(http_request: Request, request: ScanRequest) -> ExposureScanResult:
    await _ensure_public(request.domain)
    try:
        return await scan_exposure(request.domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Exposure scan failed: {str(e)}")


@router.post("/scan/fingerprint", response_model=FingerprintScanResult)
@limiter.limit("20/minute")
async def scan_fingerprint_tech(http_request: Request, request: ScanRequest) -> FingerprintScanResult:
    await _ensure_public(request.domain)
    try:
        return await scan_fingerprint(request.domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fingerprint scan failed: {str(e)}")


# ---------------------------------------------------------------------------
# Full scan — runs all scanners concurrently and persists the result
# ---------------------------------------------------------------------------

FREE_SCAN_LIMIT = 5
ANON_DAILY_LIMIT = 1


def _start_of_month() -> datetime:
    now = datetime.now(timezone.utc)
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _start_of_today() -> datetime:
    now = datetime.now(timezone.utc)
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


def _get_client_ip(http_request: Request) -> str:
    forwarded_for = http_request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return http_request.client.host if http_request.client else "unknown"


@router.post("/scan/full", response_model=FullScanResult)
@limiter.limit("15/minute")
async def scan_full(
    request: ScanRequest,
    http_request: Request,
    db: AsyncSession | None = Depends(get_db),
    user_id: str | None = Depends(get_optional_user_id),
    is_owner: bool = Depends(get_is_owner),
) -> FullScanResult:
    client_ip = _get_client_ip(http_request)

    if db is not None and not is_owner:
        if user_id:
            # Logged-in free users: 5 scans per month
            count = await db.scalar(
                select(func.count()).where(
                    ScanJob.user_id == user_id,
                    ScanJob.created_at >= _start_of_month(),
                )
            )
            if (count or 0) >= FREE_SCAN_LIMIT:
                raise HTTPException(
                    status_code=402,
                    detail=f"Monthly scan limit reached ({FREE_SCAN_LIMIT}/{FREE_SCAN_LIMIT}). Upgrade to Starter for unlimited scans.",
                )
        else:
            # Anonymous users: 1 scan per day per IP
            count = await db.scalar(
                select(func.count()).where(
                    ScanJob.user_id.is_(None),
                    ScanJob.ip_address == client_ip,
                    ScanJob.created_at >= _start_of_today(),
                )
            )
            if (count or 0) >= ANON_DAILY_LIMIT:
                raise HTTPException(
                    status_code=402,
                    detail="Daily scan limit reached. Create a free account for 5 scans per month, or upgrade to Starter for unlimited scans.",
                )

    try:
        result = await run_full_scan(request.domain)
    except UnsafeTargetError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Full scan failed: {str(e)}")

    if db is not None:
        job = ScanJob(
            id=uuid.uuid4(),
            domain=result.domain,
            overall_risk_score=result.overall_risk_score,
            overall_risk_level=result.overall_risk_level,
            result=result.model_dump(),
            user_id=user_id,
            paid=False,
            ip_address=client_ip,
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
    user_id: str = Depends(require_user_id),
) -> list[ScanHistoryItem]:
    if db is None:
        raise HTTPException(status_code=503, detail="Database not configured")

    stmt = (
        select(ScanJob)
        .where(ScanJob.user_id == user_id)
        .order_by(desc(ScanJob.created_at))
        .limit(limit)
    )
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
    user_id: str | None = Depends(get_optional_user_id),
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

    # Scans with a user_id are private — only the owner can access them
    if row.user_id and row.user_id != user_id:
        raise HTTPException(status_code=403, detail="Access denied")

    result = FullScanResult.model_validate(row.result)
    result.scan_id = str(row.id)
    result.paid = row.paid
    return result


# ---------------------------------------------------------------------------
# Business reports (HTML + PDF)
# ---------------------------------------------------------------------------

async def _load_scan(scan_id: str, db: AsyncSession | None, user_id: str | None = None) -> FullScanResult:
    if db is None:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        job_id = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID")
    row = await db.get(ScanJob, job_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if row.user_id and row.user_id != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    result = FullScanResult.model_validate(row.result)
    result.scan_id = str(row.id)
    result.paid = row.paid
    return result


@router.get("/scans/{scan_id}/report", response_class=HTMLResponse)
async def download_html_report(
    scan_id: str,
    client_name: str = Query(default="", description="Client or company name for the cover page"),
    db: AsyncSession | None = Depends(get_db),
    user_id: str | None = Depends(get_optional_user_id),
) -> HTMLResponse:
    result = await _load_scan(scan_id, db, user_id)
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
    user_id: str | None = Depends(get_optional_user_id),
) -> Response:
    result = await _load_scan(scan_id, db, user_id)
    loop = asyncio.get_running_loop()
    pdf_bytes = await loop.run_in_executor(None, generate_pdf, result, client_name)
    filename = f"security-report-{result.domain}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# Usage / account
# ---------------------------------------------------------------------------

@router.get("/me/usage")
async def get_usage(
    user_id: str = Depends(require_user_id),
    db: AsyncSession | None = Depends(get_db),
) -> dict:
    if db is None:
        return {"scans_used": 0, "scans_limit": FREE_SCAN_LIMIT, "scans_remaining": FREE_SCAN_LIMIT}
    count = await db.scalar(
        select(func.count()).where(
            ScanJob.user_id == user_id,
            ScanJob.created_at >= _start_of_month(),
        )
    )
    used = int(count or 0)
    return {
        "scans_used": used,
        "scans_limit": FREE_SCAN_LIMIT,
        "scans_remaining": max(0, FREE_SCAN_LIMIT - used),
    }


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@router.get("/health")
async def health(db: AsyncSession | None = Depends(get_db)) -> dict:
    return {
        "status": "ok",
        "database": "connected" if db is not None else "not configured",
    }
