from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from api.routes import router
from api.livefeed_router import router as livefeed_router, limiter
from db.session import init_db, create_tables
from services import livefeed
import os


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    await create_tables()
    # Populate the livefeed cache immediately on boot
    await livefeed.refresh()
    # Schedule a refresh every 30 minutes
    scheduler = AsyncIOScheduler()
    scheduler.add_job(livefeed.refresh, "interval", minutes=30, id="livefeed_refresh")
    scheduler.start()
    yield
    scheduler.shutdown(wait=False)


_raw = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000")
_origins = [o.strip() for o in _raw.split(",") if o.strip()]

app = FastAPI(
    title="SiteGuard API",
    description="Defensive security assessment API. Read-only, non-intrusive checks; no exploitation.",
    version="0.2.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)

app.include_router(router)
app.include_router(livefeed_router)
