from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routes import router
from db.session import init_db, create_tables
import os


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    await create_tables()
    yield


# Accept a comma-separated ALLOWED_ORIGINS env var so the same image
# works in dev (localhost), Lovable preview (*.lovable.app), and production.
_raw = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000")
_origins = [o.strip() for o in _raw.split(",") if o.strip()]

app = FastAPI(
    title="SiteGuard API",
    description="Defensive security assessment API — passive scanning only.",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)

app.include_router(router)
