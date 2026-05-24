from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routes import router
from db.session import init_db, create_tables


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    await create_tables()
    yield


app = FastAPI(
    title="Site Exposure Scanner",
    description="Defensive security assessment API — passive scanning only.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # tighten to your frontend origin in prod
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

app.include_router(router)
