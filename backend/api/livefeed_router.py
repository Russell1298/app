from fastapi import APIRouter, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from services.livefeed import get_items

limiter = Limiter(key_func=get_remote_address)
router = APIRouter(prefix="/api/v1", tags=["livefeed"])


@router.get("/livefeed")
@limiter.limit("60/minute")
async def livefeed(request: Request) -> list[dict]:
    """
    Returns up to 10 recent security news items for the homepage ticker.
    Reads from in-memory cache only — never hits upstream sources on request.
    Returns an empty array on cold start rather than 500.
    """
    return get_items()
