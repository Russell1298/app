from fastapi import APIRouter, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from services.livefeed import get_items

limiter = Limiter(key_func=get_remote_address)

# No prefix on the router — full paths are declared on each route so we can
# expose both /api/livefeed (Lovable homepage ticker) and /api/v1/livefeed
# (dashboard ticker) from the same handler.
router = APIRouter(tags=["livefeed"])


async def _livefeed_handler(request: Request) -> list[dict]:
    """
    Returns up to 10 recent security news items for the homepage ticker.
    Reads from in-memory cache only — never hits upstream sources on request.
    Returns an empty array on cold start rather than 500.
    """
    return get_items()


@router.get("/api/v1/livefeed")
@limiter.limit("60/minute")
async def livefeed_v1(request: Request) -> list[dict]:
    return await _livefeed_handler(request)


@router.get("/api/livefeed")
@limiter.limit("60/minute")
async def livefeed(request: Request) -> list[dict]:
    return await _livefeed_handler(request)
