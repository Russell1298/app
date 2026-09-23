import os
import jwt
from fastapi import Header, HTTPException

_SECRET = os.getenv("SUPABASE_JWT_SECRET", "")
_OWNER_EMAIL = os.getenv("OWNER_EMAIL", "").strip().lower()


def _decode_payload(authorization: str | None) -> dict | None:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    if not _SECRET:
        return None
    token = authorization.removeprefix("Bearer ")
    try:
        return jwt.decode(
            token,
            _SECRET,
            algorithms=["HS256"],
            audience="authenticated",
        )
    except jwt.PyJWTError:
        return None


def _decode(authorization: str | None) -> str | None:
    payload = _decode_payload(authorization)
    return payload.get("sub") if payload else None


def get_optional_user_id(authorization: str | None = Header(default=None)) -> str | None:
    return _decode(authorization)


def require_user_id(authorization: str | None = Header(default=None)) -> str:
    user_id = _decode(authorization)
    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user_id


def get_is_owner(authorization: str | None = Header(default=None)) -> bool:
    """True if the request is authenticated as the account configured in OWNER_EMAIL."""
    if not _OWNER_EMAIL:
        return False
    payload = _decode_payload(authorization)
    if not payload:
        return False
    email = str(payload.get("email", "")).strip().lower()
    return bool(email) and email == _OWNER_EMAIL
