import os
import jwt
from fastapi import Header, HTTPException

_SECRET = os.getenv("SUPABASE_JWT_SECRET", "")


def _decode(authorization: str | None) -> str | None:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    if not _SECRET:
        return None
    token = authorization.removeprefix("Bearer ")
    try:
        payload = jwt.decode(
            token,
            _SECRET,
            algorithms=["HS256"],
            audience="authenticated",
        )
        return payload.get("sub")
    except jwt.PyJWTError:
        return None


def get_optional_user_id(authorization: str | None = Header(default=None)) -> str | None:
    return _decode(authorization)


def require_user_id(authorization: str | None = Header(default=None)) -> str:
    user_id = _decode(authorization)
    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user_id
