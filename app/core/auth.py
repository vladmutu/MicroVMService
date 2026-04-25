from fastapi import Header, HTTPException, status

from app.core.config import get_settings


async def optional_bearer_auth(authorization: str | None = Header(default=None)) -> None:
    settings = get_settings()
    expected = settings.bearer_token
    if not expected:
        return

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")

    presented = authorization.removeprefix("Bearer ").strip()
    if presented != expected:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bearer token")
