import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.models import RevokedToken, User
from app.security import decode_access_token
from app.storage import NoteStorage, get_storage

_bearer = HTTPBearer(auto_error=False, description="JWT from POST /login")

SessionDep = Annotated[AsyncSession, Depends(get_session)]
StorageDep = Annotated[NoteStorage, Depends(get_storage)]


@dataclass
class AuthContext:
    user: User
    jti: uuid.UUID
    expires_at: datetime


def _unauthorized(detail: str = "Not authenticated") -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, detail, headers={"WWW-Authenticate": "Bearer"})


async def get_auth(
    session: SessionDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> AuthContext:
    if credentials is None:
        raise _unauthorized()
    try:
        claims = decode_access_token(credentials.credentials)
        user_id = uuid.UUID(claims["sub"])
        jti = uuid.UUID(claims["jti"])
    except (jwt.PyJWTError, ValueError):
        raise _unauthorized("Invalid or expired token")

    if await session.get(RevokedToken, jti) is not None:
        raise _unauthorized("Token has been revoked")

    # The user (and their clearance) is always re-read from the database: the clearance
    # claim in the JWT is informational and could be stale after an admin changes it.
    user = await session.get(User, user_id)
    if user is None or not user.active:
        raise _unauthorized("Account is inactive or no longer exists")

    return AuthContext(user=user, jti=jti, expires_at=datetime.fromtimestamp(claims["exp"], UTC))


AuthDep = Annotated[AuthContext, Depends(get_auth)]


async def get_current_user(auth: AuthDep) -> User:
    return auth.user


CurrentUser = Annotated[User, Depends(get_current_user)]


async def get_admin(user: CurrentUser) -> User:
    if not user.is_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Administrator privileges required")
    return user


AdminUser = Annotated[User, Depends(get_admin)]
