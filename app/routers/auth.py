from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import delete, select

from app import audit
from app.deps import AuthDep, SessionDep
from app.models import AuditEvent, RevokedToken, User
from app.schemas import LoginRequest, TokenResponse
from app.security import create_access_token, verify_password

router = APIRouter(tags=["Auth"])


@router.post("/login", response_model=TokenResponse, summary="Log in and receive a JWT")
async def login(body: LoginRequest, session: SessionDep) -> TokenResponse:
    """Exchange email + password for a bearer token containing the user id and clearance."""
    user = await session.scalar(select(User).where(User.email == body.email.lower()))
    if not verify_password(user.password_hash if user else None, body.password) or not user.active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")

    token, expires_at = create_access_token(user)
    audit.record(session, AuditEvent.USER_LOGGED_IN, user.id)
    await session.commit()
    return TokenResponse(access_token=token, expires_at=expires_at, user_id=user.id, clearance=user.clearance)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, summary="Revoke the current JWT")
async def logout(auth: AuthDep, session: SessionDep) -> None:
    """Revokes the token used for this request; later requests with it get 401."""
    session.add(RevokedToken(jti=auth.jti, expires_at=auth.expires_at))
    await session.execute(delete(RevokedToken).where(RevokedToken.expires_at < datetime.now(UTC)))
    audit.record(session, AuditEvent.USER_LOGGED_OUT, auth.user.id)
    await session.commit()
