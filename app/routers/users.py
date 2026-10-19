from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import AdminUser, CurrentUser, SessionDep
from app.models import Clearance, User
from app.schemas import PasswordReset, UserCreate, UserOut, UserUpdate
from app.security import hash_password, verify_password

router = APIRouter(tags=["Users"])

_ADMIN_ONLY_FIELDS = {"email", "clearance", "active", "is_admin"}


async def _commit_or_conflict(session: SessionDep) -> None:
    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "A user with that email already exists")


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED, summary="Create a user (admin)")
async def create_user(body: UserCreate, session: SessionDep, admin: AdminUser) -> User:
    """Admins create accounts and assign clearance. Users can't self-register,
    since that would let anyone pick their own clearance."""
    user = User(
        email=body.email.lower(),
        password_hash=hash_password(body.password),
        first_name=body.first_name,
        last_name=body.last_name,
        clearance=body.clearance,
        is_admin=body.is_admin,
    )
    session.add(user)
    await _commit_or_conflict(session)
    await session.refresh(user)
    return user


@router.patch("/users", response_model=UserOut, summary="Update a user")
async def update_user(body: UserUpdate, session: SessionDep, current: CurrentUser) -> User:
    """Without `user_id`, updates yourself. Anyone can change their own name;
    email, clearance, active and is_admin, and any change to another user, require admin.
    Nobody can change their own clearance, admins included: another admin must do it."""
    changes = body.model_dump(exclude_unset=True, exclude={"user_id"})
    target_id = body.user_id or current.id
    editing_self = target_id == current.id

    if not current.is_admin and (not editing_self or _ADMIN_ONLY_FIELDS & changes.keys()):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Administrator privileges required")
    if editing_self and (changes.get("active") is False or changes.get("is_admin") is False):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Admins can't deactivate or demote themselves")
    # Two-person rule: a clearance change always needs a second admin, so nobody can raise their own.
    if editing_self and "clearance" in changes:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "You can't change your own clearance; another administrator must do it"
        )

    user = await session.get(User, target_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    if "email" in changes:
        changes["email"] = changes["email"].lower()
    for field, value in changes.items():
        if value is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"{field} can't be null")
        setattr(user, field, value)

    await _commit_or_conflict(session)
    return user


@router.post("/reset-password", status_code=status.HTTP_204_NO_CONTENT, summary="Change or reset a password")
async def reset_password(body: PasswordReset, session: SessionDep, current: CurrentUser) -> None:
    """Change your own password (requires `current_password`), or as an admin
    set a new password for another user with `user_id`."""
    if body.user_id is None or body.user_id == current.id:
        if not body.current_password or not verify_password(current.password_hash, body.current_password):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Current password is incorrect")
        user = current
    else:
        if not current.is_admin:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Administrator privileges required")
        user = await session.get(User, body.user_id)
        if user is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    user.password_hash = hash_password(body.new_password)
    await session.commit()


async def ensure_bootstrap_admin(session: AsyncSession, email: str, password: str) -> None:
    """Seed one admin when the database is empty, so someone can create the first users."""
    if await session.scalar(select(User.id).limit(1)) is not None:
        return
    session.add(
        User(
            email=email.lower(),
            password_hash=hash_password(password),
            first_name="System",
            last_name="Administrator",
            clearance=Clearance.TOP_SECRET,
            is_admin=True,
        )
    )
    await session.commit()
