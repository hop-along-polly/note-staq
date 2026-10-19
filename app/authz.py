"""Authorization for notes. Every note endpoint goes through `authorize_note`
before it touches S3, so content is never read for a user who may not see it."""

import uuid

from fastapi import HTTPException, status
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Clearance, Note, NotePermission, NoteRole, User


def clearance_denied(classification: Clearance, clearance: Clearance) -> HTTPException:
    return HTTPException(
        status.HTTP_403_FORBIDDEN,
        f"You do not have clearance for this note (requires {classification}, you hold {clearance})",
    )


async def authorize_note(
    session: AsyncSession,
    note_id: uuid.UUID,
    user: User,
    required: NoteRole,
    *,
    lock: bool = False,
) -> tuple[Note, NoteRole]:
    """Load a note and the caller's role on it, or raise.

    - No note, or no grant for this user -> 404 (doesn't reveal that the note exists).
    - Grant exists but clearance is too low -> 403, even for owners.
    - Grant exists but role is too low -> 403.
    """
    query = (
        select(Note, NotePermission.role)
        .outerjoin(NotePermission, and_(NotePermission.note_id == Note.id, NotePermission.user_id == user.id))
        .where(Note.id == note_id)
    )
    if lock:
        query = query.with_for_update(of=Note)
    row = (await session.execute(query)).one_or_none()

    if row is None or row.role is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Note not found")
    note, role = row.tuple()

    if not user.clearance.covers(note.classification):
        raise clearance_denied(note.classification, user.clearance)
    if not role.allows(required):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, f"This action requires the {required} role; you are a {role}"
        )
    return note, role
