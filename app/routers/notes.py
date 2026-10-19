import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Query, Response, status
from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError

from app import audit
from app.authz import authorize_note, clearance_denied
from app.config import get_settings
from app.deps import CurrentUser, SessionDep, StorageDep
from app.models import AuditEvent, Note, NotePermission, NoteRole, User
from app.schemas import (
    NoteContentUpdate,
    NoteCreate,
    NoteDetail,
    NoteMetadata,
    NoteMetadataUpdate,
    NoteSummary,
    PermissionOut,
    UserRef,
    check_key_length,
    normalize_location,
)
from app.storage import NoteNotInStorage

router = APIRouter(prefix="/notes", tags=["Notes"])


# Helpers


def _etag(note: Note) -> str:
    return f'"{int(note.updated_at.timestamp() * 1_000_000)}"'


def _check_size(content: str) -> None:
    limit = get_settings().max_note_bytes
    if len(content.encode()) > limit:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, f"Note content exceeds {limit} bytes")


def _summary(note: Note, role: NoteRole) -> dict:
    return {
        "id": note.id,
        "filename": note.filename,
        "location": note.location,
        "classification": note.classification,
        "role": role,
        "created_by": note.created_by,
        "created_at": note.created_at,
        "updated_by": note.updated_by,
        "updated_at": note.updated_at,
    }


async def _permissions(session: SessionDep, note_id: uuid.UUID) -> list[PermissionOut]:
    rows = await session.execute(
        select(NotePermission, User)
        .join(User, User.id == NotePermission.user_id)
        .where(NotePermission.note_id == note_id)
        .order_by(NotePermission.granted_at)
    )
    return [
        PermissionOut(
            user_id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            role=perm.role,
            granted_by=perm.granted_by,
            granted_at=perm.granted_at,
        )
        for perm, user in rows.tuples()
    ]


async def _metadata(session: SessionDep, note: Note, role: NoteRole | None) -> NoteMetadata:
    return NoteMetadata(**_summary(note, role), permissions=await _permissions(session, note.id))


async def _resolve_user(session: SessionDep, ref: UserRef) -> User:
    if ref.user_id is not None:
        user = await session.get(User, ref.user_id)
    else:
        user = await session.scalar(select(User).where(User.email == ref.email.lower()))
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"User not found: {ref.user_id or ref.email}")
    return user


def _key_conflict(location: str, filename: str) -> HTTPException:
    key = f"{location}/{filename}" if location else filename
    return HTTPException(status.HTTP_409_CONFLICT, f"A note already exists at '{key}'")


# Endpoints


@router.post("", response_model=NoteMetadata, status_code=status.HTTP_201_CREATED, summary="Create a note")
async def create_note(
    body: NoteCreate, session: SessionDep, storage: StorageDep, user: CurrentUser, response: Response
) -> NoteMetadata:
    """Creates the note's metadata and writes its content to S3. The author becomes its first owner.
    You can't create a note classified above your own clearance."""
    _check_size(body.content)
    if not user.clearance.covers(body.classification):
        raise clearance_denied(body.classification, user.clearance)

    note = Note(
        filename=body.filename,
        location=body.location,
        classification=body.classification,
        created_by=user.id,
        updated_by=user.id,
    )
    session.add(note)
    try:
        await session.flush()
    except IntegrityError:
        await session.rollback()
        raise _key_conflict(body.location, body.filename)

    session.add(NotePermission(note_id=note.id, user_id=user.id, role=NoteRole.OWNER, granted_by=user.id))
    audit.record(
        session, AuditEvent.FILE_CREATED, user.id, note.id, key=note.s3_key, classification=note.classification
    )
    await session.flush()

    await storage.put(note.s3_key, body.content)
    try:
        await session.commit()
    except Exception:
        await storage.delete_quietly(note.s3_key)
        raise

    response.headers["Location"] = f"/notes/{note.id}"
    response.headers["ETag"] = _etag(note)
    return await _metadata(session, note, NoteRole.OWNER)


@router.get("", response_model=list[NoteSummary], summary="List notes you can access")
async def list_notes(
    session: SessionDep,
    user: CurrentUser,
    location: Annotated[str | None, Query(description="Only notes in this folder, e.g. 'projects/alpha'.")] = None,
    recursive: Annotated[bool, Query(description="With `location`, include subfolders.")] = False,
    q: Annotated[str | None, Query(description="Case-insensitive filename search.")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[NoteSummary]:
    """Searches metadata only. Notes above your clearance are never returned, even if shared with you."""
    query = (
        select(Note, NotePermission.role)
        .join(NotePermission, and_(NotePermission.note_id == Note.id, NotePermission.user_id == user.id))
        .where(Note.classification.in_(user.clearance.levels_covered()))
    )
    if location is not None:
        try:
            folder = normalize_location(location)
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))
        if not recursive:
            query = query.where(Note.location == folder)
        elif folder:
            query = query.where(or_(Note.location == folder, Note.location.startswith(f"{folder}/", autoescape=True)))
    if q:
        query = query.where(Note.filename.icontains(q, autoescape=True))

    rows = await session.execute(query.order_by(Note.location, Note.filename).limit(limit).offset(offset))
    return [NoteSummary(**_summary(note, role)) for note, role in rows.tuples()]


@router.get("/{note_id}", response_model=NoteDetail, summary="Fetch a note and its content")
async def get_note(
    note_id: uuid.UUID, session: SessionDep, storage: StorageDep, user: CurrentUser, response: Response
) -> NoteDetail:
    """Permissions and clearance are checked against the metadata before the content is read from S3.
    Returns 403 if the note was shared with you but is above your clearance."""
    note, role = await authorize_note(session, note_id, user, NoteRole.VIEWER)
    try:
        content = await storage.get(note.s3_key)
    except NoteNotInStorage:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Note content is missing from storage")

    audit.record(session, AuditEvent.FILE_VIEWED, user.id, note.id)
    await session.commit()

    response.headers["ETag"] = _etag(note)
    return NoteDetail(**_summary(note, role), permissions=await _permissions(session, note.id), content=content)


@router.put("/{note_id}", response_model=NoteMetadata, summary="Update a note's content (editor or owner)")
async def update_note_content(
    note_id: uuid.UUID,
    body: NoteContentUpdate,
    session: SessionDep,
    storage: StorageDep,
    user: CurrentUser,
    response: Response,
    if_match: Annotated[
        str | None, Header(description="ETag from a previous GET; rejects the write if someone saved since.")
    ] = None,
) -> NoteMetadata:
    _check_size(body.content)
    note, role = await authorize_note(session, note_id, user, NoteRole.EDITOR, lock=True)
    if if_match is not None and if_match != _etag(note):
        raise HTTPException(
            status.HTTP_412_PRECONDITION_FAILED, "The note was modified since you loaded it; reload and retry"
        )

    await storage.put(note.s3_key, body.content)
    note.updated_by = user.id
    note.updated_at = datetime.now(UTC)
    audit.record(session, AuditEvent.FILE_CONTENT_MODIFIED, user.id, note.id)
    await session.commit()

    response.headers["ETag"] = _etag(note)
    return await _metadata(session, note, role)


@router.delete("/{note_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a note (owner)")
async def delete_note(note_id: uuid.UUID, session: SessionDep, storage: StorageDep, user: CurrentUser) -> None:
    note, _ = await authorize_note(session, note_id, user, NoteRole.OWNER, lock=True)
    key = note.s3_key
    await session.delete(note)
    audit.record(session, AuditEvent.FILE_DELETED, user.id, note_id, key=key)
    await session.commit()
    await storage.delete_quietly(key)


@router.put(
    "/{note_id}/metadata",
    response_model=NoteMetadata,
    summary="Update sharing, classification, location or filename (owner)",
)
async def update_note_metadata(
    note_id: uuid.UUID,
    body: NoteMetadataUpdate,
    session: SessionDep,
    storage: StorageDep,
    user: CurrentUser,
    response: Response,
) -> NoteMetadata:
    """Only the fields you send are changed. Rules:

    - Every grantee must hold clearance for the note's (new) classification -> otherwise 403.
    - Reclassifying removes access for every user not cleared for the new level (logged as
      'File Sharing Revoked'), so a note never stays readable below its classification and
      access doesn't silently return if it is later lowered again.
    - You can't classify a note above your own clearance -> 403.
    - The note must keep at least one owner -> otherwise 409.
    - Moving or renaming onto an existing note's location and filename -> 409.
    """
    note, role = await authorize_note(session, note_id, user, NoteRole.OWNER, lock=True)

    grants = {}
    for grant in body.grant:
        grantee = await _resolve_user(session, grant)
        if not grantee.active:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"User {grantee.email} is inactive")
        grants[grantee.id] = (grantee, grant.role)
    revokes = {u.id: u for u in [await _resolve_user(session, ref) for ref in body.revoke]}
    if grants.keys() & revokes.keys():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "A user can't be both granted and revoked")

    rows = await session.execute(
        select(NotePermission, User).join(User, User.id == NotePermission.user_id).where(NotePermission.note_id == note.id)
    )
    current = {perm.user_id: (perm, holder) for perm, holder in rows.tuples()}

    old_classification = note.classification
    new_classification = body.classification or old_classification
    if not user.clearance.covers(new_classification):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, f"You can't classify a note above your own clearance ({user.clearance})"
        )

    final = {uid: (holder, perm.role) for uid, (perm, holder) in current.items() if uid not in revokes}
    final.update(grants)

    for grantee, _ in grants.values():
        if not grantee.clearance.covers(new_classification):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"User {grantee.email} does not have clearance for this note "
                f"(requires {new_classification}, holds {grantee.clearance})",
            )
    uncleared = {}
    if new_classification != old_classification:
        uncleared = {uid: h for uid, (h, _) in final.items() if not h.clearance.covers(new_classification)}
        for uid in uncleared:
            del final[uid]
    if not any(r == NoteRole.OWNER for _, r in final.values()):
        raise HTTPException(status.HTTP_409_CONFLICT, "A note must keep at least one owner")

    # Flush in this order so the database triggers see a consistent state:
    # revoke -> reclassify -> grant -> move.
    for uid, revoked in revokes.items():
        if uid in current:
            await session.delete(current[uid][0])
            audit.record(session, AuditEvent.FILE_SHARING_REVOKED, user.id, note.id, target=revoked.email)
    for uid, holder in uncleared.items():
        await session.delete(current[uid][0])
        audit.record(
            session,
            AuditEvent.FILE_SHARING_REVOKED,
            user.id,
            note.id,
            target=holder.email,
            reason=f"insufficient clearance for {new_classification}",
        )
    await session.flush()

    if new_classification != old_classification:
        note.classification = new_classification
        audit.record(
            session, AuditEvent.FILE_RECLASSIFIED, user.id, note.id, old=old_classification, new=new_classification
        )
        await session.flush()

    now = datetime.now(UTC)
    for uid, (grantee, new_role) in grants.items():
        existing = current.get(uid)
        if existing and existing[0].role == new_role:
            continue
        if existing:
            existing[0].role, existing[0].granted_by, existing[0].granted_at = new_role, user.id, now
        else:
            session.add(NotePermission(note_id=note.id, user_id=uid, role=new_role, granted_by=user.id))
        audit.record(session, AuditEvent.FILE_SHARED, user.id, note.id, target=grantee.email, role=new_role)
    await session.flush()

    old_key = note.s3_key
    new_location = body.location if body.location is not None else note.location
    new_filename = body.filename if body.filename is not None else note.filename
    moved = (new_location, new_filename) != (note.location, note.filename)
    if moved:
        try:
            check_key_length(new_location, new_filename)
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))
        note.location, note.filename = new_location, new_filename
        audit.record(session, AuditEvent.FILE_MOVED, user.id, note.id, old=old_key, new=note.s3_key)

    note.updated_by = user.id
    note.updated_at = now
    try:
        await session.flush()
    except IntegrityError:
        await session.rollback()
        raise _key_conflict(new_location, new_filename)

    # S3 has no rename: copy to the new key, commit, then remove the old key.
    if moved:
        await storage.copy(old_key, note.s3_key)
    try:
        await session.commit()
    except Exception:
        if moved:
            await storage.delete_quietly(note.s3_key)
        raise
    if moved:
        await storage.delete_quietly(old_key)

    response.headers["ETag"] = _etag(note)
    return await _metadata(session, note, final[user.id][1] if user.id in final else None)
