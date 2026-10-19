import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditEvent, AuditLog


def record(
  session: AsyncSession,
  event: AuditEvent,
  user_id: uuid.UUID | None,
  note_id: uuid.UUID | None = None,
  **details,
) -> None:
  """Stage an audit entry; it commits (or rolls back) with the caller's transaction."""
  session.add(AuditLog(event=event, user_id=user_id, note_id=note_id, details=details))
