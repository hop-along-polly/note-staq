import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, text
from sqlalchemy.dialects.postgresql import ENUM, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Clearance(enum.StrEnum):
  """Ordered lowest to highest, matching the clearance_level enum in Postgres."""

  UNCLASSIFIED = "UNCLASSIFIED"
  CONFIDENTIAL = "CONFIDENTIAL"
  SECRET = "SECRET"
  TOP_SECRET = "TOP SECRET"

  @property
  def rank(self) -> int:
    return list(Clearance).index(self)

  def covers(self, classification: "Clearance") -> bool:
    """True when a holder of this clearance may access a note at `classification`."""
    return self.rank >= classification.rank

  def levels_covered(self) -> list["Clearance"]:
    return [c for c in Clearance if self.covers(c)]


class NoteRole(enum.StrEnum):
  OWNER = "owner"
  EDITOR = "editor"
  VIEWER = "viewer"

  @property
  def rank(self) -> int:
    return {NoteRole.VIEWER: 1, NoteRole.EDITOR: 2, NoteRole.OWNER: 3}[self]

  def allows(self, required: "NoteRole") -> bool:
    return self.rank >= required.rank


class AuditEvent(enum.StrEnum):
  FILE_CREATED = "File Created"
  FILE_DELETED = "File Deleted"
  FILE_VIEWED = "File Viewed"
  FILE_MOVED = "File Moved"
  FILE_CONTENT_MODIFIED = "File Content Modified"
  FILE_SHARED = "File Shared"
  FILE_SHARING_REVOKED = "File Sharing Revoked"
  FILE_RECLASSIFIED = "File Reclassified"
  USER_LOGGED_IN = "User Logged In"
  USER_LOGGED_OUT = "User Logged Out"


def _pg_enum(cls: type[enum.Enum], name: str) -> ENUM:
  # The types are created by db/init/001_schema.sql; map by value, not member name.
  return ENUM(cls, name=name, create_type=False, values_callable=lambda e: [m.value for m in e])


class Base(DeclarativeBase):
  type_annotation_map = {datetime: DateTime(timezone=True)}


class User(Base):
  __tablename__ = "users"

  id: Mapped[uuid.UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
  active: Mapped[bool] = mapped_column(server_default=text("true"))
  is_admin: Mapped[bool] = mapped_column(server_default=text("false"))
  email: Mapped[str] = mapped_column(unique=True)
  password_hash: Mapped[str]
  first_name: Mapped[str]
  last_name: Mapped[str]
  clearance: Mapped[Clearance] = mapped_column(_pg_enum(Clearance, "clearance_level"))
  created_at: Mapped[datetime] = mapped_column(server_default=text("now()"))


class Note(Base):
  __tablename__ = "notes"

  id: Mapped[uuid.UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
  filename: Mapped[str]
  location: Mapped[str]
  classification: Mapped[Clearance] = mapped_column(_pg_enum(Clearance, "clearance_level"))
  created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
  created_at: Mapped[datetime] = mapped_column(server_default=text("now()"))
  updated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
  updated_at: Mapped[datetime] = mapped_column(server_default=text("now()"))

  @property
  def s3_key(self) -> str:
    return f"{self.location}/{self.filename}" if self.location else self.filename


class NotePermission(Base):
  __tablename__ = "note_permissions"

  note_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("notes.id", ondelete="CASCADE"), primary_key=True)
  user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
  role: Mapped[NoteRole] = mapped_column(_pg_enum(NoteRole, "note_role"))
  granted_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
  granted_at: Mapped[datetime] = mapped_column(server_default=text("now()"))


class AuditLog(Base):
  __tablename__ = "audit_log"

  id: Mapped[uuid.UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
  event: Mapped[AuditEvent] = mapped_column(_pg_enum(AuditEvent, "audit_event"))
  user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
  note_id: Mapped[uuid.UUID | None]
  details: Mapped[dict] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
  occurred_at: Mapped[datetime] = mapped_column(server_default=text("now()"))


class RevokedToken(Base):
  __tablename__ = "revoked_tokens"

  jti: Mapped[uuid.UUID] = mapped_column(primary_key=True)
  expires_at: Mapped[datetime]
