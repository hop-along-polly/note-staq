import re
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

from app.models import Clearance, NoteRole

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_MAX_S3_KEY_BYTES = 1024


def _validate_segment(segment: str, what: str) -> str:
  if segment in ("", ".", ".."):
    raise ValueError(f"{what} segment {segment!r} is not allowed")
  if "\\" in segment or _CONTROL_CHARS.search(segment):
    raise ValueError(f"{what} may not contain backslashes or control characters")
  return segment


def normalize_location(value: str) -> str:
  """'/projects/alpha/' -> 'projects/alpha'; '' or '/' -> '' (root)."""
  value = value.strip().strip("/")
  if not value:
    return ""
  return "/".join(_validate_segment(s, "location") for s in value.split("/"))


def normalize_filename(value: str) -> str:
  value = value.strip()
  if "/" in value:
    raise ValueError("filename may not contain '/'; use location for folders")
  if len(value) > 255:
    raise ValueError("filename may be at most 255 characters")
  return _validate_segment(value, "filename")


def check_key_length(location: str, filename: str) -> None:
  key = f"{location}/{filename}" if location else filename
  if len(key.encode()) > _MAX_S3_KEY_BYTES:
    raise ValueError(f"location + filename may be at most {_MAX_S3_KEY_BYTES} bytes")


# Auth


class LoginRequest(BaseModel):
  email: EmailStr
  password: str


class TokenResponse(BaseModel):
  access_token: str
  token_type: str = "bearer"
  expires_at: datetime
  user_id: uuid.UUID
  clearance: Clearance


# Users


class UserCreate(BaseModel):
  email: EmailStr
  password: str = Field(min_length=12, max_length=256)
  first_name: str = Field(min_length=1, max_length=100)
  last_name: str = Field(min_length=1, max_length=100)
  clearance: Clearance = Clearance.UNCLASSIFIED
  is_admin: bool = False


class UserUpdate(BaseModel):
  user_id: uuid.UUID | None = Field(
    default=None, description="User to update. Omit to update yourself. Updating others requires admin."
  )
  first_name: str | None = Field(default=None, min_length=1, max_length=100)
  last_name: str | None = Field(default=None, min_length=1, max_length=100)
  email: EmailStr | None = Field(default=None, description="Admin only.")
  clearance: Clearance | None = Field(default=None, description="Admin only.")
  active: bool | None = Field(default=None, description="Admin only.")
  is_admin: bool | None = Field(default=None, description="Admin only.")


class PasswordReset(BaseModel):
  user_id: uuid.UUID | None = Field(
    default=None, description="Admin only: reset another user's password. Omit to change your own."
  )
  current_password: str | None = Field(default=None, description="Required when changing your own password.")
  new_password: str = Field(min_length=12, max_length=256)


class UserOut(BaseModel):
  model_config = ConfigDict(from_attributes=True)

  id: uuid.UUID
  email: str
  first_name: str
  last_name: str
  clearance: Clearance
  active: bool
  is_admin: bool
  created_at: datetime


# Notes


class NoteCreate(BaseModel):
  filename: str = Field(examples=["mission-brief.md"])
  location: str = Field(default="", description="Folder path, e.g. 'projects/alpha'. Empty = root.")
  classification: Clearance = Clearance.UNCLASSIFIED
  content: str = ""

  @field_validator("filename")
  @classmethod
  def _filename(cls, v: str) -> str:
    return normalize_filename(v)

  @field_validator("location")
  @classmethod
  def _location(cls, v: str) -> str:
    return normalize_location(v)

  @model_validator(mode="after")
  def _key_length(self) -> "NoteCreate":
    check_key_length(self.location, self.filename)
    return self


class NoteContentUpdate(BaseModel):
  content: str


class UserRef(BaseModel):
  """Identify a user by id or email."""

  user_id: uuid.UUID | None = None
  email: EmailStr | None = None

  @model_validator(mode="after")
  def _exactly_one(self) -> "UserRef":
    if (self.user_id is None) == (self.email is None):
      raise ValueError("provide exactly one of user_id or email")
    return self


class PermissionGrant(UserRef):
  role: NoteRole


class NoteMetadataUpdate(BaseModel):
  """Owner-only changes. Every field is optional; only what you send is changed."""

  filename: str | None = None
  location: str | None = None
  classification: Clearance | None = None
  grant: list[PermissionGrant] = Field(
    default_factory=list, description="Add users or change their role (owner, editor, viewer)."
  )
  revoke: list[UserRef] = Field(default_factory=list, description="Remove users' access.")

  @field_validator("filename")
  @classmethod
  def _filename(cls, v: str | None) -> str | None:
    return None if v is None else normalize_filename(v)

  @field_validator("location")
  @classmethod
  def _location(cls, v: str | None) -> str | None:
    return None if v is None else normalize_location(v)


class PermissionOut(BaseModel):
  user_id: uuid.UUID
  email: str
  first_name: str
  last_name: str
  role: NoteRole
  granted_by: uuid.UUID | None
  granted_at: datetime


class NoteSummary(BaseModel):
  id: uuid.UUID
  filename: str
  location: str
  classification: Clearance
  role: NoteRole | None = Field(description="Your role on this note (null if you just revoked your own access).")
  created_by: uuid.UUID | None
  created_at: datetime
  updated_by: uuid.UUID | None
  updated_at: datetime


class NoteMetadata(NoteSummary):
  permissions: list[PermissionOut]


class NoteDetail(NoteMetadata):
  content: str
