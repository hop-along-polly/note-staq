from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
  model_config = SettingsConfigDict(env_file=".env", extra="ignore")

  database_url: str = "postgresql+asyncpg://notestaq:notestaq@localhost:5432/notestaq"

  s3_endpoint_url: str | None = "http://localhost:4566"
  s3_bucket: str = "notestaq-notes"
  aws_region: str = "us-east-1"
  aws_access_key_id: str = "test"
  aws_secret_access_key: str = "test"

  jwt_secret: str = "change-me-in-production-this-is-only-for-local-dev"
  jwt_algorithm: str = "HS256"
  jwt_ttl_minutes: int = 60

  # Seeded on startup when the users table is empty, so there is someone to create users.
  bootstrap_admin_email: str = "admin@example.com"
  bootstrap_admin_password: str = "note-staq-pw"

  max_note_bytes: int = 1_000_000


@lru_cache
def get_settings() -> Settings:
  return Settings()
