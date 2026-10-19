import logging
from contextlib import AsyncExitStack

import aioboto3
from botocore.exceptions import ClientError
from fastapi import Request

from app.config import Settings

log = logging.getLogger(__name__)


class NoteNotInStorage(Exception):
  pass


class NoteStorage:
  """Note bodies in S3. Callers must authorize against Postgres metadata before using this."""

  def __init__(self, settings: Settings) -> None:
    self._settings = settings
    self._bucket = settings.s3_bucket
    self._stack = AsyncExitStack()
    self._client = None

  async def start(self) -> None:
    session = aioboto3.Session()
    self._client = await self._stack.enter_async_context(
      session.client(
        "s3",
        endpoint_url=self._settings.s3_endpoint_url,
        region_name=self._settings.aws_region,
        aws_access_key_id=self._settings.aws_access_key_id,
        aws_secret_access_key=self._settings.aws_secret_access_key,
      )
    )
    await self._ensure_bucket()

  async def stop(self) -> None:
    await self._stack.aclose()

  async def _ensure_bucket(self) -> None:
    try:
      await self._client.head_bucket(Bucket=self._bucket)
    except ClientError:
      log.info("Creating bucket %s", self._bucket)
      await self._client.create_bucket(Bucket=self._bucket)
    await self._client.put_public_access_block(
      Bucket=self._bucket,
      PublicAccessBlockConfiguration={
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
      },
    )

  async def put(self, key: str, content: str) -> None:
    await self._client.put_object(
      Bucket=self._bucket,
      Key=key,
      Body=content.encode(),
      ContentType="text/plain; charset=utf-8",
      ServerSideEncryption="AES256",
    )

  async def get(self, key: str) -> str:
    try:
      response = await self._client.get_object(Bucket=self._bucket, Key=key)
    except ClientError as exc:
      if exc.response["Error"]["Code"] in ("NoSuchKey", "404"):
        raise NoteNotInStorage(key) from exc
      raise
    async with response["Body"] as body:
      return (await body.read()).decode()

  async def copy(self, source_key: str, dest_key: str) -> None:
    await self._client.copy_object(
      Bucket=self._bucket,
      Key=dest_key,
      CopySource={"Bucket": self._bucket, "Key": source_key},
      ServerSideEncryption="AES256",
    )

  async def delete(self, key: str) -> None:
    await self._client.delete_object(Bucket=self._bucket, Key=key)

  async def delete_quietly(self, key: str) -> None:
    """Best-effort cleanup; an orphaned object is preferable to failing a committed request."""
    try:
      await self.delete(key)
    except Exception:
      log.exception("Failed to delete S3 object %s; it is now orphaned", key)


def get_storage(request: Request) -> NoteStorage:
  return request.app.state.storage
