import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.exc import DBAPIError

from app.config import get_settings
from app.db import SessionLocal, engine
from app.routers import auth, notes, users
from app.storage import NoteStorage

logging.basicConfig(level=logging.INFO)

DESCRIPTION = """
Note Staq is a multi-user note service with per-note sharing and clearance-based access control.

**Authentication:** call `POST /login`, then click **Authorize** and paste the `access_token`.

**Roles (per note):** `viewer` can list and read · `editor` can also change content ·
`owner` can also share, reclassify, move, rename and delete. A note always has at least one owner.

**Clearance:** `UNCLASSIFIED` < `CONFIDENTIAL` < `SECRET` < `TOP SECRET`. A user can never read a note
classified above their clearance, even if it was shared with them (403). Notes you have no access to
return 404, so their existence isn't revealed.
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    app.state.storage = NoteStorage(settings)
    await app.state.storage.start()
    async with SessionLocal() as session:
        await users.ensure_bootstrap_admin(
            session, settings.bootstrap_admin_email, settings.bootstrap_admin_password
        )
    yield
    await app.state.storage.stop()
    await engine.dispose()


app = FastAPI(title="Note Staq", version="1.0.0", description=DESCRIPTION, lifespan=lifespan)
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(notes.router)


# Backstop for the database triggers in db/init/001_schema.sql. The API checks the same rules
# first, so these fire only on races or bugs.
_TRIGGER_ERRORS = {"CL001": status.HTTP_403_FORBIDDEN, "CL002": status.HTTP_409_CONFLICT}


@app.exception_handler(DBAPIError)
async def trigger_error_handler(request: Request, exc: DBAPIError):
    sqlstate = getattr(exc.orig, "sqlstate", None) or getattr(exc.orig, "pgcode", None)
    if sqlstate in _TRIGGER_ERRORS:
        message = str(exc.orig).split("\n")[0].split(": ", 1)[-1]
        return JSONResponse({"detail": message}, status_code=_TRIGGER_ERRORS[sqlstate])
    raise exc


@app.get("/health", tags=["Health"], summary="Liveness check")
async def health() -> dict:
    return {"status": "ok"}
