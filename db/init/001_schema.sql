-- Note Staq schema. Runs automatically on first start of the Postgres container
-- (mounted into /docker-entrypoint-initdb.d).

-- ---------------------------- Types ---------------------------- 

-- Declaration order matters: Postgres compares enum values in this order,
-- so UNCLASSIFIED < CONFIDENTIAL < SECRET < TOP SECRET.
CREATE TYPE clearance_level AS ENUM ('UNCLASSIFIED', 'CONFIDENTIAL', 'SECRET', 'TOP SECRET');

CREATE TYPE note_role AS ENUM ('owner', 'editor', 'viewer');

CREATE TYPE audit_event AS ENUM (
    'File Created',
    'File Deleted',
    'File Viewed',
    'File Moved',
    'File Content Modified',
    'File Shared',
    'File Sharing Revoked',
    'File Reclassified',
    'User Logged In',
    'User Logged Out'
);

-- ---------------------------- Tables ----------------------------

CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    active        BOOLEAN NOT NULL DEFAULT TRUE,
    is_admin      BOOLEAN NOT NULL DEFAULT FALSE,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    first_name    TEXT NOT NULL,
    last_name     TEXT NOT NULL,
    clearance     clearance_level NOT NULL DEFAULT 'UNCLASSIFIED',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Metadata only. The note body lives in S3 at key "<location>/<filename>"
-- (or just "<filename>" when location is the root, '').
CREATE TABLE notes (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    filename       TEXT NOT NULL,
    location       TEXT NOT NULL DEFAULT '',
    classification clearance_level NOT NULL DEFAULT 'UNCLASSIFIED',
    created_by     UUID REFERENCES users(id),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by     UUID REFERENCES users(id),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT notes_location_filename_key UNIQUE (location, filename)
);
CREATE INDEX notes_location_idx ON notes (location text_pattern_ops);

CREATE TABLE note_permissions (
    note_id    UUID NOT NULL REFERENCES notes(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       note_role NOT NULL,
    granted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (note_id, user_id)
);
CREATE INDEX note_permissions_user_idx ON note_permissions (user_id);

-- note_id intentionally has no FK: audit history must outlive deleted notes.
CREATE TABLE audit_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event       audit_event NOT NULL,
    user_id     UUID REFERENCES users(id),
    note_id     UUID,
    details     JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_note_idx ON audit_log (note_id, occurred_at);
CREATE INDEX audit_log_user_idx ON audit_log (user_id, occurred_at);

-- JWT IDs invalidated by POST /logout. Rows can be purged once expires_at passes.
CREATE TABLE revoked_tokens (
    jti        UUID PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

-- ---------------------------- Integrity triggers ----------------------------
-- The API checks all of these first and returns friendly errors; the triggers are
-- a backstop so no code path (or hand-written SQL) can break the security model.
--   CL001 = clearance violation, CL002 = note would be left without an owner.

-- Nobody can be granted any role on a note above their clearance.
CREATE FUNCTION note_permissions_clearance_check() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    v_classification clearance_level;
    v_clearance      clearance_level;
    v_email          TEXT;
BEGIN
    SELECT classification INTO v_classification FROM notes WHERE id = NEW.note_id;
    SELECT clearance, email INTO v_clearance, v_email FROM users WHERE id = NEW.user_id;
    IF v_clearance < v_classification THEN
        RAISE EXCEPTION 'User % does not have clearance for this note (requires %, holds %)',
              v_email, v_classification, v_clearance
              USING ERRCODE = 'CL001';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER note_permissions_clearance
    BEFORE INSERT OR UPDATE ON note_permissions
    FOR EACH ROW EXECUTE FUNCTION note_permissions_clearance_check();

-- Reclassifying a note removes access for everyone not cleared for the new level, so a
-- note never stays readable below its classification and access doesn't silently return
-- if the note is later lowered again. (The API does this first and audits each removal.)
CREATE FUNCTION notes_reclassify_revoke() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM note_permissions p
    USING users u
    WHERE u.id = p.user_id
      AND p.note_id = NEW.id
      AND u.clearance < NEW.classification;
    RETURN NULL;
END $$;

CREATE TRIGGER notes_reclassify
    AFTER UPDATE OF classification ON notes
    FOR EACH ROW
    WHEN (NEW.classification IS DISTINCT FROM OLD.classification)
    EXECUTE FUNCTION notes_reclassify_revoke();

-- Every note must have at least one owner. Deferred to COMMIT so a note and its
-- first owner can be inserted in one transaction, and owners can be swapped.
CREATE FUNCTION notes_require_owner_check() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    v_note_id UUID;
BEGIN
    IF TG_TABLE_NAME = 'notes' THEN
        v_note_id := NEW.id;
    ELSE
        v_note_id := OLD.note_id;
    END IF;

    IF EXISTS (SELECT 1 FROM notes WHERE id = v_note_id)
       AND NOT EXISTS (SELECT 1 FROM note_permissions WHERE note_id = v_note_id AND role = 'owner') THEN
        RAISE EXCEPTION 'Note % must have at least one owner', v_note_id
              USING ERRCODE = 'CL002';
    END IF;
    RETURN NULL;
END $$;

CREATE CONSTRAINT TRIGGER notes_require_owner
    AFTER INSERT ON notes
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION notes_require_owner_check();

CREATE CONSTRAINT TRIGGER note_permissions_require_owner
    AFTER UPDATE OR DELETE ON note_permissions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION notes_require_owner_check();
