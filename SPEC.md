# Tech Stack
Language: Python
Framework: Fast API (async native & built-in API docs.)
File Storage: S3 (Localstack)
Database: Postgres
Local Runtime: Docker & Docker Compose with Postgres, Adminer, and Localstack services

## Functional Requirements
 - A User should never be able to access a note that requires a higher clearance level than the user has; even if the file has been shared with them. Return a 403 if this happens
    - Unclassified is the lowest level of clearance and Top Secret is the highest level of clearance.
 - Every note has to have at least 1 Owner.
    - The original author of a note is automatically assigned as an Owner when the file is generated.
 - Viewers can only list and view notes. Editors can list, view and update the contents of notes. Owners can list, view and update the contents of notes as well as change the Clearance classification, Location, file name and all other changes the notes metadata.

## Non-Functional Requirements
 - When a user logins to the `/login` endpoint using their email and password a JWT is returned containing their user Id, and clearance level
 - The entiere app should be able to spin up locally using Docker Compose and Localstack
 - Include an Adminer service in the local docker compose stack for easy access to the database during development
 - Include a Bruno collection in the `/bruno` folder showing how each of the endpoints works.
 - Leverage FastAPI's automatic API documentation to document the API endpoints.
 - The actual notes should be written to S3 while their metadata is written to the Postgres Database
 - When a User searches for or tries to fetch a file it's metadata should be looked up first and permissions/security checks performed before the note is retrieved from S3 and sent to the user. This ensures no information is leaked

## REST Endpoints

### Auth
POST /login
POST /logout

### User Management & RBAC
POST /users (Create User)
PATCH /users (Update User)
POST /reset-password (Reset password)


### Notes Management
POST /notes (Create a new note)
GET /notes (Lists all notes the logged in user has permission to)
GET /notes/<note-id> (Fetch the note with the specified ID)
PUT /notes/<note-id> (Update contents of a note)
DELETE /notes/<note-id> (delete specific note)
PUT /notes/<note-id>/metadata (Update Notes Sharing, Classification, Location, Filename etc.)


## Database Schema

```sql
CREATE TYPE clearance_level as ENUM ('UNCLASSIFIED', 'CONFIDENTIAL', 'SECRET', 'TOP SECRET');
CREATE TYPE role as ENUM ('owner', 'editor', 'viewer')
CREATE TYPE audit_event as ENUM('File Created', 'File Deleted', 'File Viewed', 'File Moved', 'File Content Modified', 'File Shared', 'User Logged In', 'User Logged Out', 'File Sharing Revoked')
```

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    active BOOLEAN DEFAULT 1,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    clearance clearance_level DEFAULT 'UNCLASSIFIED',
    created_at TIMESTAMPTZ DEFAULT now()
);
```

```sql
CREATE TABLE notes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    filename TEXT NOT NULL,
    location TEXT NOT NULL,
    classification clearance_level DEFAULT 'UNCLASSIFIED',
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by UUID REFERENCES users(id),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT constraint_name UNIQUE (location, filename)
);
```

```sql
CREATE TABLE note_permissions (
    note_id UUID REFERENCES notes(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role note_role NOT NULL
    granted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now()
)

CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event audit_event NOT NULL,
    user_id UUID REFERENCES users(id),
    note_id UUID REFERENCES notes(id),
    occured_at TIMESTAMPTZ NOT NULL default now()
);
