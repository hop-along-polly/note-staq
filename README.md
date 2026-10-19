# Note Staq

## Write-up

The design choices I spent the most time on all related to the data security model used by the application. The 2 choices that took the most consideration were
 1. Granting user permissions at the Note level instead of implementing a traditional RBAC system. 
 2. Adding in the `clearance_level` TYPE in Postgres and adding columns to the `users` and `notes` tables to ensure users could not access notes they don't have clearance for.

I wanted the application to be secure by default and hard for unintentional data breaches to occur when sharing notes. Originally I thought about using RBAC but I didn't like that an admin could go into any teams folders and notes and make changes. I wanted that to be a very explicitly granted permission.

If I had more time I would like to update the data security model to allow for a clearance level to be set on an entire folder and not individual notes. I would also like to support custom roles/groups so teams could create team specific folders and keep information private without trying to work in the confines of the clearance system.


## Quick start

```bash
docker compose up -d --build
```

| Service    | URL                        | Notes                                                                |
|------------|----------------------------|----------------------------------------------------------------------|
| API        | http://localhost:8000      |                                                                      |
| API docs   | http://localhost:8000/docs | Click **Authorize** and paste the `access_token` from `/login`.      |
| Adminer    | http://localhost:8081      | System `PostgreSQL`, server `postgres`, user `notestaq`, password `notestaq-pw`, db `notestaq`. |
| Postgres   | localhost:5432             | Schema in `db/init/001_schema.sql`, applied on first start.          |
| LocalStack | http://localhost:4566      | S3 bucket `notestaq-notes`, created by the API on startup.           |

The first startup seeds an admin account, `admin@example.com` / `note-staq-pw`, which you can override with `BOOTSTRAP_ADMIN_EMAIL` / `BOOTSTRAP_ADMIN_PASSWORD`. Only admins can create users, since self-registration would let anyone choose their own clearance.

To reset all data, run `docker compose down -v`.

## Trying it out

**Bruno:** open the `bruno/` folder in Bruno, select the `Local` environment, and run the folders in order (Auth -> Users -> Notes). From the CLI:

```bash
cd bruno && bru run --env Local
```

The collection walks through the main scenarios, including sharing above clearance (403), a clearance downgrade blocking access to an already-shared note (403), and removing the last owner (409). Each run uses unique emails and paths, so it can be repeated.

**Integration tests** (against the running stack):

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest -q tests
```

## Endpoints

| Method | Path                    | Who                       | Purpose                                                       |
|--------|-------------------------|---------------------------|---------------------------------------------------------------|
| POST   | `/login`                | anyone                    | Returns a JWT with the user id (`sub`) and `clearance`        |
| POST   | `/logout`               | authenticated             | Revokes the current token                                     |
| POST   | `/users`                | admin                     | Create a user and set their clearance                         |
| PATCH  | `/users`                | self (name) / admin (all) | Update a user; `user_id` in the body, defaults to yourself    |
| POST   | `/reset-password`       | self / admin              | Change your password (`current_password`) or reset another user's (admin, `user_id`) |
| POST   | `/notes`                | authenticated             | Create a note; the author becomes its first owner             |
| GET    | `/notes`                | viewer+                   | List accessible notes; filters `location`, `recursive`, `q`, `limit`, `offset` |
| GET    | `/notes/{id}`           | viewer+                   | Metadata, permissions and content                             |
| PUT    | `/notes/{id}`           | editor+                   | Replace the content; optional `If-Match` for optimistic locking |
| DELETE | `/notes/{id}`           | owner                     | Delete the metadata and the S3 object                         |
| PUT    | `/notes/{id}/metadata`  | owner                     | Any of: `filename`, `location`, `classification`, `grant[]`, `revoke[]` |

## Security model

- **Order of checks.** Every note request loads the metadata from Postgres and authorizes it (`app/authz.py`) before anything is read from S3. A note you have no role on returns **404**, so its existence isn't revealed. A note you have a role on but aren't cleared for returns **403**.
- **Clearance is never trusted from the JWT.** The token carries `clearance` as the spec requires, but each request re-reads the user from the database. A downgrade or deactivation therefore takes effect immediately, and logout revokes the token's `jti`.
- **Clearance changes need two people.** Only admins can change clearance, and nobody can change their own, admins included, so raising a clearance always needs a second admin.
- **Listings hide notes above your clearance**, even ones shared with you, because a filename can itself be sensitive.
- **Reclassifying removes access for anyone not cleared for the new level**, in the same transaction, and logs each removal as `File Sharing Revoked`. The note is never readable below its classification, and lowering it again doesn't silently restore anyone's access.
- **The database enforces the rules too.** Triggers in `001_schema.sql` reject granting any role to an uncleared user and leaving a note with no owner, and remove uncleared users' access when a note is reclassified. The API checks the same rules first and returns friendly errors; the triggers catch races and hand-written SQL.
- **Audit log.** Every create, view, edit, move, reclassify, share, revoke, delete, login and logout is written to `audit_log` in the same transaction as the change.
- **S3.** The bucket blocks public access and objects are encrypted at rest (SSE-S3). Clients never get direct S3 access; content goes through the API only.


## Project layout

```
app/
  main.py         FastAPI app, lifespan (S3 client, bootstrap admin), DB trigger error mapping
  authz.py        Single note authorization path (role + clearance)
  routers/        auth.py, users.py, notes.py
  models.py       SQLAlchemy models + Clearance / NoteRole ordering
  schemas.py      Request/response models, path validation
  storage.py      S3 access (LocalStack locally)
  security.py     Argon2 password hashing, JWT
db/init/          Postgres schema + triggers
bruno/            Bruno collection
tests/            Integration tests
```
