"""Integration tests against a running stack: `docker compose up -d`, then `pytest`."""

import os
import uuid

import httpx
import pytest

BASE_URL = os.environ.get("NOTESTAQ_URL", "http://localhost:8000")
ADMIN = ("admin@example.com", "note-staq-pw")
PASSWORD = "Correct-Horse-Battery-1"


@pytest.fixture(scope="session")
def client():
    with httpx.Client(base_url=BASE_URL, timeout=10) as c:
        yield c


def login(client, email, password=PASSWORD):
    r = client.post("/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="session")
def admin(client):
    return login(client, *ADMIN)


@pytest.fixture(scope="session")
def run_id():
    return uuid.uuid4().hex[:8]


def make_user(client, admin, run_id, name, clearance):
    email = f"{name}-{run_id}@example.com"
    r = client.post(
        "/users",
        headers=admin,
        json={"email": email, "password": PASSWORD, "first_name": name, "last_name": "Test", "clearance": clearance},
    )
    assert r.status_code == 201, r.text
    return {"id": r.json()["id"], "email": email, "headers": login(client, email)}


@pytest.fixture(scope="session")
def alice(client, admin, run_id):
    return make_user(client, admin, run_id, "alice", "TOP SECRET")


@pytest.fixture(scope="session")
def bob(client, admin, run_id):
    return make_user(client, admin, run_id, "bob", "SECRET")


@pytest.fixture(scope="session")
def carol(client, admin, run_id):
    return make_user(client, admin, run_id, "carol", "UNCLASSIFIED")


def create_note(client, owner, run_id, classification="UNCLASSIFIED", content="hello", filename=None):
    r = client.post(
        "/notes",
        headers=owner["headers"],
        json={
            "filename": filename or f"{uuid.uuid4().hex[:6]}.md",
            "location": f"tests/{run_id}",
            "classification": classification,
            "content": content,
        },
    )
    assert r.status_code == 201, r.text
    return r.json()


def share(client, owner, note, user, role):
    return client.put(
        f"/notes/{note['id']}/metadata", headers=owner["headers"], json={"grant": [{"email": user["email"], "role": role}]}
    )


# ─────────────────────────── Auth ───────────────────────────


def test_login_rejects_bad_password(client, alice):
    r = client.post("/login", json={"email": alice["email"], "password": "wrong-password-123"})
    assert r.status_code == 401


def test_jwt_contains_user_id_and_clearance(client, bob):
    import base64, json

    r = client.post("/login", json={"email": bob["email"], "password": PASSWORD})
    payload = r.json()["access_token"].split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    assert claims["sub"] == bob["id"]
    assert claims["clearance"] == "SECRET"


def test_logout_revokes_token(client, carol):
    headers = login(client, carol["email"])
    assert client.get("/notes", headers=headers).status_code == 200
    assert client.post("/logout", headers=headers).status_code == 204
    assert client.get("/notes", headers=headers).status_code == 401


def test_requires_auth(client):
    assert client.get("/notes").status_code == 401


# ─────────────────────────── Users ───────────────────────────


def test_non_admin_cannot_create_users_or_raise_own_clearance(client, carol, run_id):
    r = client.post(
        "/users",
        headers=carol["headers"],
        json={"email": f"x-{run_id}@example.com", "password": PASSWORD, "first_name": "x", "last_name": "y"},
    )
    assert r.status_code == 403
    assert client.patch("/users", headers=carol["headers"], json={"clearance": "TOP SECRET"}).status_code == 403
    r = client.patch("/users", headers=carol["headers"], json={"first_name": "Caroline"})
    assert r.status_code == 200 and r.json()["first_name"] == "Caroline"


def test_admin_cannot_change_own_clearance(client, admin, run_id):
    second_admin = make_user(client, admin, run_id, "admin2", "SECRET")
    client.patch("/users", headers=admin, json={"user_id": second_admin["id"], "is_admin": True})
    h = login(client, second_admin["email"])
    # Neither implicitly (no user_id) nor explicitly (own user_id)
    assert client.patch("/users", headers=h, json={"clearance": "TOP SECRET"}).status_code == 403
    r = client.patch("/users", headers=h, json={"user_id": second_admin["id"], "clearance": "TOP SECRET"})
    assert r.status_code == 403 and "another administrator" in r.json()["detail"]
    # A different admin can
    r = client.patch("/users", headers=admin, json={"user_id": second_admin["id"], "clearance": "TOP SECRET"})
    assert r.status_code == 200 and r.json()["clearance"] == "TOP SECRET"


def test_duplicate_email_conflicts(client, admin, alice):
    r = client.post(
        "/users",
        headers=admin,
        json={"email": alice["email"], "password": PASSWORD, "first_name": "a", "last_name": "b"},
    )
    assert r.status_code == 409


def test_reset_password(client, admin, run_id):
    user = make_user(client, admin, run_id, "dave", "UNCLASSIFIED")
    h = user["headers"]
    assert client.post("/reset-password", headers=h, json={"current_password": "nope", "new_password": "N" * 12}).status_code == 403
    assert client.post(
        "/reset-password", headers=h, json={"current_password": PASSWORD, "new_password": "Another-Strong-Pass-2"}
    ).status_code == 204
    login(client, user["email"], "Another-Strong-Pass-2")
    # Admin reset of someone else
    assert client.post(
        "/reset-password", headers=admin, json={"user_id": user["id"], "new_password": PASSWORD}
    ).status_code == 204
    login(client, user["email"])


def test_deactivated_user_is_locked_out(client, admin, run_id):
    user = make_user(client, admin, run_id, "erin", "UNCLASSIFIED")
    assert client.patch("/users", headers=admin, json={"user_id": user["id"], "active": False}).status_code == 200
    assert client.get("/notes", headers=user["headers"]).status_code == 401
    assert client.post("/login", json={"email": user["email"], "password": PASSWORD}).status_code == 401


# ─────────────────────────── Clearance ───────────────────────────


def test_cannot_create_note_above_own_clearance(client, bob, run_id):
    r = client.post(
        "/notes",
        headers=bob["headers"],
        json={"filename": "x.md", "location": f"tests/{run_id}", "classification": "TOP SECRET"},
    )
    assert r.status_code == 403


def test_cannot_share_above_recipient_clearance(client, alice, bob, run_id):
    note = create_note(client, alice, run_id, "TOP SECRET")
    r = share(client, alice, note, bob, "viewer")
    assert r.status_code == 403
    assert "does not have clearance" in r.json()["detail"]


def test_clearance_downgrade_blocks_access_even_when_shared(client, admin, alice, run_id):
    frank = make_user(client, admin, run_id, "frank", "SECRET")
    note = create_note(client, alice, run_id, "SECRET", content="classified")
    assert share(client, alice, note, frank, "viewer").status_code == 200
    assert client.get(f"/notes/{note['id']}", headers=frank["headers"]).status_code == 200

    client.patch("/users", headers=admin, json={"user_id": frank["id"], "clearance": "CONFIDENTIAL"})
    r = client.get(f"/notes/{note['id']}", headers=frank["headers"])
    assert r.status_code == 403
    assert "clearance" in r.json()["detail"]
    assert "classified" not in r.text
    # Also hidden from listings
    ids = [n["id"] for n in client.get("/notes", headers=frank["headers"]).json()]
    assert note["id"] not in ids


def test_reclassify_revokes_uncleared_users(client, alice, bob, run_id):
    note = create_note(client, alice, run_id, "SECRET")
    assert share(client, alice, note, bob, "editor").status_code == 200

    r = client.put(f"/notes/{note['id']}/metadata", headers=alice["headers"], json={"classification": "TOP SECRET"})
    assert r.status_code == 200, r.text
    assert r.json()["classification"] == "TOP SECRET"
    assert [p["email"] for p in r.json()["permissions"]] == [alice["email"]]

    # Lowering it again doesn't silently restore Bob's access
    r = client.put(f"/notes/{note['id']}/metadata", headers=alice["headers"], json={"classification": "SECRET"})
    assert [p["email"] for p in r.json()["permissions"]] == [alice["email"]]
    assert client.get(f"/notes/{note['id']}", headers=bob["headers"]).status_code == 404


def test_unshared_note_is_404(client, alice, carol, run_id):
    note = create_note(client, alice, run_id)
    assert client.get(f"/notes/{note['id']}", headers=carol["headers"]).status_code == 404


# ─────────────────────────── Roles ───────────────────────────


def test_viewer_can_read_but_not_edit(client, alice, bob, run_id):
    note = create_note(client, alice, run_id, content="v1")
    share(client, alice, note, bob, "viewer")
    r = client.get(f"/notes/{note['id']}", headers=bob["headers"])
    assert r.status_code == 200 and r.json()["content"] == "v1" and r.json()["role"] == "viewer"
    assert client.put(f"/notes/{note['id']}", headers=bob["headers"], json={"content": "x"}).status_code == 403


def test_editor_can_edit_content_but_not_metadata(client, alice, bob, run_id):
    note = create_note(client, alice, run_id, content="v1")
    share(client, alice, note, bob, "editor")
    assert client.put(f"/notes/{note['id']}", headers=bob["headers"], json={"content": "v2"}).status_code == 200
    assert client.get(f"/notes/{note['id']}", headers=alice["headers"]).json()["content"] == "v2"
    assert client.put(f"/notes/{note['id']}/metadata", headers=bob["headers"], json={"filename": "y.md"}).status_code == 403
    assert client.delete(f"/notes/{note['id']}", headers=bob["headers"]).status_code == 403


def test_if_match_prevents_lost_updates(client, alice, run_id):
    note = create_note(client, alice, run_id)
    etag = client.get(f"/notes/{note['id']}", headers=alice["headers"]).headers["etag"]
    h = {**alice["headers"], "If-Match": etag}
    assert client.put(f"/notes/{note['id']}", headers=h, json={"content": "first"}).status_code == 200
    assert client.put(f"/notes/{note['id']}", headers=h, json={"content": "stale"}).status_code == 412


def test_co_owner_can_share_and_last_owner_cannot_leave(client, alice, bob, carol, run_id):
    note = create_note(client, alice, run_id)
    # Alice can't remove herself while she's the only owner
    r = client.put(f"/notes/{note['id']}/metadata", headers=alice["headers"], json={"revoke": [{"email": alice["email"]}]})
    assert r.status_code == 409
    # Bob becomes co-owner, then shares with Carol and removes Alice
    assert share(client, alice, note, bob, "owner").status_code == 200
    r = client.put(
        f"/notes/{note['id']}/metadata",
        headers=bob["headers"],
        json={"grant": [{"email": carol["email"], "role": "viewer"}], "revoke": [{"email": alice["email"]}]},
    )
    assert r.status_code == 200, r.text
    roles = {p["email"]: p["role"] for p in r.json()["permissions"]}
    assert roles == {bob["email"]: "owner", carol["email"]: "viewer"}
    assert client.get(f"/notes/{note['id']}", headers=alice["headers"]).status_code == 404


# ─────────────────────────── Notes CRUD / S3 ───────────────────────────


def test_move_and_rename(client, alice, run_id):
    note = create_note(client, alice, run_id, content="movable")
    r = client.put(
        f"/notes/{note['id']}/metadata",
        headers=alice["headers"],
        json={"location": f"/tests/{run_id}/archive/", "filename": "moved.md"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["location"] == f"tests/{run_id}/archive"
    assert client.get(f"/notes/{note['id']}", headers=alice["headers"]).json()["content"] == "movable"


def test_duplicate_location_filename_conflicts(client, alice, run_id):
    create_note(client, alice, run_id, filename="dup.md")
    r = client.post(
        "/notes", headers=alice["headers"], json={"filename": "dup.md", "location": f"tests/{run_id}"}
    )
    assert r.status_code == 409


def test_rejects_path_traversal(client, alice):
    r = client.post("/notes", headers=alice["headers"], json={"filename": "x.md", "location": "a/../b"})
    assert r.status_code == 422
    r = client.post("/notes", headers=alice["headers"], json={"filename": "a/b.md"})
    assert r.status_code == 422


def test_list_filters(client, alice, run_id):
    create_note(client, alice, run_id, filename="Findable-Report.md")
    r = client.get("/notes", headers=alice["headers"], params={"location": f"tests/{run_id}", "q": "findable"})
    assert [n["filename"] for n in r.json()] == ["Findable-Report.md"]
    r = client.get("/notes", headers=alice["headers"], params={"location": "tests", "recursive": True, "q": "findable"})
    assert len(r.json()) == 1
    r = client.get("/notes", headers=alice["headers"], params={"location": "tests", "q": "findable"})
    assert r.json() == []


def test_delete(client, alice, run_id):
    note = create_note(client, alice, run_id)
    assert client.delete(f"/notes/{note['id']}", headers=alice["headers"]).status_code == 204
    assert client.get(f"/notes/{note['id']}", headers=alice["headers"]).status_code == 404
