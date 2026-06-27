"""End-to-end auth-route tests against an ephemeral SQLite + FastAPI TestClient."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker


@pytest.fixture()
def app_client(tmp_path) -> Iterator[TestClient]:
    db_path = tmp_path / "shield-auth.db"
    url = f"sqlite:///{db_path}"
    os.environ["DATABASE_URL"] = url

    api_root = Path(__file__).resolve().parents[2]
    cfg = Config(str(api_root / "alembic.ini"))
    cfg.set_main_option("script_location", str(api_root / "alembic"))
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")

    test_engine = create_engine(url, future=True)
    TestSession = sessionmaker(bind=test_engine, autoflush=False, autocommit=False, future=True)

    from app.db.session import get_db
    from app.main import create_app

    def override_get_db() -> Iterator[Session]:
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as c:
        yield c


def _register(
    client: TestClient,
    email: str = "first@example.com",
    password: str = "correct horse battery staple!",
) -> dict:
    r = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": password,
            "display_name": "Test User",
        },
    )
    assert r.status_code == 201, r.text
    return r.json()


@pytest.mark.unit
def test_first_registrant_is_client_primary_poc(app_client: TestClient) -> None:
    # Self-registration never creates an admin. The first registrant on a fresh
    # deployment is a regular client user who becomes their org's Primary POC.
    body = _register(app_client)
    assert body["is_primary_poc"] is True
    assert body["user"]["role"] == "client"
    assert body["user"]["client_id"]
    assert body["tokens"]["access_token"]
    assert body["tokens"]["refresh_token"]
    assert body["tokens"]["access_expires_at"]


@pytest.mark.unit
def test_second_registrant_joins_by_approved_domain(app_client: TestClient) -> None:
    # The first registrant on a work domain auto-creates the org AND approves
    # the domain, so a colleague who follows auto-joins the same client - no
    # admin action required.
    founder = _register(app_client, email="first@acme.com")
    assert founder["user"]["role"] == "client"
    assert founder["is_primary_poc"] is True
    cid = founder["user"]["client_id"]
    assert cid

    body = _register(app_client, email="second@acme.com")
    assert body["is_primary_poc"] is False
    assert body["user"]["role"] == "client"
    assert body["user"]["client_id"] == cid


@pytest.mark.unit
def test_register_generic_provider_gets_own_isolated_org(app_client: TestClient) -> None:
    # Open registration: a generic-provider user is allowed, but is placed in
    # their OWN private org -- strangers who merely share gmail.com are never
    # grouped together.
    _register(app_client, email="first@acme.com")  # unrelated work-domain user
    one = _register(app_client, email="someone@gmail.com")
    assert one["is_primary_poc"] is True
    assert one["user"]["role"] == "client"
    assert one["user"]["client_id"]

    two = _register(app_client, email="another@gmail.com")
    assert two["user"]["client_id"]
    # Different gmail users do not share an org.
    assert two["user"]["client_id"] != one["user"]["client_id"]


@pytest.mark.unit
def test_register_unknown_work_domain_autocreates_and_groups(app_client: TestClient) -> None:
    # Open registration: an unknown work domain auto-creates the org, and the
    # first registrant becomes its Primary POC. Colleagues on the same domain
    # then auto-join that same org.
    _register(app_client, email="first@acme.com")  # unrelated work-domain user
    founder = _register(app_client, email="newhire@unregistered-co.com")
    assert founder["is_primary_poc"] is True
    assert founder["user"]["role"] == "client"
    cid = founder["user"]["client_id"]
    assert cid

    colleague = _register(app_client, email="colleague@unregistered-co.com")
    assert colleague["is_primary_poc"] is False
    assert colleague["user"]["client_id"] == cid


@pytest.mark.unit
def test_duplicate_registration_rejected(app_client: TestClient) -> None:
    _register(app_client)
    r = app_client.post(
        "/auth/register",
        json={
            "email": "first@example.com",
            "password": "correct horse battery staple!",
            "display_name": "Test User",
        },
    )
    assert r.status_code == 409


@pytest.mark.unit
def test_password_policy_enforced_on_register(app_client: TestClient) -> None:
    r = app_client.post(
        "/auth/register",
        json={
            "email": "first@example.com",
            "password": "short",
            "display_name": "Test User",
        },
    )
    assert r.status_code == 422


@pytest.mark.unit
def test_login_with_correct_password(app_client: TestClient) -> None:
    _register(app_client)
    r = app_client.post(
        "/auth/login",
        json={"email": "first@example.com", "password": "correct horse battery staple!"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["access_token"]
    assert body["refresh_token"]


@pytest.mark.unit
def test_login_wrong_password_returns_401(app_client: TestClient) -> None:
    _register(app_client)
    r = app_client.post(
        "/auth/login",
        json={"email": "first@example.com", "password": "wrong horse battery staple!"},
    )
    assert r.status_code == 401


@pytest.mark.unit
def test_login_unknown_user_returns_401_not_404(app_client: TestClient) -> None:
    # Account-existence oracle defense (OWASP A07).
    r = app_client.post(
        "/auth/login",
        json={"email": "ghost@example.com", "password": "correct horse battery staple!"},
    )
    assert r.status_code == 401


@pytest.mark.unit
def test_lockout_after_max_failed_attempts(app_client: TestClient) -> None:
    _register(app_client)
    # 10 wrong attempts → next attempt should hit 423 LOCKED, even if password
    # is correct.
    for _ in range(10):
        app_client.post(
            "/auth/login",
            json={"email": "first@example.com", "password": "wrong horse battery staple!"},
        )
    r = app_client.post(
        "/auth/login",
        json={"email": "first@example.com", "password": "correct horse battery staple!"},
    )
    assert r.status_code == 423


@pytest.mark.unit
def test_me_returns_current_user(app_client: TestClient) -> None:
    body = _register(app_client)
    access = body["tokens"]["access_token"]
    r = app_client.get("/auth/me", headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 200
    me = r.json()
    assert me["email"] == "first@example.com"
    assert me["role"] == "client"


@pytest.mark.unit
def test_me_rejects_missing_token(app_client: TestClient) -> None:
    r = app_client.get("/auth/me")
    assert r.status_code == 401


@pytest.mark.unit
def test_me_rejects_refresh_token(app_client: TestClient) -> None:
    body = _register(app_client)
    refresh = body["tokens"]["refresh_token"]
    r = app_client.get("/auth/me", headers={"Authorization": f"Bearer {refresh}"})
    assert r.status_code == 401


@pytest.mark.unit
def test_refresh_issues_new_pair(app_client: TestClient) -> None:
    body = _register(app_client)
    refresh = body["tokens"]["refresh_token"]
    r = app_client.post("/auth/refresh", json={"refresh_token": refresh})
    assert r.status_code == 200
    new = r.json()
    assert new["access_token"]
    assert new["refresh_token"]


@pytest.mark.unit
def test_refresh_rejects_access_token(app_client: TestClient) -> None:
    body = _register(app_client)
    access = body["tokens"]["access_token"]
    r = app_client.post("/auth/refresh", json={"refresh_token": access})
    assert r.status_code == 401


@pytest.mark.unit
def test_logout_audits_and_returns_204(app_client: TestClient) -> None:
    body = _register(app_client)
    access = body["tokens"]["access_token"]
    r = app_client.post("/auth/logout", headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 204
