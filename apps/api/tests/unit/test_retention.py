"""Retention purge tests (app.maintenance.retention.purge_stale_users).

Purge crypto-shreds (anonymizes) the row rather than deleting it, because the
append-only audit trail references users.id.
"""

from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker


@pytest.fixture()
def session_factory(tmp_path):
    db_path = tmp_path / "shield-retention.db"
    url = f"sqlite:///{db_path}"
    os.environ["DATABASE_URL"] = url
    api_root = Path(__file__).resolve().parents[2]
    cfg = Config(str(api_root / "alembic.ini"))
    cfg.set_main_option("script_location", str(api_root / "alembic"))
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")
    engine = create_engine(url, future=True)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def _mk_user(db: Session, *, email: str, is_active: bool, last_login_days_ago: int | None):
    from app.models._common import utcnow
    from app.models.user import User, UserRole

    now = utcnow()
    last = None if last_login_days_ago is None else now - timedelta(days=last_login_days_ago)
    user = User(
        email=email,
        password_hash="argon2-placeholder",
        role=UserRole.CLIENT,
        display_name=email,
        title="Engineer",
        phone="555-0100",
        timezone="UTC",
        is_active=is_active,
        last_login_at=last,
        deactivated_at=(None if is_active else last),
    )
    # Backdate created_at past the window so the created_at guard doesn't block.
    user.created_at = now - timedelta(days=1000)
    db.add(user)
    db.flush()
    return user


@pytest.mark.unit
def test_anonymizes_deactivated_and_stale(session_factory) -> None:
    from app.maintenance.retention import purge_stale_users
    from app.models.user import User

    db = session_factory()
    user = _mk_user(db, email="old@x.com", is_active=False, last_login_days_ago=400)
    uid = user.id
    db.commit()

    summary = purge_stale_users(db, max_idle_days=365)
    assert summary.purged == 1

    purged = db.execute(select(User).where(User.id == uid)).scalar_one()
    # Row is kept (audit integrity), but PII is gone.
    assert purged.email == f"purged-{uid}@deleted.example"
    assert purged.display_name is None
    assert purged.title is None
    assert purged.phone is None
    assert purged.password_hash == "!purged"
    assert purged.is_active is False
    assert purged.purged_at is not None


@pytest.mark.unit
def test_purge_is_idempotent(session_factory) -> None:
    from app.maintenance.retention import purge_stale_users

    db = session_factory()
    _mk_user(db, email="old@x.com", is_active=False, last_login_days_ago=400)
    db.commit()

    assert purge_stale_users(db, max_idle_days=365).purged == 1
    # Second run skips the already-purged row (purged_at is set).
    assert purge_stale_users(db, max_idle_days=365).purged == 0


@pytest.mark.unit
def test_keeps_active_users_however_idle(session_factory) -> None:
    from app.maintenance.retention import purge_stale_users
    from app.models.user import User

    db = session_factory()
    _mk_user(db, email="active@x.com", is_active=True, last_login_days_ago=1000)
    db.commit()

    assert purge_stale_users(db, max_idle_days=365).purged == 0
    kept = db.execute(select(User).where(User.email == "active@x.com")).scalar_one()
    assert kept.purged_at is None


@pytest.mark.unit
def test_keeps_recently_deactivated(session_factory) -> None:
    from app.maintenance.retention import purge_stale_users

    db = session_factory()
    _mk_user(db, email="recent@x.com", is_active=False, last_login_days_ago=10)
    db.commit()

    assert purge_stale_users(db, max_idle_days=365).purged == 0


@pytest.mark.unit
def test_anonymizes_even_when_user_owns_a_service(session_factory) -> None:
    # Anonymization keeps the row, so a foreign key like services.opened_by stays
    # valid - no need to skip data owners the way a hard delete would.
    from app.maintenance.retention import purge_stale_users
    from app.models.client import Client
    from app.models.service import Service, ServiceKind, ServiceStatus
    from app.models.user import User

    db = session_factory()
    user = _mk_user(db, email="owner@x.com", is_active=False, last_login_days_ago=400)
    org = Client(legal_name="Acme")
    db.add(org)
    db.flush()
    svc = Service(
        kind=ServiceKind.TECH_DEBT,
        status=ServiceStatus.IN_PROGRESS,
        title="Acme - Tech Debt",
        client_id=org.id,
        opened_by=user.id,
    )
    db.add(svc)
    db.commit()

    assert purge_stale_users(db, max_idle_days=365).purged == 1
    purged = db.execute(select(User).where(User.id == user.id)).scalar_one()
    assert purged.purged_at is not None
    # The service still references the (now anonymized) user row.
    kept_svc = db.execute(select(Service).where(Service.id == svc.id)).scalar_one()
    assert kept_svc.opened_by == user.id
