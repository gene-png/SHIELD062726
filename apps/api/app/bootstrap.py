"""Startup bootstrap: provision the env-seeded admin service account.

Self-registration (`app.routes.auth.register`) only ever creates `client`
users. The standing platform admin is provisioned here from environment
configuration, so a fresh deployment has exactly one admin to sign in with and
no signup path can escalate to admin.

Idempotent: if a user with the configured email already exists, this is a
no-op (it never resets a password or flips an existing role).
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import audit
from app.config import Settings
from app.logging import get_logger
from app.models._common import utcnow
from app.models.user import User, UserRole
from app.security.password import PasswordPolicyError, hash_password

_log = get_logger(__name__)


def ensure_bootstrap_admin(db: Session, settings: Settings) -> User | None:
    """Create the env-configured admin service account if it doesn't exist.

    Returns the created User, or None when seeding is disabled (no email/
    password configured) or the account already exists.
    """
    email = settings.shield_bootstrap_admin_email.strip().lower()
    password = settings.shield_bootstrap_admin_password

    if not email or not password:
        _log.info("bootstrap_admin_skipped", reason="not_configured")
        return None

    existing = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if existing is not None:
        _log.info("bootstrap_admin_present", email=email, role=existing.role.value)
        return None

    try:
        password_hash = hash_password(password)
    except PasswordPolicyError as exc:
        # Don't crash the app on a weak seed password; log loudly and skip.
        _log.error("bootstrap_admin_password_rejected", error=str(exc))
        return None

    admin = User(
        email=email,
        password_hash=password_hash,
        role=UserRole.ADMIN,
        display_name=settings.shield_bootstrap_admin_name,
        timezone="UTC",
        is_active=True,
        client_id=None,  # cross-tenant platform admin
        last_login_at=utcnow(),
    )
    db.add(admin)
    db.flush()
    audit(
        db,
        action="user.created",
        target_type="user",
        target_id=admin.id,
        actor_user_id=admin.id,
        details={"role": "admin", "source": "bootstrap", "seed": True},
    )
    db.commit()
    _log.info("bootstrap_admin_created", email=email)
    return admin
