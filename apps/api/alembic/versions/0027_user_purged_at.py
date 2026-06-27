"""users.purged_at - retention crypto-shred timestamp

Revision ID: 0027
Revises: 0026
Create Date: 2026-06-27 00:00:00

The retention job anonymizes (crypto-shreds) deactivated, long-idle accounts
rather than row-deleting them, because audit_entries is append-only and
references users.id via actor_user_id. This column marks a row as already
purged so the job is idempotent.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0027"
down_revision: str | Sequence[str] | None = "0026"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("purged_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.drop_column("purged_at")
