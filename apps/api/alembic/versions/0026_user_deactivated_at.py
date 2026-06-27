"""users.deactivated_at - account deactivation timestamp (retention clock)

Revision ID: 0026
Revises: 0025
Create Date: 2026-06-27 00:00:00

Admins deactivate accounts (is_active=false) rather than hard-deleting them.
This column records when, starting the retention clock: deactivated accounts
with no login for the configured idle window are later purged.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0026"
down_revision: str | Sequence[str] | None = "0025"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("deactivated_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.drop_column("deactivated_at")
