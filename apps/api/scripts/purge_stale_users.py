"""Run the user-retention purge once (cron/manual entrypoint).

Usage (from apps/api, inside the api container or venv):
  python -m scripts.purge_stale_users

Honors SHIELD_USER_PURGE_IDLE_DAYS (default 365). Idempotent and safe to run
repeatedly; only deactivated accounts idle past the window are removed, and
accounts that still own data are skipped.
"""

from __future__ import annotations

import sys
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_ROOT))

from app.config import get_settings  # noqa: E402
from app.db.session import SessionLocal  # noqa: E402
from app.maintenance.retention import purge_stale_users  # noqa: E402


def main() -> None:
    settings = get_settings()
    with SessionLocal() as db:
        summary = purge_stale_users(db, max_idle_days=settings.shield_user_purge_idle_days)
    print(
        f"Purge complete: purged={summary.purged} skipped={summary.skipped} "
        f"reasons={summary.skipped_reasons}"
    )


if __name__ == "__main__":
    main()
