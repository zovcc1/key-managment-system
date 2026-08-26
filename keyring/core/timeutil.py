"""SQLite drops tzinfo on round-trip for `DateTime(timezone=True)` columns
(Postgres does not). Every comparison/subtraction against a DB-fetched
datetime must go through this so both backends behave identically."""
from __future__ import annotations

from datetime import datetime, timezone


def aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
