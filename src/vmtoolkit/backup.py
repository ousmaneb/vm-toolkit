"""Dated copies of the database, made with SQLite's online backup so they're consistent mid-write."""

import sqlite3
from datetime import datetime
from pathlib import Path

from .config import Settings


def backup(settings: Settings, keep: int = 14, now: datetime | None = None) -> tuple[Path, list[Path]]:
    """Copy the database to <data_dir>/backups/<name>-<date>.db and delete all but the newest `keep`."""
    now = now or datetime.now()
    folder = settings.data_dir / "backups"
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / f"{settings.db_path.stem}-{now:%Y-%m-%d}.db"
    source = sqlite3.connect(settings.db_path)
    dest = sqlite3.connect(target)
    try:
        source.backup(dest)
    finally:
        dest.close()
        source.close()
    copies = sorted(folder.glob(f"{settings.db_path.stem}-????-??-??.db"))
    removed = copies[:-keep] if keep > 0 else []
    for old in removed:
        old.unlink()
    return target, removed
