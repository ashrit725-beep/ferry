"""Shared test fixtures. Area-specific helpers live in tests/helpers_<area>.py."""

from __future__ import annotations

from pathlib import Path

import pytest

from ferry.config import Settings
from ferry.db import Database


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    d = tmp_path / "data"
    d.mkdir()
    return d


@pytest.fixture
def settings(data_dir: Path) -> Settings:
    return Settings(data_dir=data_dir)


@pytest.fixture
def database(settings: Settings) -> Database:
    db = Database(settings.db_path)
    db.init()
    return db


@pytest.fixture
def conn(database: Database):
    c = database.connect()
    try:
        yield c
    finally:
        c.close()
