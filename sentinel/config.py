from __future__ import annotations

import os
from pathlib import Path


def data_dir() -> Path:
    return Path(os.environ.get("SENTINEL_DATA_DIR", ".sentinel")).resolve()


def db_path() -> Path:
    return data_dir() / "sentinel.db"


def evidence_dir() -> Path:
    return data_dir() / "evidence"


def reports_dir() -> Path:
    return data_dir() / "reports"

