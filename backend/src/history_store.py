"""Persist minimal scan summaries without retaining submitted URL paths or queries."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from typing import Optional
from urllib.parse import urlparse

DEFAULT_SQLITE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "scan_history.sqlite3"
)


def _connection_settings(
    database_url: Optional[str] = None, sqlite_path: Optional[str] = None
) -> tuple:
    url = database_url if database_url is not None else os.getenv("DATABASE_URL")
    if url:
        if url.startswith("postgres://"):
            url = "postgresql://" + url[len("postgres://") :]
        return "postgres", url
    return "sqlite", sqlite_path or os.getenv("PHISHGUARD_SQLITE_PATH", DEFAULT_SQLITE_PATH)


def initialize_history_store(
    database_url: Optional[str] = None, sqlite_path: Optional[str] = None
) -> None:
    backend, target = _connection_settings(database_url, sqlite_path)
    if backend == "postgres":
        import psycopg2

        with closing(psycopg2.connect(target)) as connection:
            with connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        CREATE TABLE IF NOT EXISTS scan_history (
                            id BIGSERIAL PRIMARY KEY,
                            scanned_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                            domain TEXT NOT NULL,
                            risk_level TEXT NOT NULL,
                            probability DOUBLE PRECISION NOT NULL,
                            model_type TEXT NOT NULL,
                            explanation_summary TEXT NOT NULL
                        )
                        """
                    )
        return

    os.makedirs(os.path.dirname(os.path.abspath(target)), exist_ok=True)
    with sqlite3.connect(target) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                domain TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                probability REAL NOT NULL,
                model_type TEXT NOT NULL,
                explanation_summary TEXT NOT NULL
            )
            """
        )


def save_scan_summary(
    url: str,
    risk_level: str,
    probability: float,
    model_type: str,
    explanations: list,
    database_url: Optional[str] = None,
    sqlite_path: Optional[str] = None,
) -> None:
    backend, target = _connection_settings(database_url, sqlite_path)
    domain = urlparse(url).hostname
    if not domain:
        raise ValueError("Cannot store scan history without a valid domain.")
    summary = json.dumps(
        [
            {
                "label": str(item["label"]),
                "effect": str(item["effect"]),
            }
            for item in explanations[:3]
        ],
        ensure_ascii=True,
    )
    values = (domain, risk_level, probability, model_type, summary)

    if backend == "postgres":
        import psycopg2

        with closing(psycopg2.connect(target)) as connection:
            with connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO scan_history
                            (domain, risk_level, probability, model_type, explanation_summary)
                        VALUES (%s, %s, %s, %s, %s)
                        """,
                        values,
                    )
        return

    os.makedirs(os.path.dirname(os.path.abspath(target)), exist_ok=True)
    with sqlite3.connect(target) as connection:
        connection.execute(
            """
            INSERT INTO scan_history
                (domain, risk_level, probability, model_type, explanation_summary)
            VALUES (?, ?, ?, ?, ?)
            """,
            values,
        )


def get_history_count(
    database_url: Optional[str] = None, sqlite_path: Optional[str] = None
) -> int:
    """Return a non-sensitive record count for tests."""
    backend, target = _connection_settings(database_url, sqlite_path)
    if backend == "postgres":
        import psycopg2

        with closing(psycopg2.connect(target)) as connection:
            with connection:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT COUNT(*) FROM scan_history")
                    return int(cursor.fetchone()[0])

    with sqlite3.connect(target) as connection:
        row = connection.execute("SELECT COUNT(*) FROM scan_history").fetchone()
        return int(row[0])
