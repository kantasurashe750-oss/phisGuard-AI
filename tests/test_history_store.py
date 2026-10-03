import json
import sqlite3

from backend.src.history_store import (
    get_history_count,
    initialize_history_store,
    save_scan_summary,
)


def test_scan_history_persists_only_domain_and_explanation_summary(tmp_path):
    database = str(tmp_path / "history.sqlite3")
    initialize_history_store(database_url="", sqlite_path=database)
    save_scan_summary(
        "https://login.example.com/path?token=secret",
        "HIGH",
        0.91,
        "random_forest",
        [
            {"label": "Unusually long URL", "effect": "increases"},
            {"label": "Young domain", "effect": "increases"},
        ],
        database_url="",
        sqlite_path=database,
    )

    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT domain, risk_level, probability, model_type, explanation_summary
            FROM scan_history
            """
        ).fetchone()

    assert row[:4] == ("login.example.com", "HIGH", 0.91, "random_forest")
    assert "secret" not in str(row)
    assert json.loads(row[4]) == [
        {"label": "Unusually long URL", "effect": "increases"},
        {"label": "Young domain", "effect": "increases"},
    ]
    assert get_history_count(database_url="", sqlite_path=database) == 1
