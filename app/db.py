"""Tiny SQLite layer (stdlib only): search history + pinned notes."""
from __future__ import annotations

import datetime
import hmac
import hashlib
import os
import secrets
import sqlite3
import time
from pathlib import Path

DB_PATH = Path(
    os.environ.get(
        "OSINT_DB",
        Path(__file__).resolve().parent.parent / "data" / "osint.db",
    )
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT NOT NULL,
    target TEXT NOT NULL,
    ok INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_queries_created ON queries(created_at DESC);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT NOT NULL,
    target TEXT NOT NULL,
    summary TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS licenses (
    key TEXT PRIMARY KEY,
    plan TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL
);
"""


def _conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init() -> None:
    with _conn() as conn:
        conn.executescript(_SCHEMA)


def add_query(tool: str, target: str, ok: bool = True) -> None:
    with _conn() as conn:
        conn.execute(
            "INSERT INTO queries (tool, target, ok, created_at) VALUES (?,?,?,?)",
            (tool, target, 1 if ok else 0, time.time()),
        )
        # keep the log bounded
        conn.execute(
            "DELETE FROM queries WHERE id NOT IN "
            "(SELECT id FROM queries ORDER BY created_at DESC LIMIT 2000)"
        )


def recent_queries(limit: int = 100) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM queries ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    out = [dict(r) for r in rows]
    for row in out:
        row["created_str"] = datetime.datetime.fromtimestamp(
            row["created_at"]).strftime("%Y-%m-%d %H:%M:%S")
    return out


def add_note(tool: str, target: str, summary: str) -> None:
    with _conn() as conn:
        conn.execute(
            "INSERT INTO notes (tool, target, summary, created_at) VALUES (?,?,?,?)",
            (tool, target, summary, time.time()),
        )


def list_notes() -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM notes ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def delete_note(note_id: int) -> None:
    with _conn() as conn:
        conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))


def delete_query(query_id: int) -> None:
    with _conn() as conn:
        conn.execute("DELETE FROM queries WHERE id = ?", (query_id,))


def clear_history() -> int:
    with _conn() as conn:
        n = conn.execute("SELECT COUNT(*) FROM queries").fetchone()[0]
        conn.execute("DELETE FROM queries")
    return n


def clear_notes() -> int:
    with _conn() as conn:
        n = conn.execute("SELECT COUNT(*) FROM notes").fetchone()[0]
        conn.execute("DELETE FROM notes")
    return n


def admin_stats() -> dict:
    with _conn() as conn:
        total_queries = conn.execute("SELECT COUNT(*) FROM queries").fetchone()[0]
        unique = conn.execute("SELECT COUNT(DISTINCT target) FROM queries").fetchone()[0]
        tools = conn.execute(
            "SELECT COUNT(DISTINCT tool) FROM queries").fetchone()[0]
        by_tool = dict(conn.execute(
            "SELECT tool, COUNT(*) FROM queries GROUP BY tool ORDER BY COUNT(*) DESC"
        ).fetchall())
        ok_rate = conn.execute(
            "SELECT AVG(ok) FROM queries").fetchone()[0]
        total_notes = conn.execute("SELECT COUNT(*) FROM notes").fetchone()[0]
    return {
        "total_queries": total_queries,
        "unique_targets": unique,
        "total_tools": tools,
        "by_tool": by_tool,
        "ok_rate": round((ok_rate or 0) * 100, 1),
        "total_notes": total_notes,
    }


# --- licenses -------------------------------------------------------------

def has_pro() -> bool:
    with _conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM licenses WHERE active = 1 LIMIT 1").fetchone()
    return row is not None


def activate_license(plan: str = "pro") -> str:
    key = f"OSINT-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"
    with _conn() as conn:
        conn.execute(
            "INSERT INTO licenses (key, plan, active, created_at) VALUES (?,?,1,?)",
            (key, plan, time.time()),
        )
    return key


def deactivate_all() -> int:
    with _conn() as conn:
        cur = conn.execute("UPDATE licenses SET active = 0 WHERE active = 1")
    return cur.rowcount


def list_licenses() -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM licenses ORDER BY created_at DESC").fetchall()
    out = [dict(r) for r in rows]
    for row in out:
        row["created_str"] = datetime.datetime.fromtimestamp(
            row["created_at"]).strftime("%Y-%m-%d %H:%M")
    return out
