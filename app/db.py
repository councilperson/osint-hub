"""Tiny SQLite layer (stdlib only): search history + pinned notes."""
from __future__ import annotations

import datetime
import hmac
import hashlib
import json
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
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'free',
    credits INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    last_seen REAL,
    daily_credit_day TEXT,
    daily_credits INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS credit_ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    delta INTEGER NOT NULL,
    balance INTEGER NOT NULL,
    reason TEXT NOT NULL,
    ref TEXT,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ledger_user ON credit_ledger(user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    kind TEXT NOT NULL,
    query TEXT NOT NULL,
    value TEXT NOT NULL,
    found INTEGER NOT NULL DEFAULT 0,
    checked INTEGER NOT NULL DEFAULT 0,
    total INTEGER NOT NULL DEFAULT 0,
    elapsed REAL NOT NULL DEFAULT 0,
    results TEXT NOT NULL DEFAULT '[]',
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cases_user ON cases(user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS case_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    query TEXT NOT NULL,
    payload TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_case_items_case ON case_items(case_id, created_at DESC);
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL DEFAULT 'default',
    active INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL,
    last_used REAL
);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    email TEXT NOT NULL DEFAULT '',
    plan TEXT NOT NULL,
    crypto TEXT NOT NULL,
    address TEXT NOT NULL,
    amount TEXT NOT NULL,
    txid TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status, created_at DESC);
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


# --------------------------------------------------------------------------
# accounts
# --------------------------------------------------------------------------

def insert_user(email: str, password_hash: str, plan: str = "free") -> dict:
    with _conn() as conn:
        cur = conn.execute(
            "INSERT INTO users (email, password_hash, plan, credits, created_at) "
            "VALUES (?,?,?,0,?)", (email, password_hash, plan, time.time()))
        row = conn.execute("SELECT * FROM users WHERE id = ?",
                           (cur.lastrowid,)).fetchone()
    return dict(row)


def get_user(user_id: int) -> dict | None:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(row) if row else None


def get_user_by_email(email: str) -> dict | None:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    return dict(row) if row else None


def list_users() -> list[dict]:
    with _conn() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    out = [dict(r) for r in rows]
    for row in out:
        row["created_str"] = datetime.datetime.fromtimestamp(
            row["created_at"]).strftime("%Y-%m-%d %H:%M")
        row["last_seen_str"] = (
            datetime.datetime.fromtimestamp(row["last_seen"]).strftime("%Y-%m-%d %H:%M")
            if row.get("last_seen") else "")
    return out


def set_user_plan(user_id: int, plan: str) -> None:
    with _conn() as conn:
        conn.execute("UPDATE users SET plan = ? WHERE id = ?", (plan, user_id))


def set_user_password(user_id: int, password_hash: str) -> None:
    with _conn() as conn:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                     (password_hash, user_id))


def delete_user(user_id: int) -> None:
    with _conn() as conn:
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM credit_ledger WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM api_keys WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM cases WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


def touch_user(user_id: int) -> None:
    with _conn() as conn:
        conn.execute("UPDATE users SET last_seen = ? WHERE id = ?",
                     (time.time(), user_id))


# --------------------------------------------------------------------------
# credits
# --------------------------------------------------------------------------

def adjust_credits(user_id: int, delta: int, reason: str, ref: str = "") -> int:
    """Apply a credit delta and write a ledger row. Returns the new balance."""
    with _conn() as conn:
        row = conn.execute("SELECT credits FROM users WHERE id = ?",
                           (user_id,)).fetchone()
        if row is None:
            return 0
        balance = max(0, int(row[0] or 0) + int(delta))
        conn.execute("UPDATE users SET credits = ? WHERE id = ?", (balance, user_id))
        conn.execute(
            "INSERT INTO credit_ledger (user_id, delta, balance, reason, ref, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (user_id, int(delta), balance, reason, ref, time.time()))
    return balance


def credit_ledger(user_id: int, limit: int = 100) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM credit_ledger WHERE user_id = ? "
            "ORDER BY created_at DESC LIMIT ?", (user_id, limit)).fetchall()
    out = [dict(r) for r in rows]
    for row in out:
        row["created_str"] = datetime.datetime.fromtimestamp(
            row["created_at"]).strftime("%Y-%m-%d %H:%M")
    return out


def grant_daily_credits(user_id: int, day: str, amount: int) -> int:
    """Give a user their daily allowance, once per calendar day."""
    with _conn() as conn:
        row = conn.execute(
            "SELECT daily_credit_day, daily_credits FROM users WHERE id = ?",
            (user_id,)).fetchone()
        if row is None:
            return 0
        if row["daily_credit_day"] == day:
            return int(row["daily_credits"] or 0)
        balance = int(conn.execute("SELECT credits FROM users WHERE id = ?",
                                   (user_id,)).fetchone()[0] or 0) + amount
        conn.execute(
            "UPDATE users SET credits = ?, daily_credit_day = ?, daily_credits = ? "
            "WHERE id = ?", (balance, day, amount, user_id))
        conn.execute(
            "INSERT INTO credit_ledger (user_id, delta, balance, reason, ref, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (user_id, amount, balance, "daily allowance", day, time.time()))
    return amount


# --------------------------------------------------------------------------
# sessions
# --------------------------------------------------------------------------

def insert_session(token_hash: str, user_id: int, expires_at: float) -> None:
    with _conn() as conn:
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) "
            "VALUES (?,?,?,?)", (token_hash, user_id, time.time(), expires_at))
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))


def delete_session(token_hash: str) -> None:
    with _conn() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))


def user_for_session(token_hash: str) -> dict | None:
    with _conn() as conn:
        row = conn.execute(
            "SELECT u.*, s.expires_at FROM sessions s "
            "JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
            (token_hash,)).fetchone()
    return dict(row) if row else None


# --------------------------------------------------------------------------
# API keys
# --------------------------------------------------------------------------

def insert_api_key(user_id: int, key: str, name: str, created_at: float) -> int:
    with _conn() as conn:
        cur = conn.execute(
            "INSERT INTO api_keys (user_id, key, name, active, created_at) "
            "VALUES (?,?,?,1,?)", (user_id, key, name, created_at))
        return int(cur.lastrowid)


def user_for_api_key(key: str) -> dict | None:
    with _conn() as conn:
        row = conn.execute(
            "SELECT u.*, k.id AS api_key_id FROM api_keys k "
            "JOIN users u ON u.id = k.user_id WHERE k.key = ? AND k.active = 1",
            (key,)).fetchone()
    return dict(row) if row else None


def list_api_keys(user_id: int) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT id, name, key, active, created_at, last_used FROM api_keys "
            "WHERE user_id = ? ORDER BY created_at DESC", (user_id,)).fetchall()
    out = [dict(r) for r in rows]
    for row in out:
        row["key_masked"] = row["key"][:10] + "…" + row["key"][-4:]
        row["created_str"] = datetime.datetime.fromtimestamp(
            row["created_at"]).strftime("%Y-%m-%d %H:%M")
        row["last_used_str"] = (
            datetime.datetime.fromtimestamp(row["last_used"]).strftime("%Y-%m-%d %H:%M")
            if row.get("last_used") else "never")
    return out


def touch_api_key(key_id: int, when: float) -> None:
    with _conn() as conn:
        conn.execute("UPDATE api_keys SET last_used = ? WHERE id = ?", (when, key_id))


def revoke_api_key(user_id: int, key_id: int) -> int:
    with _conn() as conn:
        cur = conn.execute(
            "UPDATE api_keys SET active = 0 WHERE id = ? AND user_id = ?",
            (key_id, user_id))
        return cur.rowcount


# --------------------------------------------------------------------------
# scans
# --------------------------------------------------------------------------

def insert_scan(user_id: int | None, kind: str, query: str, value: str,
                found: int, checked: int, total: int, elapsed: float,
                results: list) -> int:
    with _conn() as conn:
        cur = conn.execute(
            "INSERT INTO scans (user_id, kind, query, value, found, checked, total, "
            "elapsed, results, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (user_id, kind, query, value, found, checked, total, elapsed,
             json.dumps(results, ensure_ascii=False), time.time()))
        return int(cur.lastrowid)


def get_scan(scan_id: int, user_id: int | None = None) -> dict | None:
    with _conn() as conn:
        if user_id is None:
            row = conn.execute("SELECT * FROM scans WHERE id = ?",
                               (scan_id,)).fetchone()
        else:
            row = conn.execute("SELECT * FROM scans WHERE id = ? AND user_id = ?",
                               (scan_id, user_id)).fetchone()
    if not row:
        return None
    out = dict(row)
    try:
        out["results"] = json.loads(out.get("results") or "[]")
    except ValueError:
        out["results"] = []
    out["created_str"] = datetime.datetime.fromtimestamp(
        out["created_at"]).strftime("%Y-%m-%d %H:%M:%S")
    return out


def list_scans(user_id: int, limit: int = 100) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT id, kind, query, value, found, checked, total, elapsed, created_at "
            "FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
            (user_id, limit)).fetchall()
    out = [dict(r) for r in rows]
    for row in out:
        row["created_str"] = datetime.datetime.fromtimestamp(
            row["created_at"]).strftime("%Y-%m-%d %H:%M:%S")
    return out


# --------------------------------------------------------------------------
# cloud cases
# --------------------------------------------------------------------------

def create_case(user_id: int, name: str, notes: str = "") -> int:
    with _conn() as conn:
        cur = conn.execute(
            "INSERT INTO cases (user_id, name, notes, created_at) VALUES (?,?,?,?)",
            (user_id, name[:160], notes[:4000], time.time()))
        return int(cur.lastrowid)


def list_cases(user_id: int) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT c.*, (SELECT COUNT(*) FROM case_items i WHERE i.case_id = c.id) "
            "AS item_count FROM cases c WHERE c.user_id = ? ORDER BY c.created_at DESC",
            (user_id,)).fetchall()
    out = [dict(r) for r in rows]
    for row in out:
        row["created_str"] = datetime.datetime.fromtimestamp(
            row["created_at"]).strftime("%Y-%m-%d %H:%M")
    return out


def get_case(case_id: int, user_id: int) -> dict | None:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM cases WHERE id = ? AND user_id = ?",
                           (case_id, user_id)).fetchone()
    if not row:
        return None
    out = dict(row)
    out["created_str"] = datetime.datetime.fromtimestamp(
        out["created_at"]).strftime("%Y-%m-%d %H:%M")
    return out


def delete_case(case_id: int, user_id: int) -> int:
    with _conn() as conn:
        conn.execute("DELETE FROM case_items WHERE case_id = ?", (case_id,))
        cur = conn.execute("DELETE FROM cases WHERE id = ? AND user_id = ?",
                           (case_id, user_id))
        return cur.rowcount


def add_case_item(case_id: int, kind: str, query: str, payload: dict) -> int:
    with _conn() as conn:
        cur = conn.execute(
            "INSERT INTO case_items (case_id, kind, query, payload, created_at) "
            "VALUES (?,?,?,?,?)",
            (case_id, kind, query[:200],
             json.dumps(payload, ensure_ascii=False)[:200000], time.time()))
        return int(cur.lastrowid)


def list_case_items(case_id: int) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM case_items WHERE case_id = ? ORDER BY created_at DESC",
            (case_id,)).fetchall()
    out = [dict(r) for r in rows]
    for row in out:
        try:
            row["payload"] = json.loads(row.get("payload") or "{}")
        except ValueError:
            row["payload"] = {}
        row["created_str"] = datetime.datetime.fromtimestamp(
            row["created_at"]).strftime("%Y-%m-%d %H:%M:%S")
    return out


def delete_case_item(item_id: int, case_id: int, user_id: int) -> int:
    with _conn() as conn:
        cur = conn.execute(
            "DELETE FROM case_items WHERE id = ? AND case_id = ? AND case_id IN "
            "(SELECT id FROM cases WHERE id = ? AND user_id = ?)",
            (item_id, case_id, case_id, user_id))
        return cur.rowcount


# --------------------------------------------------------------------------
# crypto orders
# --------------------------------------------------------------------------

def create_order(user_id: int | None, email: str, plan: str, crypto: str,
                 address: str, amount: str, txid: str = "") -> int:
    with _conn() as conn:
        cur = conn.execute(
            "INSERT INTO orders (user_id, email, plan, crypto, address, amount, txid, "
            "status, created_at) VALUES (?,?,?,?,?,?,?,'pending',?)",
            (user_id, email[:190], plan, crypto, address, amount, txid[:190],
             time.time()))
        return int(cur.lastrowid)


def list_orders(limit: int = 200) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM orders ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    out = [dict(r) for r in rows]
    for row in out:
        row["created_str"] = datetime.datetime.fromtimestamp(
            row["created_at"]).strftime("%Y-%m-%d %H:%M:%S")
    return out


def get_order(order_id: int) -> dict | None:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if not row:
        return None
    out = dict(row)
    out["created_str"] = datetime.datetime.fromtimestamp(
        out["created_at"]).strftime("%Y-%m-%d %H:%M:%S")
    return out


def set_order_status(order_id: int, status: str, txid: str = "") -> None:
    with _conn() as conn:
        if txid:
            conn.execute("UPDATE orders SET status = ?, txid = ? WHERE id = ?",
                         (status, txid, order_id))
        else:
            conn.execute("UPDATE orders SET status = ? WHERE id = ?",
                         (status, order_id))
