"""Tiny SQLite layer (stdlib only): accounts, credits, scans, cases, orders.

Every call opens a short-lived connection (WAL mode, busy timeout) and closes
it again, so concurrent requests on a small instance never trip over a
"database is locked" error and no file handles leak.
"""
from __future__ import annotations

import contextlib
import datetime
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
-- Monitoring & Alerts
CREATE TABLE IF NOT EXISTS monitors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    frequency TEXT NOT NULL DEFAULT 'daily',
    channel TEXT NOT NULL DEFAULT 'email',
    channel_config TEXT NOT NULL DEFAULT '{}',
    enabled INTEGER NOT NULL DEFAULT 1,
    last_run REAL,
    last_hit_count INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_monitors_user ON monitors(user_id, enabled);
CREATE TABLE IF NOT EXISTS monitor_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    monitor_id INTEGER NOT NULL,
    hits_found INTEGER NOT NULL DEFAULT 0,
    total_checked INTEGER NOT NULL DEFAULT 0,
    elapsed REAL NOT NULL DEFAULT 0,
    error TEXT,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_monitor_runs_monitor ON monitor_runs(monitor_id, created_at DESC);
CREATE TABLE IF NOT EXISTS monitor_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    monitor_id INTEGER NOT NULL,
    run_id INTEGER NOT NULL,
    endpoint_id TEXT NOT NULL,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    url TEXT NOT NULL,
    detail TEXT,
    display_name TEXT,
    avatar TEXT,
    meta TEXT NOT NULL DEFAULT '[]',
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_monitor_hits_run ON monitor_hits(run_id);
-- White-Label API Reseller
CREATE TABLE IF NOT EXISTS sub_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    api_key TEXT NOT NULL UNIQUE,
    credits_limit INTEGER NOT NULL DEFAULT 1000,
    credits_used INTEGER NOT NULL DEFAULT 0,
    rate_limit INTEGER NOT NULL DEFAULT 60,
    branding TEXT NOT NULL DEFAULT '{}',
    active INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sub_accounts_owner ON sub_accounts(owner_id);
CREATE TABLE IF NOT EXISTS sub_account_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sub_account_id INTEGER NOT NULL,
    credits_spent INTEGER NOT NULL DEFAULT 0,
    scans_count INTEGER NOT NULL DEFAULT 0,
    period_start REAL NOT NULL,
    period_end REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sub_usage_account ON sub_account_usage(sub_account_id, period_start DESC);
-- Professional Report Service
CREATE TABLE IF NOT EXISTS report_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    template_json TEXT NOT NULL DEFAULT '{}',
    is_default INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_report_templates_user ON report_templates(user_id);
CREATE TABLE IF NOT EXISTS report_generations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    scan_id INTEGER NOT NULL,
    template_id INTEGER,
    format TEXT NOT NULL,
    file_path TEXT,
    status TEXT NOT NULL DEFAULT 'completed',
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_report_gens_user ON report_generations(user_id, created_at DESC);
"""


_MIGRATIONS = [
    # (table, column, DDL) — added when an older database is missing them
    ("queries", "user_id", "ALTER TABLE queries ADD COLUMN user_id INTEGER"),
    ("notes", "user_id", "ALTER TABLE notes ADD COLUMN user_id INTEGER"),
]

_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_queries_user ON queries(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notes_user ON notes(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_monitors_enabled ON monitors(enabled);
CREATE INDEX IF NOT EXISTS idx_monitor_hits_monitor ON monitor_hits(monitor_id);
CREATE INDEX IF NOT EXISTS idx_ledger_ref ON credit_ledger(user_id, reason, ref);
"""


@contextlib.contextmanager
def _conn():
    """A connection that commits on success, rolls back on error and is
    always closed."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 15000")
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    try:
        # WAL lets readers and the writer work at the same time.
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.executescript(_SCHEMA)
        for table, column, ddl in _MIGRATIONS:
            cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
            if column not in cols:
                conn.execute(ddl)
        conn.executescript(_INDEXES)
        conn.commit()
    finally:
        conn.close()


def _json_obj(raw, default=None):
    """Parse a JSON column; a corrupt value falls back instead of crashing a page."""
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw or "null") or (default if default is not None else {})
    except (TypeError, ValueError):
        return default if default is not None else {}


def add_query(tool: str, target: str, ok: bool = True,
              user_id: int | None = None) -> None:
    with _conn() as conn:
        conn.execute(
            "INSERT INTO queries (tool, target, ok, created_at, user_id) VALUES (?,?,?,?,?)",
            (tool, target[:500], 1 if ok else 0, time.time(), user_id),
        )
        # keep the log bounded
        conn.execute(
            "DELETE FROM queries WHERE id NOT IN "
            "(SELECT id FROM queries ORDER BY created_at DESC LIMIT 2000)"
        )


def recent_queries(limit: int = 100, user_id: int | None = None) -> list[dict]:
    """All lookups (admin view), or only one account's when user_id is given."""
    with _conn() as conn:
        if user_id is None:
            rows = conn.execute(
                "SELECT * FROM queries ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM queries WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
                (user_id, limit)).fetchall()
    out = [dict(r) for r in rows]
    for row in out:
        row["created_str"] = datetime.datetime.fromtimestamp(
            row["created_at"]).strftime("%Y-%m-%d %H:%M:%S")
    return out


def add_note(tool: str, target: str, summary: str,
             user_id: int | None = None) -> None:
    with _conn() as conn:
        conn.execute(
            "INSERT INTO notes (tool, target, summary, created_at, user_id) VALUES (?,?,?,?,?)",
            (tool[:200], target[:500], summary, time.time(), user_id),
        )


def list_notes(user_id: int | None = None) -> list[dict]:
    """All notes (admin view), or only one account's when user_id is given."""
    with _conn() as conn:
        if user_id is None:
            rows = conn.execute(
                "SELECT * FROM notes ORDER BY created_at DESC").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM notes WHERE user_id = ? ORDER BY created_at DESC",
                (user_id,)).fetchall()
    out = [dict(r) for r in rows]
    for row in out:
        row["created_str"] = datetime.datetime.fromtimestamp(
            row["created_at"]).strftime("%Y-%m-%d %H:%M")
    return out


def delete_note(note_id: int, user_id: int | None = None) -> int:
    """Delete a note. With user_id, only that account's note can go."""
    with _conn() as conn:
        if user_id is None:
            cur = conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
        else:
            cur = conn.execute("DELETE FROM notes WHERE id = ? AND user_id = ?",
                               (note_id, user_id))
        return cur.rowcount


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
        conn.execute("DELETE FROM case_items WHERE case_id IN "
                     "(SELECT id FROM cases WHERE user_id = ?)", (user_id,))
        conn.execute("DELETE FROM cases WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM monitor_hits WHERE monitor_id IN "
                     "(SELECT id FROM monitors WHERE user_id = ?)", (user_id,))
        conn.execute("DELETE FROM monitor_runs WHERE monitor_id IN "
                     "(SELECT id FROM monitors WHERE user_id = ?)", (user_id,))
        conn.execute("DELETE FROM monitors WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM sub_account_usage WHERE sub_account_id IN "
                     "(SELECT id FROM sub_accounts WHERE owner_id = ?)", (user_id,))
        conn.execute("DELETE FROM sub_accounts WHERE owner_id = ?", (user_id,))
        conn.execute("DELETE FROM report_templates WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM report_generations WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM notes WHERE user_id = ?", (user_id,))
        conn.execute("UPDATE queries SET user_id = NULL WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


def touch_user(user_id: int, min_interval: float = 60.0) -> None:
    """Record activity, at most once a minute so page views stay read-only."""
    now = time.time()
    with _conn() as conn:
        conn.execute("UPDATE users SET last_seen = ? WHERE id = ? AND "
                     "(last_seen IS NULL OR last_seen < ?)",
                     (now, user_id, now - min_interval))


def count_users() -> int:
    with _conn() as conn:
        return int(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])


def count_rows(table: str) -> int:
    if table not in {"users", "scans", "orders", "queries", "notes"}:
        raise ValueError(table)
    with _conn() as conn:
        return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def delete_sessions_for_user(user_id: int, keep_hash: str = "") -> None:
    with _conn() as conn:
        conn.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?",
                     (user_id, keep_hash))


# --------------------------------------------------------------------------
# credits
# --------------------------------------------------------------------------

def adjust_credits(user_id: int, delta: int, reason: str, ref: str = "") -> int:
    """Apply a credit delta and write a ledger row. Returns the new balance.

    The balance never goes below zero. The UPDATE is a single statement, so
    two requests at once cannot both read the old balance."""
    delta = int(delta)
    with _conn() as conn:
        cur = conn.execute(
            "UPDATE users SET credits = MAX(0, credits + ?) WHERE id = ?",
            (delta, user_id))
        if cur.rowcount == 0:
            return 0
        balance = int(conn.execute("SELECT credits FROM users WHERE id = ?",
                                   (user_id,)).fetchone()[0] or 0)
        conn.execute(
            "INSERT INTO credit_ledger (user_id, delta, balance, reason, ref, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (user_id, delta, balance, reason, ref, time.time()))
    return balance


def try_spend_credits(user_id: int, amount: int, reason: str, ref: str = "") -> int | None:
    """Atomically take `amount` credits if the balance covers it.

    Returns the new balance, or None (and changes nothing) when it does not."""
    amount = max(0, int(amount))
    with _conn() as conn:
        cur = conn.execute(
            "UPDATE users SET credits = credits - ? WHERE id = ? AND credits >= ?",
            (amount, user_id, amount))
        if cur.rowcount == 0:
            return None
        balance = int(conn.execute("SELECT credits FROM users WHERE id = ?",
                                   (user_id,)).fetchone()[0] or 0)
        conn.execute(
            "INSERT INTO credit_ledger (user_id, delta, balance, reason, ref, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (user_id, -amount, balance, reason, ref, time.time()))
    return balance


def has_ledger_entry(user_id: int, reason: str, ref: str) -> bool:
    with _conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM credit_ledger WHERE user_id = ? AND reason = ? AND ref = ? LIMIT 1",
            (user_id, reason, ref)).fetchone()
    return row is not None


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
    """Give a user their allowance once per period (day or month key).

    The period check and the top-up are one UPDATE, so parallel requests at
    the start of a new period cannot grant it twice."""
    with _conn() as conn:
        cur = conn.execute(
            "UPDATE users SET credits = credits + ?, daily_credit_day = ?, daily_credits = ? "
            "WHERE id = ? AND (daily_credit_day IS NULL OR daily_credit_day != ?)",
            (amount, day, amount, user_id, day))
        if cur.rowcount == 0:
            return 0
        balance = int(conn.execute("SELECT credits FROM users WHERE id = ?",
                                   (user_id,)).fetchone()[0] or 0)
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


def submit_order_txid(order_id: int, txid: str) -> bool:
    """Buyer-side: attach a TXID, only while the order is still open."""
    with _conn() as conn:
        cur = conn.execute(
            "UPDATE orders SET status = 'submitted', txid = ? "
            "WHERE id = ? AND status IN ('pending', 'submitted')",
            (txid[:190], order_id))
        return cur.rowcount > 0


def approve_order_once(order_id: int) -> bool:
    """Flip an order to approved exactly once (safe against double clicks)."""
    with _conn() as conn:
        cur = conn.execute(
            "UPDATE orders SET status = 'approved' WHERE id = ? AND status != 'approved'",
            (order_id,))
        return cur.rowcount > 0


def set_order_status(order_id: int, status: str, txid: str = "") -> None:
    with _conn() as conn:
        if txid:
            conn.execute("UPDATE orders SET status = ?, txid = ? WHERE id = ?",
                         (status, txid[:190], order_id))
        else:
            conn.execute("UPDATE orders SET status = ? WHERE id = ?",
                         (status, order_id))


# --------------------------------------------------------------------------
# Monitoring & Alerts
# --------------------------------------------------------------------------

def create_monitor(user_id: int, kind: str, target: str, frequency: str = "daily",
                   channel: str = "email", channel_config: dict = None) -> int:
    with _conn() as conn:
        cur = conn.execute(
            "INSERT INTO monitors (user_id, kind, target, frequency, channel, channel_config, enabled, created_at) "
            "VALUES (?,?,?,?,?,?,1,?)",
            (user_id, kind, target[:200], frequency, channel,
             json.dumps(channel_config or {}), time.time()))
        return int(cur.lastrowid)


def list_monitors(user_id: int) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM monitors WHERE user_id = ? ORDER BY created_at DESC", (user_id,)).fetchall()
    out = [dict(r) for r in rows]
    for row in out:
        row["created_str"] = datetime.datetime.fromtimestamp(
            row["created_at"]).strftime("%Y-%m-%d %H:%M")
        row["last_run_str"] = (datetime.datetime.fromtimestamp(row["last_run"]).strftime(
            "%Y-%m-%d %H:%M") if row.get("last_run") else "")
        row["channel_config"] = _json_obj(row["channel_config"])
    return out


def get_monitor(monitor_id: int, user_id: int) -> dict | None:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM monitors WHERE id = ? AND user_id = ?",
                           (monitor_id, user_id)).fetchone()
    if not row:
        return None
    out = dict(row)
    out["created_str"] = datetime.datetime.fromtimestamp(
        out["created_at"]).strftime("%Y-%m-%d %H:%M")
    out["channel_config"] = _json_obj(out["channel_config"])
    return out


def update_monitor(monitor_id: int, user_id: int, **kwargs) -> int:
    allowed = {"kind", "target", "frequency", "channel", "channel_config", "enabled"}
    fields = []
    values = []
    for k, v in kwargs.items():
        if k in allowed:
            fields.append(f"{k} = ?")
            if k == "channel_config":
                values.append(json.dumps(v))
            else:
                values.append(v)
    if not fields:
        return 0
    values.extend([monitor_id, user_id])
    with _conn() as conn:
        cur = conn.execute(f"UPDATE monitors SET {', '.join(fields)} WHERE id = ? AND user_id = ?", values)
        return cur.rowcount


def delete_monitor(monitor_id: int, user_id: int) -> int:
    with _conn() as conn:
        conn.execute("DELETE FROM monitor_hits WHERE monitor_id = ?", (monitor_id,))
        conn.execute("DELETE FROM monitor_runs WHERE monitor_id = ?", (monitor_id,))
        cur = conn.execute("DELETE FROM monitors WHERE id = ? AND user_id = ?", (monitor_id, user_id))
        return cur.rowcount


def list_enabled_monitors() -> list[dict]:
    with _conn() as conn:
        rows = conn.execute("SELECT * FROM monitors WHERE enabled = 1").fetchall()
    out = [dict(r) for r in rows]
    for row in out:
        row["channel_config"] = _json_obj(row.get("channel_config"))
    return out


def mark_monitor_run(monitor_id: int, hit_count: int) -> None:
    with _conn() as conn:
        conn.execute("UPDATE monitors SET last_run = ?, last_hit_count = ? WHERE id = ?",
                     (time.time(), hit_count, monitor_id))


def count_monitors(user_id: int) -> int:
    with _conn() as conn:
        return int(conn.execute("SELECT COUNT(*) FROM monitors WHERE user_id = ?",
                                (user_id,)).fetchone()[0])


def get_monitor_run(run_id: int, monitor_id: int) -> dict | None:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM monitor_runs WHERE id = ? AND monitor_id = ?",
                           (run_id, monitor_id)).fetchone()
    if not row:
        return None
    out = dict(row)
    out["created_str"] = datetime.datetime.fromtimestamp(
        out["created_at"]).strftime("%Y-%m-%d %H:%M:%S")
    return out


def create_monitor_run(monitor_id: int, hits_found: int, total_checked: int,
                       elapsed: float, error: str = "") -> int:
    with _conn() as conn:
        cur = conn.execute(
            "INSERT INTO monitor_runs (monitor_id, hits_found, total_checked, elapsed, error, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (monitor_id, hits_found, total_checked, elapsed, error, time.time()))
        return int(cur.lastrowid)


def add_monitor_hits(run_id: int, monitor_id: int, hits: list[dict]) -> int:
    with _conn() as conn:
        count = 0
        for h in hits:
            conn.execute(
                "INSERT INTO monitor_hits (monitor_id, run_id, endpoint_id, name, category, url, detail, display_name, avatar, meta, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (monitor_id, run_id, h.get("id", ""), h.get("name", ""), h.get("category", ""),
                 h.get("url", ""), h.get("detail", ""), h.get("display_name", ""),
                 h.get("avatar", ""), json.dumps(h.get("meta", [])), time.time()))
            count += 1
        return count


def list_monitor_runs(monitor_id: int, limit: int = 50) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM monitor_runs WHERE monitor_id = ? ORDER BY created_at DESC LIMIT ?",
            (monitor_id, limit)).fetchall()
    out = [dict(r) for r in rows]
    for row in out:
        row["created_str"] = datetime.datetime.fromtimestamp(
            row["created_at"]).strftime("%Y-%m-%d %H:%M:%S")
    return out


def list_monitor_hits(run_id: int) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM monitor_hits WHERE run_id = ? ORDER BY created_at DESC", (run_id,)).fetchall()
    out = [dict(r) for r in rows]
    for row in out:
        row["created_str"] = datetime.datetime.fromtimestamp(
            row["created_at"]).strftime("%Y-%m-%d %H:%M:%S")
        row["meta"] = _json_obj(row["meta"], [])
    return out


# --------------------------------------------------------------------------
# White-Label API Reseller
# --------------------------------------------------------------------------

def create_sub_account(owner_id: int, name: str, credits_limit: int = 1000,
                       rate_limit: int = 60, branding: dict = None) -> dict:
    key = "osh_" + secrets.token_urlsafe(24)
    with _conn() as conn:
        cur = conn.execute(
            "INSERT INTO sub_accounts (owner_id, name, api_key, credits_limit, credits_used, rate_limit, branding, active, created_at) "
            "VALUES (?,?,?,?,0,?,?,1,?)",
            (owner_id, name[:100], key, credits_limit, rate_limit,
             json.dumps(branding or {}), time.time()))
        sub_id = int(cur.lastrowid)
    return {"id": sub_id, "key": key, "name": name}


def list_sub_accounts(owner_id: int) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM sub_accounts WHERE owner_id = ? ORDER BY created_at DESC", (owner_id,)).fetchall()
    out = [dict(r) for r in rows]
    for row in out:
        row["created_str"] = datetime.datetime.fromtimestamp(
            row["created_at"]).strftime("%Y-%m-%d %H:%M")
        row["branding"] = _json_obj(row["branding"])
    return out


def get_sub_account(sub_id: int, owner_id: int) -> dict | None:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM sub_accounts WHERE id = ? AND owner_id = ?",
                           (sub_id, owner_id)).fetchone()
    if not row:
        return None
    out = dict(row)
    out["created_str"] = datetime.datetime.fromtimestamp(
        out["created_at"]).strftime("%Y-%m-%d %H:%M")
    out["branding"] = _json_obj(out["branding"])
    return out


def update_sub_account(sub_id: int, owner_id: int, **kwargs) -> int:
    allowed = {"name", "credits_limit", "rate_limit", "branding", "active"}
    fields = []
    values = []
    for k, v in kwargs.items():
        if k in allowed:
            fields.append(f"{k} = ?")
            if k == "branding":
                values.append(json.dumps(v))
            else:
                values.append(v)
    if not fields:
        return 0
    values.extend([sub_id, owner_id])
    with _conn() as conn:
        cur = conn.execute(f"UPDATE sub_accounts SET {', '.join(fields)} WHERE id = ? AND owner_id = ?", values)
        return cur.rowcount


def delete_sub_account(sub_id: int, owner_id: int) -> int:
    with _conn() as conn:
        conn.execute("DELETE FROM sub_account_usage WHERE sub_account_id = ?", (sub_id,))
        cur = conn.execute("DELETE FROM sub_accounts WHERE id = ? AND owner_id = ?", (sub_id, owner_id))
        return cur.rowcount


def get_sub_account_by_key(key: str) -> dict | None:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM sub_accounts WHERE api_key = ? AND active = 1",
                           (key,)).fetchone()
    return dict(row) if row else None


def try_use_sub_account_credits(sub_id: int, amount: int) -> bool:
    """Atomically count usage against a sub-account's cap."""
    with _conn() as conn:
        cur = conn.execute(
            "UPDATE sub_accounts SET credits_used = credits_used + ? "
            "WHERE id = ? AND active = 1 AND credits_used + ? <= credits_limit",
            (amount, sub_id, amount))
        return cur.rowcount > 0


def release_sub_account_credits(sub_id: int, amount: int) -> None:
    with _conn() as conn:
        conn.execute("UPDATE sub_accounts SET credits_used = MAX(0, credits_used - ?) "
                     "WHERE id = ?", (amount, sub_id))


def list_all_sub_accounts() -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT sa.*, u.email as owner_email FROM sub_accounts sa "
            "JOIN users u ON u.id = sa.owner_id ORDER BY sa.created_at DESC").fetchall()
    return [dict(r) for r in rows]


def record_sub_account_usage(sub_id: int, credits_spent: int, scans_count: int,
                             period_start: float, period_end: float) -> int:
    with _conn() as conn:
        cur = conn.execute(
            "INSERT INTO sub_account_usage (sub_account_id, credits_spent, scans_count, period_start, period_end) "
            "VALUES (?,?,?,?,?)",
            (sub_id, credits_spent, scans_count, period_start, period_end))
        return int(cur.lastrowid)


def get_sub_account_usage(sub_id: int, limit: int = 12) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM sub_account_usage WHERE sub_account_id = ? ORDER BY period_start DESC LIMIT ?",
            (sub_id, limit)).fetchall()
    out = [dict(r) for r in rows]
    for row in out:
        row["period_start_str"] = datetime.datetime.fromtimestamp(
            row["period_start"]).strftime("%Y-%m-%d")
        row["period_end_str"] = datetime.datetime.fromtimestamp(
            row["period_end"]).strftime("%Y-%m-%d")
    return out


# --------------------------------------------------------------------------
# Professional Report Service
# --------------------------------------------------------------------------

def count_cases(user_id: int) -> int:
    with _conn() as conn:
        return int(conn.execute("SELECT COUNT(*) FROM cases WHERE user_id = ?",
                                (user_id,)).fetchone()[0])


def create_report_template(user_id: int, name: str, template_json: dict) -> int:
    with _conn() as conn:
        cur = conn.execute(
            "INSERT INTO report_templates (user_id, name, template_json, is_default, created_at) "
            "VALUES (?,?,?,0,?)",
            (user_id, name[:100], json.dumps(template_json), time.time()))
        return int(cur.lastrowid)


def list_report_templates(user_id: int) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM report_templates WHERE user_id = ? ORDER BY created_at DESC", (user_id,)).fetchall()
    out = [dict(r) for r in rows]
    for row in out:
        row["created_str"] = datetime.datetime.fromtimestamp(
            row["created_at"]).strftime("%Y-%m-%d %H:%M")
        row["template_json"] = _json_obj(row["template_json"])
    return out


def get_report_template(template_id: int, user_id: int) -> dict | None:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM report_templates WHERE id = ? AND user_id = ?",
                           (template_id, user_id)).fetchone()
    if not row:
        return None
    out = dict(row)
    out["created_str"] = datetime.datetime.fromtimestamp(
        out["created_at"]).strftime("%Y-%m-%d %H:%M")
    out["template_json"] = _json_obj(out["template_json"])
    return out


def delete_report_template(template_id: int, user_id: int) -> int:
    with _conn() as conn:
        cur = conn.execute("DELETE FROM report_templates WHERE id = ? AND user_id = ?", (template_id, user_id))
        return cur.rowcount


def create_report_generation(user_id: int, scan_id: int, template_id: int | None,
                             format: str, file_path: str = "") -> int:
    with _conn() as conn:
        cur = conn.execute(
            "INSERT INTO report_generations (user_id, scan_id, template_id, format, file_path, status, created_at) "
            "VALUES (?,?,?,?,?,'completed',?)",
            (user_id, scan_id, template_id, format, file_path, time.time()))
        return int(cur.lastrowid)


def list_report_generations(user_id: int, limit: int = 50) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM report_generations WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
            (user_id, limit)).fetchall()
    out = [dict(r) for r in rows]
    for row in out:
        row["created_str"] = datetime.datetime.fromtimestamp(
            row["created_at"]).strftime("%Y-%m-%d %H:%M:%S")
    return out
