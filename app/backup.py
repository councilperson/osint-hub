"""Off-box SQLite persistence for hosts with an ephemeral disk (Render free tier).

On startup the DB is restored from GitHub if the local file is missing, and while
the app runs a consistent snapshot (sqlite3 backup API -> gzip) is pushed back
every BACKUP_INTERVAL seconds when it changed, plus once more on shutdown
(uvicorn turns Render's SIGTERM into a lifespan shutdown).

Pick ONE backend via env vars (everything no-ops if none is set):
  BACKUP_GITHUB_TOKEN   token with access to the target below (required)
  BACKUP_GITHUB_REPO    "owner/name" of a PRIVATE repo  (recommended; Contents: read/write)
  BACKUP_GIST_ID        id of a secret gist             (alternative; Gists: read/write)
Optional:
  BACKUP_PATH           file name in the repo/gist (default osint-db.sqlite.gz.b64)
  BACKUP_BRANCH         repo branch (default: the repo's default branch)
  BACKUP_INTERVAL       seconds between pushes (default 300, minimum 30)
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import gzip
import hashlib
import logging
import os
import sqlite3
import tempfile
import threading
from pathlib import Path

import httpx

log = logging.getLogger("osint.backup")
API = "https://api.github.com"
SQLITE_MAGIC = b"SQLite format 3\x00"
_lock = threading.Lock()
_last_digest: str | None = None


def _cfg() -> dict:
    env = os.environ.get
    return {
        "token": env("BACKUP_GITHUB_TOKEN", "").strip(),
        "repo": env("BACKUP_GITHUB_REPO", "").strip().strip("/"),
        "gist": env("BACKUP_GIST_ID", "").strip(),
        "path": env("BACKUP_PATH", "").strip() or "osint-db.sqlite.gz.b64",
        "branch": env("BACKUP_BRANCH", "").strip(),
        "interval": max(30, int(env("BACKUP_INTERVAL", "300") or 300)),
    }


def enabled() -> bool:
    c = _cfg()
    return bool(c["token"] and (c["repo"] or c["gist"]))


def _client(c: dict) -> httpx.Client:
    return httpx.Client(timeout=30, headers={
        "Authorization": f"Bearer {c['token']}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "osint-hub-backup",
    })


# ---------------------------------------------------------------- encoding

def snapshot_bytes(db_path: Path) -> bytes:
    """A transactionally consistent copy of the live DB, as raw SQLite bytes."""
    fd, tmp = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        src = sqlite3.connect(str(db_path))
        dst = sqlite3.connect(tmp)
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        return Path(tmp).read_bytes()
    finally:
        with contextlib.suppress(OSError):
            os.remove(tmp)


def encode(raw: bytes) -> str:
    return base64.b64encode(gzip.compress(raw, mtime=0)).decode("ascii")


def decode(text: str) -> bytes:
    raw = gzip.decompress(base64.b64decode("".join(text.split())))
    if not raw.startswith(SQLITE_MAGIC):
        raise ValueError("backup is not a SQLite database")
    return raw


# ---------------------------------------------------------------- remote I/O

def _fetch_remote(c: dict) -> tuple[str | None, str | None]:
    """Return (encoded_text, repo_sha). (None, None) if nothing stored yet."""
    with _client(c) as cl:
        if c["repo"]:
            params = {"ref": c["branch"]} if c["branch"] else None
            url = f"{API}/repos/{c['repo']}/contents/{c['path']}"
            r = cl.get(url, params=params)
            if r.status_code == 404:
                return None, None
            r.raise_for_status()
            sha = r.json().get("sha")
            raw = cl.get(url, params=params,
                         headers={"Accept": "application/vnd.github.raw+json"})
            raw.raise_for_status()
            return raw.text, sha
        r = cl.get(f"{API}/gists/{c['gist']}")
        r.raise_for_status()
        f = (r.json().get("files") or {}).get(c["path"])
        if not f:
            return None, None
        if f.get("truncated") and f.get("raw_url"):
            raw = cl.get(f["raw_url"])
            raw.raise_for_status()
            return raw.text, None
        return f.get("content") or None, None


def _push_remote(c: dict, text: str) -> None:
    with _client(c) as cl:
        if c["repo"]:
            _, sha = _fetch_remote(c)
            body = {"message": "db snapshot",
                    "content": base64.b64encode(text.encode()).decode()}
            if sha:
                body["sha"] = sha
            if c["branch"]:
                body["branch"] = c["branch"]
            r = cl.put(f"{API}/repos/{c['repo']}/contents/{c['path']}", json=body)
        else:
            r = cl.patch(f"{API}/gists/{c['gist']}",
                         json={"files": {c["path"]: {"content": text}}})
        r.raise_for_status()


# ---------------------------------------------------------------- public API

def restore(db_path: Path, force: bool = False) -> bool:
    """Pull the stored DB into db_path if the local file is missing. Never raises."""
    global _last_digest
    if not enabled():
        return False
    db_path = Path(db_path)
    if db_path.exists() and db_path.stat().st_size > 0 and not force:
        return False
    try:
        text, _ = _fetch_remote(_cfg())
        if not text:
            log.info("backup: no remote snapshot yet")
            return False
        raw = decode(text)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = db_path.with_suffix(db_path.suffix + ".restore")
        tmp.write_bytes(raw)
        os.replace(tmp, db_path)
        _last_digest = hashlib.sha256(raw).hexdigest()
        log.warning("backup: restored %d bytes into %s", len(raw), db_path)
        return True
    except Exception as exc:  # noqa: BLE001 - never block startup
        log.error("backup: restore failed: %s", exc)
        return False


def push(db_path: Path) -> bool:
    """Upload a snapshot if the DB changed since the last push. Never raises."""
    global _last_digest
    if not enabled() or not Path(db_path).exists():
        return False
    with _lock:
        try:
            raw = snapshot_bytes(Path(db_path))
            digest = hashlib.sha256(raw).hexdigest()
            if digest == _last_digest:
                return False
            _push_remote(_cfg(), encode(raw))
            _last_digest = digest
            log.info("backup: pushed %d bytes", len(raw))
            return True
        except Exception as exc:  # noqa: BLE001
            log.error("backup: push failed: %s", exc)
            return False


def lifespan_for(db_path_fn):
    """Build a FastAPI lifespan that pushes periodically and on shutdown."""
    @contextlib.asynccontextmanager
    async def lifespan(app):
        task = None
        if enabled():
            interval = _cfg()["interval"]

            async def loop():
                while True:
                    await asyncio.sleep(interval)
                    await asyncio.to_thread(push, db_path_fn())
            task = asyncio.create_task(loop())
        try:
            yield
        finally:
            if task:
                task.cancel()
                with contextlib.suppress(BaseException):
                    await task
                await asyncio.to_thread(push, db_path_fn())
    return lifespan
