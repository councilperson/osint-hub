"""Off-box DB backup: encode/decode, gist + repo round-trips (GitHub mocked)."""
from __future__ import annotations

import base64
import json
import pathlib
import sqlite3
import sys

import httpx
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import backup  # noqa: E402


def _make_db(path: pathlib.Path, rows: int = 3) -> None:
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE IF NOT EXISTS t (v TEXT)")
    conn.executemany("INSERT INTO t VALUES (?)", [(f"row{i}",) for i in range(rows)])
    conn.commit()
    conn.close()


def _count(path: pathlib.Path) -> int:
    conn = sqlite3.connect(path)
    try:
        return conn.execute("SELECT COUNT(*) FROM t").fetchone()[0]
    finally:
        conn.close()


class FakeGitHub:
    def __init__(self):
        self.gist_files: dict = {}
        self.repo_file: dict | None = None  # {"content": text, "sha": str}
        self.writes = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer tok"
        path = request.url.path
        if path.startswith("/gists/"):
            if request.method == "GET":
                return httpx.Response(200, json={"files": {
                    k: {"content": v, "truncated": False} for k, v in self.gist_files.items()}})
            if request.method == "PATCH":
                self.writes += 1
                for k, v in json.loads(request.content)["files"].items():
                    self.gist_files[k] = v["content"]
                return httpx.Response(200, json={})
        if path.startswith("/repos/"):
            if request.method == "GET":
                if not self.repo_file:
                    return httpx.Response(404, json={})
                if "raw" in request.headers.get("accept", ""):
                    return httpx.Response(200, text=self.repo_file["content"])
                return httpx.Response(200, json={"sha": self.repo_file["sha"]})
            if request.method == "PUT":
                body = json.loads(request.content)
                if self.repo_file:
                    assert body.get("sha") == self.repo_file["sha"]
                self.writes += 1
                self.repo_file = {"content": base64.b64decode(body["content"]).decode(),
                                  "sha": f"sha{self.writes}"}
                return httpx.Response(200, json={})
        return httpx.Response(500)


@pytest.fixture
def gh(monkeypatch):
    fake = FakeGitHub()
    real = backup._client

    def client(c):
        cl = real(c)
        return httpx.Client(transport=httpx.MockTransport(fake.handler),
                            headers=cl.headers, timeout=5)
    monkeypatch.setattr(backup, "_client", client)
    monkeypatch.setattr(backup, "_last_digest", None)
    for k in ("BACKUP_GITHUB_REPO", "BACKUP_GIST_ID", "BACKUP_PATH", "BACKUP_BRANCH"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("BACKUP_GITHUB_TOKEN", "tok")
    return fake


def test_disabled_is_noop(tmp_path, monkeypatch):
    for k in ("BACKUP_GITHUB_TOKEN", "BACKUP_GITHUB_REPO", "BACKUP_GIST_ID"):
        monkeypatch.delenv(k, raising=False)
    db = tmp_path / "x.db"
    _make_db(db)
    assert not backup.enabled()
    assert backup.push(db) is False
    assert backup.restore(tmp_path / "missing.db") is False


def test_encode_decode_roundtrip(tmp_path):
    db = tmp_path / "a.db"
    _make_db(db, 5)
    raw = backup.snapshot_bytes(db)
    assert raw.startswith(backup.SQLITE_MAGIC)
    assert backup.decode(backup.encode(raw)) == raw
    with pytest.raises(Exception):
        backup.decode(base64.b64encode(b"not gzip").decode())


@pytest.mark.parametrize("backend", ["gist", "repo"])
def test_push_then_restore(tmp_path, monkeypatch, gh, backend):
    if backend == "gist":
        monkeypatch.setenv("BACKUP_GIST_ID", "abc")
    else:
        monkeypatch.setenv("BACKUP_GITHUB_REPO", "me/private-backup")
    db = tmp_path / "live.db"
    _make_db(db, 4)
    assert backup.push(db) is True
    assert backup.push(db) is False          # unchanged -> no write
    _make_db(db, 1)                          # change -> new write (repo uses sha)
    assert backup.push(db) is True
    assert gh.writes == 2

    fresh = tmp_path / "wiped" / "osint.db"  # simulates a wiped Render disk
    assert backup.restore(fresh) is True
    assert _count(fresh) == 5
    # an existing local DB is never overwritten unless forced
    assert backup.restore(fresh) is False


def test_restore_with_no_remote_and_bad_network(tmp_path, monkeypatch, gh):
    monkeypatch.setenv("BACKUP_GITHUB_REPO", "me/empty")
    assert backup.restore(tmp_path / "n.db") is False
    monkeypatch.setattr(gh, "handler", lambda r: httpx.Response(500))
    db = tmp_path / "y.db"
    _make_db(db)
    assert backup.push(db) is False          # failure is swallowed, never raises


def test_lifespan_pushes_on_shutdown(tmp_path, monkeypatch, gh):
    import asyncio
    monkeypatch.setenv("BACKUP_GIST_ID", "abc")
    db = tmp_path / "l.db"
    _make_db(db, 2)

    async def run():
        async with backup.lifespan_for(lambda: db)(None):
            pass
    asyncio.run(run())
    assert gh.writes == 1 and gh.gist_files


def test_ssrf_guard_blocks_internal_hosts():
    from app import services
    for url in ("http://127.0.0.1/", "http://localhost:8000/", "http://169.254.169.254/latest/",
                "http://10.0.0.5/", "http://[::1]/"):
        with pytest.raises(services.LookupError):
            services._assert_public_host(url)
