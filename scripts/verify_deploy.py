"""Check that a GitHub branch holds exactly the files in this folder.

    python scripts/verify_deploy.py councilperson/osint-hub main

The Nov 2026 Monitors/Reports outage was an incomplete upload: GitHub main was
missing app/templates/monitors.html, reports.html, monitor_detail.html and
reseller_account_detail.html, and still had old bulk.html, order.html and
pro.html. This compares git blob hashes of every tracked project file with the
branch on GitHub (public repo, no token needed) and lists what differs.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
INCLUDE = ("app", "tests", "scripts", "data")
TOP_FILES = ("Dockerfile", "requirements.txt", "requirements-dev.txt", "render.yaml",
             ".dockerignore", ".gitignore", "README.md", "CHANGES.md")
SKIP_PARTS = {"__pycache__", ".pytest_cache"}


def blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def local_files() -> dict[str, str]:
    out = {}
    for name in TOP_FILES:
        p = ROOT / name
        if p.is_file():
            out[name] = blob_sha(p.read_bytes())
    for top in INCLUDE:
        for p in (ROOT / top).rglob("*"):
            if p.is_file() and not SKIP_PARTS & set(p.parts) and p.suffix not in (".db", ".pyc"):
                rel = p.relative_to(ROOT).as_posix()
                out[rel] = blob_sha(p.read_bytes())
    return out


def remote_files(repo: str, ref: str) -> dict[str, str]:
    url = f"https://api.github.com/repos/{repo}/git/trees/{ref}?recursive=1"
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                               "User-Agent": "osint-hub-verify"})
    with urllib.request.urlopen(req, timeout=30) as r:
        tree = json.load(r)
    return {e["path"]: e["sha"] for e in tree["tree"] if e["type"] == "blob"}


def main() -> int:
    repo = sys.argv[1] if len(sys.argv) > 1 else "councilperson/osint-hub"
    ref = sys.argv[2] if len(sys.argv) > 2 else "main"
    local, remote = local_files(), remote_files(repo, ref)
    missing = sorted(set(local) - set(remote))
    differ = sorted(p for p in set(local) & set(remote) if local[p] != remote[p])
    extra = sorted(p for p in set(remote) - set(local)
                   if p.split("/")[0] in INCLUDE or p in TOP_FILES)
    for label, items in (("MISSING on GitHub", missing), ("DIFFERENT on GitHub", differ),
                         ("only on GitHub", extra)):
        for p in items:
            print(f"{label}: {p}")
    if not (missing or differ):
        print(f"OK: {repo}@{ref} matches all {len(local)} local files")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
