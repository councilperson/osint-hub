"""Profile enrichment.

The sweep tells you *where* a handle exists. This adds the useful details:
display name, avatar, bio, follower counts and location, taken from the
platform's own public API where one exists.

Only official, keyless, public endpoints are used. Each enrichment is optional:
if the API is down or the platform changed, the scan still reports the hit.
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any

import httpx

from .scanner import UA, _check_one  # noqa: F401  (shared UA constant)

API_HEADERS = {
    "User-Agent": UA,
    "Accept": "application/json",
    "Accept-Language": "en-US,en;q=0.9",
}


def _md5(text: str) -> str:
    import hashlib
    return hashlib.md5(text.strip().lower().encode("utf-8")).hexdigest()


def _gravatar(email: str) -> str:
    return f"https://www.gravatar.com/avatar/{_md5(email)}?d=identicon&s=96"


def _favicon(url: str) -> str:
    """The site's own favicon — no third-party image proxy involved."""
    m = re.match(r"https?://([^/]+)", url or "")
    if not m:
        return ""
    host = m.group(1).split("@")[-1].split(":")[0]
    if not host or "." not in host:
        return ""
    return f"https://{host}/favicon.ico"


def _clean(text: Any, limit: int = 240) -> str:
    if not text:
        return ""
    s = str(text)
    s = re.sub(r"<[^>]+>", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s[:limit]


# --- per-platform extractors ------------------------------------------------
# Each returns a dict of profile fields, or None if the platform has no
# keyless public API for this lookup.


async def _github(client: httpx.AsyncClient, handle: str) -> dict | None:
    r = await client.get(f"https://api.github.com/users/{handle}")
    if r.status_code != 200:
        return None
    d = r.json()
    if not isinstance(d, dict) or "login" not in d:
        return None
    return {
        "display_name": d.get("name") or d.get("login"),
        "avatar": d.get("avatar_url"),
        "meta": [
            ("Followers", f"{d.get('followers', 0):,}"),
            ("Repos", f"{d.get('public_repos', 0):,}"),
            ("Location", d.get("location") or "—"),
            ("Joined", (d.get("created_at") or "")[:10] or "—"),
            ("Bio", _clean(d.get("bio")) or "—"),
        ],
    }


async def _reddit(client: httpx.AsyncClient, handle: str) -> dict | None:
    r = await client.get(
        f"https://www.reddit.com/user/{handle}/about.json",
        headers={"User-Agent": UA},
    )
    if r.status_code != 200:
        return None
    d = r.json().get("data") or {}
    if not d.get("name"):
        return None
    return {
        "display_name": d.get("name"),
        "avatar": d.get("icon_img") or "",
        "meta": [
            ("Karma", f"{d.get('total_karma', 0):,}"),
            ("Cake day", (d.get("created_utc") and str(d.get("created_utc"))[:10]) or "—"),
            ("Link", d.get("subreddit", {}).get("title_displayed", "") or "—"),
        ],
    }


async def _bluesky(client: httpx.AsyncClient, handle: str) -> dict | None:
    actor = handle if handle.endswith(".bsky.social") else f"{handle}.bsky.social"
    r = await client.get(
        "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile",
        params={"actor": actor},
    )
    if r.status_code != 200:
        return None
    d = r.json()
    if not d.get("handle"):
        return None
    return {
        "display_name": d.get("displayName") or d.get("handle"),
        "avatar": d.get("avatar"),
        "meta": [
            ("Followers", f"{d.get('followersCount', 0):,}"),
            ("Following", f"{d.get('followsCount', 0):,}"),
            ("Posts", f"{d.get('postsCount', 0):,}"),
            ("Bio", _clean(d.get("description")) or "—"),
        ],
    }


async def _gitlab(client: httpx.AsyncClient, handle: str) -> dict | None:
    r = await client.get("https://gitlab.com/api/v4/users",
                         params={"username": handle})
    if r.status_code != 200:
        return None
    rows = r.json()
    if not isinstance(rows, list) or not rows:
        return None
    d = rows[0]
    return {
        "display_name": d.get("name") or d.get("username"),
        "avatar": d.get("avatar_url"),
        "meta": [
            ("Projects", str(d.get("projects_count", "—"))),
            ("Location", d.get("location") or "—"),
            ("Joined", (d.get("created_at") or "")[:10] or "—"),
            ("Bio", _clean(d.get("bio")) or "—"),
        ],
    }


async def _telegram(client: httpx.AsyncClient, handle: str) -> dict | None:
    """t.me exposes an OpenGraph preview for public channels/users."""
    r = await client.get(f"https://t.me/{handle}",
                         headers={"User-Agent": UA})
    if r.status_code != 200:
        return None
    body = r.text
    if "tgme_page_title" not in body:
        return None
    title = re.search(r'property="og:title" content="([^"]*)"', body)
    desc = re.search(r'property="og:description" content="([^"]*)"', body)
    pic = re.search(r'property="og:image" content="([^"]*)"', body)
    return {
        "display_name": _clean(title.group(1)) if title else handle,
        "avatar": (pic.group(1) if pic else ""),
        "meta": [("Bio", _clean(desc.group(1)) if desc else "—")],
    }


async def _mastodon(client: httpx.AsyncClient, handle: str) -> dict | None:
    r = await client.get(f"https://mastodon.social/api/v1/accounts/lookup",
                         params={"acct": handle})
    if r.status_code != 200:
        return None
    d = r.json()
    return {
        "display_name": d.get("display_name") or d.get("username"),
        "avatar": d.get("avatar"),
        "meta": [
            ("Followers", f"{d.get('followers_count', 0):,}"),
            ("Posts", f"{d.get('statuses_count', 0):,}"),
            ("Since", (d.get("created_at") or "")[:10] or "—"),
        ],
    }


async def _gravatar_enrich(client: httpx.AsyncClient, handle: str) -> dict | None:
    """Gravatar resolves by email — a handle only works if it is an address."""
    if "@" not in handle:
        return None
    r = await client.get(f"https://www.gravatar.com/{_md5(handle)}.json")
    if r.status_code != 200:
        return None
    d = r.json()
    if not d or not isinstance(d, list):
        return None
    p = d[0]
    return {
        "display_name": _clean(p.get("displayName")) or p.get("profileName") or handle,
        "avatar": _gravatar(handle),
        "meta": [
            ("Location", p.get("currentLocation") or "—"),
            ("About", _clean(p.get("aboutMe")) or "—"),
        ],
    }


EXTRACTORS = {
    "github": _github,
    "reddit": _reddit,
    "bluesky": _bluesky,
    "gitlab": _gitlab,
    "telegram": _telegram,
    "mastodon": _mastodon,
    "gravatar": _gravatar_enrich,
}

# Platform name -> extractor key, for the platforms in the corpus we enrich.
PLATFORM_KEYS = {
    "GitHub": "github",
    "GitLab": "gitlab",
    "Reddit": "reddit",
    "Bluesky": "bluesky",
    "Telegram": "telegram",
    "Mastodon": "mastodon",
    "Gravatar": "gravatar",
}


async def enrich(platform: str, handle: str, url: str = "") -> dict:
    """Return display name / avatar / metadata for a platform+handle.

    Never raises: enrichment is best-effort decoration on top of a hit.
    """
    out: dict = {}
    key = PLATFORM_KEYS.get(platform)
    if key:
        fn = EXTRACTORS[key]
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(6.0), headers=API_HEADERS, follow_redirects=True
            ) as client:
                data = await fn(client, handle)
            if data:
                out.update(data)
        except Exception:  # noqa: BLE001
            pass
    if not out.get("avatar"):
        out["avatar"] = _favicon(url)
    return out
