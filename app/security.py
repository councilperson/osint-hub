"""Small, dependency-free security helpers shared by the routes.

* cookies get ``Secure`` automatically when the request arrived over HTTPS
  (directly or via a proxy that sets ``X-Forwarded-Proto``, as Render does);
* a same-origin check blocks cross-site form posts (CSRF) on top of the
  ``SameSite=Lax`` cookies;
* an in-memory sliding-window limiter slows down password guessing;
* ``safe_url`` keeps ``javascript:`` and similar links out of rendered pages;
* ``production_warnings`` flags default secrets on a public deployment.
"""
from __future__ import annotations

import logging
import os
import threading
import time
import urllib.parse
from collections import deque

from fastapi import Request
from fastapi.responses import Response

log = logging.getLogger("osint.security")

DEFAULT_ADMIN_TOKEN = "admin12345"
DEFAULT_SECRET_KEY = "osint-hub-local-secret"

SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


# --------------------------------------------------------------------------
# environment
# --------------------------------------------------------------------------

def is_public_deploy() -> bool:
    """True on Render (it sets RENDER=true) or when OSINT_PUBLIC is set."""
    return bool(os.environ.get("RENDER") or os.environ.get("OSINT_PUBLIC"))


def admin_token() -> str:
    return os.environ.get("ADMIN_TOKEN", DEFAULT_ADMIN_TOKEN)


def secret_key() -> str:
    return os.environ.get("SECRET_KEY", DEFAULT_SECRET_KEY)


def admin_token_is_default() -> bool:
    return admin_token() == DEFAULT_ADMIN_TOKEN


def admin_disabled() -> bool:
    """The console is switched off on a public host that still uses the
    published default token — anyone could otherwise sign in."""
    return is_public_deploy() and (admin_token_is_default() or len(admin_token()) < 12)


def production_warnings() -> list[str]:
    out = []
    if not is_public_deploy():
        return out
    if admin_token_is_default():
        out.append("ADMIN_TOKEN is the default value — the admin console is DISABLED "
                   "until you set a strong ADMIN_TOKEN.")
    elif len(admin_token()) < 12:
        out.append("ADMIN_TOKEN is shorter than 12 characters — the admin console is "
                   "DISABLED until you set a longer one.")
    if secret_key() == DEFAULT_SECRET_KEY:
        out.append("SECRET_KEY is the default value — set a long random SECRET_KEY.")
    if not os.environ.get("OWNER_PASSWORD"):
        out.append("OWNER_PASSWORD is not set — the owner account and its panel are off.")
    return out


def log_production_warnings() -> None:
    for w in production_warnings():
        log.error("SECURITY: %s", w)


# --------------------------------------------------------------------------
# HTTPS / cookies
# --------------------------------------------------------------------------

def is_https(request: Request) -> bool:
    proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    return proto == "https" or request.url.scheme == "https"


def set_cookie(resp: Response, request: Request, name: str, value: str,
               max_age: int) -> None:
    resp.set_cookie(name, value, max_age=max_age, httponly=True, samesite="lax",
                    secure=is_https(request), path="/")


def delete_cookie(resp: Response, request: Request, name: str) -> None:
    resp.delete_cookie(name, path="/", httponly=True, samesite="lax",
                       secure=is_https(request))


# --------------------------------------------------------------------------
# CSRF: same-origin check for state-changing requests
# --------------------------------------------------------------------------

def _host_of(value: str) -> str:
    try:
        return (urllib.parse.urlsplit(value).netloc or "").lower()
    except ValueError:
        return ""


def request_host(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-host", "").split(",")[0].strip()
    return (fwd or request.headers.get("host", "")).lower()


def same_origin(request: Request) -> bool:
    """Browsers send Origin (or at least Referer) on cross-site POSTs. If
    either is present it must point at this host. Requests with neither
    (curl, API clients, the test client) carry no ambient browser cookies
    from another site, so they are allowed."""
    if request.method in SAFE_METHODS:
        return True
    origin = request.headers.get("origin")
    if origin is not None:
        if origin == "null":
            return False
        return _host_of(origin) == request_host(request)
    referer = request.headers.get("referer")
    if referer:
        return _host_of(referer) == request_host(request)
    return True


# --------------------------------------------------------------------------
# rate limiting (per process, in memory — fine for one small instance)
# --------------------------------------------------------------------------

class RateLimiter:
    def __init__(self, limit: int, window: float) -> None:
        self.limit = limit
        self.window = window
        self._hits: dict[str, deque] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int | None = None) -> bool:
        """Record an attempt. Returns False when the key is over the limit."""
        now = time.monotonic()
        cap = self.limit if limit is None else limit
        with self._lock:
            q = self._hits.setdefault(key, deque())
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= cap:
                return False
            q.append(now)
            if len(self._hits) > 10_000:  # keep memory bounded
                for k in [k for k, v in self._hits.items() if not v][:5000]:
                    self._hits.pop(k, None)
            return True

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._hits.clear()


def client_ip(request: Request) -> str:
    # uvicorn runs with --proxy-headers on Render, so client.host is the real
    # visitor address taken from X-Forwarded-For.
    return (request.client.host if request.client else "") or "unknown"


# --------------------------------------------------------------------------
# output hardening
# --------------------------------------------------------------------------

_SAFE_SCHEMES = {"http", "https", "mailto", "tel"}


def safe_url(value) -> str:
    """Return the URL if its scheme is harmless, else '#'. Used as a Jinja filter."""
    text = str(value or "").strip()
    if not text:
        return "#"
    scheme = text.split(":", 1)[0].lower() if ":" in text else ""
    if scheme and scheme not in _SAFE_SCHEMES:
        return "#"
    if not scheme and not text.startswith("/"):
        return "#"
    return text


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


def add_security_headers(request: Request, resp: Response) -> None:
    for k, v in SECURITY_HEADERS.items():
        resp.headers.setdefault(k, v)
    if is_https(request):
        resp.headers.setdefault("Strict-Transport-Security",
                                "max-age=15552000; includeSubDomains")
