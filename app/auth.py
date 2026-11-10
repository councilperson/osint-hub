"""Accounts, sessions and API keys.

Passwords are hashed with PBKDF2-HMAC-SHA256 (stdlib only) and a per-user
random salt. Session tokens are random 256-bit values stored hashed in the
database, so a database copy does not hand out live sessions.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from typing import Any

from . import db, plans

PBKDF2_ROUNDS = 260_000
SESSION_COOKIE = "osint_session"
SESSION_TTL = 60 * 60 * 24 * 30  # 30 days
API_KEY_PREFIX = "osh_"


class AuthError(Exception):
    """Raised when credentials are invalid or an account already exists."""


# --- passwords ------------------------------------------------------------

def hash_password(password: str, *, rounds: int = PBKDF2_ROUNDS) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return f"pbkdf2_sha256${rounds}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, rounds, salt_hex, digest_hex = encoded.split("$", 3)
    except ValueError:
        return False
    if algo != "pbkdf2_sha256":
        return False
    try:
        rounds_i = int(rounds)
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds_i)
    return hmac.compare_digest(digest.hex(), digest_hex)


# --- users ----------------------------------------------------------------

def normalise_email(email: str) -> str:
    return email.strip().lower()


def create_user(email: str, password: str) -> dict:
    email = normalise_email(email)
    if "@" not in email or len(email) < 5 or len(email) > 190:
        raise AuthError("Enter a valid email address.")
    if len(password) < 8:
        raise AuthError("Use a password of at least 8 characters.")
    if len(password) > 512:
        raise AuthError("That password is too long.")
    if db.get_user_by_email(email):
        raise AuthError("An account with that email already exists.")
    user = db.insert_user(email, hash_password(password), plans.DEFAULT_PLAN)
    return user


def authenticate(email: str, password: str) -> dict:
    row = db.get_user_by_email(normalise_email(email))
    if not row:
        # Spend the same time as a real check so timing does not leak whether
        # the address exists.
        hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), os.urandom(16), PBKDF2_ROUNDS)
        raise AuthError("That email and password do not match an account.")
    if not verify_password(password, row["password_hash"]):
        raise AuthError("That email and password do not match an account.")
    return row


# --- sessions -------------------------------------------------------------

def _token_digest(token: str) -> str:
    return hashlib.sha256(("osint-session|" + token).encode("utf-8")).hexdigest()


def start_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    db.insert_session(_token_digest(token), user_id, time.time() + SESSION_TTL)
    return token


def end_session(token: str) -> None:
    if token:
        db.delete_session(_token_digest(token))


def user_for_token(token: str) -> dict | None:
    if not token:
        return None
    row = db.user_for_session(_token_digest(token))
    if not row:
        return None
    if float(row.get("expires_at") or 0) < time.time():
        db.delete_session(_token_digest(token))
        return None
    return row


# --- API keys -------------------------------------------------------------

def create_api_key(user_id: int, name: str = "default") -> dict:
    raw = API_KEY_PREFIX + secrets.token_urlsafe(24)
    key_id = db.insert_api_key(user_id, raw, name.strip()[:60] or "default", time.time())
    return {"id": key_id, "key": raw, "name": name.strip()[:60] or "default"}


def user_for_api_key(raw: str) -> dict | None:
    if not raw or not raw.startswith(API_KEY_PREFIX):
        return None
    row = db.user_for_api_key(raw)
    if row:
        db.touch_api_key(row["api_key_id"], time.time())
    return row


# --- helpers --------------------------------------------------------------

def effective_plan(user: dict | None) -> str:
    if not user:
        return plans.DEFAULT_PLAN
    plan = user.get("plan") or plans.DEFAULT_PLAN
    return plan if plan in plans.PLANS else plans.DEFAULT_PLAN


def is_pro(user: dict | None) -> bool:
    return plans.is_pro(effective_plan(user))


def plan_of(user: dict | None) -> dict:
    return plans.get_plan(effective_plan(user))


def credits_of(user: dict | None) -> int:
    if not user:
        return 0
    return int(user.get("credits") or 0)


def spend_credits(user: dict | None, amount: int, reason: str, ref: str = "") -> int:
    """Deduct credits, returning the new balance. Never goes below zero."""
    if not user:
        return 0
    amount = max(0, int(amount))
    if amount == 0:
        return credits_of(user)
    new = db.adjust_credits(user["id"], -amount, reason, ref)
    return new


def grant_credits(user_id: int, amount: int, reason: str, ref: str = "") -> int:
    return db.adjust_credits(user_id, abs(int(amount)), reason, ref)
