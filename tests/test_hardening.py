"""Regression tests for the Nov 2026 security / bug-fix pass.

Each test pins one fix so it can't silently come back.
"""
from __future__ import annotations

import socket

import pytest
from fastapi.testclient import TestClient

from test_app import (  # noqa: F401  (shares the temp DB + helpers)
    ADMIN_PATH, admin_client, login, make_user, order_id_from, top_up,
)
from app import auth, db, monitor, plans, pro_reports, scanner, security, services
from app import main as main_mod
from app.main import app


def _public_dns(monkeypatch, ip: str = "93.184.216.34") -> None:
    """Pretend every host resolves to a public IP (the sandbox DNS doesn't)."""
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda host, *a, **k: [(2, 1, 6, "", (ip, 0))])


def _fake_hits(monkeypatch, fail: bool = False) -> None:
    async def fake_lookup(kind, value, pro=True):
        if fail:
            raise RuntimeError("upstream exploded")
        return [scanner.Hit("x", "X", kind, "hit", "https://example.com/x", "", 1)]
    monkeypatch.setattr(scanner, "run_lookup", fake_lookup)


# --- security ---------------------------------------------------------------

def test_cross_site_post_is_blocked() -> None:
    c = login("csrf@example.com")
    r = c.post("/notes", data={"tool": "t", "target": "x", "summary": "s"},
               headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    r = c.post("/notes", data={"tool": "t", "target": "x", "summary": "s"},
               headers={"Referer": "https://evil.example/page"})
    assert r.status_code == 403
    # same-origin form posts still work
    r = c.post("/notes", data={"tool": "t", "target": "x", "summary": "ok"},
               headers={"Origin": "http://testserver"}, follow_redirects=False)
    assert r.status_code in (200, 303)


def test_session_cookie_is_httponly_and_secure_behind_https() -> None:
    make_user("cookie@example.com")
    c = TestClient(app, base_url="https://testserver")
    r = c.post("/login", data={"email": "cookie@example.com",
                               "password": "testpassword123"}, follow_redirects=False)
    cookie = r.headers.get("set-cookie", "").lower()
    assert "httponly" in cookie and "secure" in cookie and "samesite=lax" in cookie


def test_security_headers_present() -> None:
    r = TestClient(app).get("/")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "referrer-policy" in r.headers


def test_openapi_schema_not_public() -> None:
    assert TestClient(app).get("/openapi.json").status_code == 404


def test_login_is_rate_limited() -> None:
    make_user("brute@example.com")
    c = TestClient(app)
    codes = [c.post("/login", data={"email": "brute@example.com", "password": "wrong"}).status_code
             for _ in range(12)]
    assert codes[-1] == 429


def test_safe_next_rejects_offsite_redirects() -> None:
    for bad in ("//evil.com", "https://evil.com", "/\\evil.com", "\\\\evil", "/ok\r\nX: y"):
        assert main_mod._safe_next(bad) == "/"
    assert main_mod._safe_next("/account") == "/account"


def test_safe_url_filter() -> None:
    assert security.safe_url("javascript:alert(1)") == "#"
    assert security.safe_url(" JaVaScRiPt:alert(1)") == "#"
    assert security.safe_url("data:text/html,x") == "#"
    assert security.safe_url("https://ok.example/x") == "https://ok.example/x"
    assert security.safe_url("/local") == "/local"


def test_ssrf_guard_blocks_internal_hosts(monkeypatch) -> None:
    for ip in ("127.0.0.1", "10.0.0.5", "169.254.169.254", "::1"):
        _public_dns(monkeypatch, ip)
        with pytest.raises(services.LookupError):
            services.assert_public_url("http://whatever.example/")
    _public_dns(monkeypatch)
    services.assert_public_url("https://example.com/")
    with pytest.raises(services.LookupError):
        services.assert_public_url("file:///etc/passwd")


def test_admin_disabled_on_public_deploy_with_default_token(monkeypatch) -> None:
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("ADMIN_TOKEN", "admin12345")
    assert security.admin_disabled() is True
    monkeypatch.setenv("ADMIN_TOKEN", "a-long-random-admin-token-123")
    assert security.admin_disabled() is False
    monkeypatch.delenv("RENDER")
    monkeypatch.setenv("ADMIN_TOKEN", "admin12345")
    assert security.admin_disabled() is False      # local dev keeps working


def test_password_hash_rehash_and_round_bounds() -> None:
    h = auth.hash_password("correct horse battery")
    assert auth.verify_password("correct horse battery", h)
    assert not auth.verify_password("nope", h)
    # absurd round counts are refused instead of burning CPU
    algo, rounds, rest = h.split("$", 2)
    assert not auth.verify_password("correct horse battery", f"{algo}$99999999999${rest}")


# --- payments / credits -------------------------------------------------------

def test_anonymous_cannot_enable_site_wide_pro() -> None:
    TestClient(app).post("/pro/purchase", data={"plan": "pro"})
    assert db.has_pro() is False


def test_order_page_needs_owner_or_token() -> None:
    buyer = login("idor-buyer@example.com")
    r = buyer.post("/checkout", data={"plan": "pro", "crypto": "ETH"}, follow_redirects=False)
    loc = r.headers["location"]
    order_id = order_id_from(loc)
    assert "?k=" in loc
    assert login("idor-other@example.com").get(f"/checkout/{order_id}").status_code == 404
    assert TestClient(app).get(loc).status_code == 200          # guest link with token
    assert TestClient(app).get(f"/checkout/{order_id}?k=wrong").status_code == 404


def test_txid_cannot_overwrite_a_closed_order() -> None:
    c = login("closed@example.com")
    r = c.post("/checkout", data={"plan": "pro", "crypto": "BTC"}, follow_redirects=False)
    order_id = order_id_from(r.headers["location"])
    db.set_order_status(order_id, "approved") if hasattr(db, "set_order_status") \
        else db.approve_order_once(order_id)
    c.post(f"/checkout/{order_id}/txid", data={"txid": "0xdeadbeef"})
    assert db.get_order(order_id)["status"] == "approved"
    assert db.get_order(order_id)["txid"] != "0xdeadbeef"


def test_order_is_approved_only_once() -> None:
    buyer = make_user("once@example.com")
    order_id = db.create_order(buyer["id"], buyer["email"], "pro", "ETH",
                               "0x" + "b" * 40, "0.01 ETH")
    admin = admin_client()
    admin.post(f"{ADMIN_PATH}/orders/{order_id}/approve")
    after_first = db.get_user(buyer["id"])["credits"]
    admin.post(f"{ADMIN_PATH}/orders/{order_id}/approve")
    assert db.get_user(buyer["id"])["credits"] == after_first


def test_try_spend_is_atomic_and_never_negative() -> None:
    user = make_user("atomic@example.com")
    db.adjust_credits(user["id"], -db.get_user(user["id"])["credits"], "drain", "")
    top_up(user["id"], 5)
    assert db.try_spend_credits(user["id"], 3, "t") is not None
    assert db.try_spend_credits(user["id"], 3, "t") is None
    assert db.get_user(user["id"])["credits"] == 2
    db.adjust_credits(user["id"], -100, "big debit", "")
    assert db.get_user(user["id"])["credits"] == 0


def test_auto_detected_pro_type_is_still_gated(monkeypatch) -> None:
    _fake_hits(monkeypatch)
    user = make_user("autodetect@example.com")
    top_up(user["id"], 50)
    c = login("autodetect@example.com")
    # an IPv4 address auto-detects as the Pro-only "ip" type
    r = c.get("/api/scan", params={"q": "8.8.8.8"})
    assert r.status_code == 403
    assert r.json()["error"] == "upgrade_required"


def test_failed_search_refunds_credits(monkeypatch) -> None:
    _fake_hits(monkeypatch, fail=True)
    user = make_user("refund@example.com")
    top_up(user["id"], 50)
    c = login("refund@example.com")
    c.get("/account")                      # let the daily allowance land first
    before = db.get_user(user["id"])["credits"]
    r = c.get("/api/scan", params={"q": "someone@example.com", "type": "email"})
    assert r.status_code >= 500 or r.status_code == 502
    assert db.get_user(user["id"])["credits"] == before


def test_owner_credits_are_granted_only_once(monkeypatch) -> None:
    monkeypatch.setenv("OWNER_EMAIL", "boss@example.com")
    monkeypatch.setenv("OWNER_PASSWORD", "owner-password-123")
    main_mod._bootstrap_owner()
    owner = db.get_user_by_email("boss@example.com")
    first = owner["credits"]
    assert owner["plan"] == "team"
    main_mod._bootstrap_owner()
    main_mod._bootstrap_owner()
    assert db.get_user_by_email("boss@example.com")["credits"] == first


def test_owner_email_squatter_is_locked_out(monkeypatch) -> None:
    make_user("squat@example.com")                       # registered with TEST_PASSWORD
    monkeypatch.setenv("OWNER_EMAIL", "squat@example.com")
    monkeypatch.setenv("OWNER_PASSWORD", "real-owner-password")
    main_mod._bootstrap_owner()
    with pytest.raises(auth.AuthError):
        auth.authenticate("squat@example.com", "testpassword123")
    assert auth.authenticate("squat@example.com", "real-owner-password")


def test_no_owner_panel_without_owner_password(monkeypatch) -> None:
    monkeypatch.setenv("OWNER_EMAIL", "noowner@example.com")
    monkeypatch.delenv("OWNER_PASSWORD", raising=False)
    user = make_user("noowner@example.com")
    assert main_mod._is_owner(user) is False


# --- reseller -----------------------------------------------------------------

def test_reseller_sub_account_spends_owner_credits(monkeypatch) -> None:
    _fake_hits(monkeypatch)
    owner = make_user("reseller-owner@example.com", plan="pro")
    db.adjust_credits(owner["id"], -db.get_user(owner["id"])["credits"], "drain", "")
    top_up(owner["id"], 2)
    sub = db.create_sub_account(owner["id"], "client", credits_limit=1000, rate_limit=60)
    c = TestClient(app)
    hdr = {"X-API-Key": sub["key"]}
    cost = plans.type_cost("email")
    ok = 0
    for _ in range(5):
        r = c.get("/reseller/api/v1/scan", params={"q": "a@example.com", "type": "email"},
                  headers=hdr)
        if r.status_code == 200:
            ok += 1
        else:
            assert r.status_code == 402
    assert ok == 2 // cost
    assert db.get_user(owner["id"])["credits"] == 2 - ok * cost


def test_reseller_key_from_free_owner_is_refused() -> None:
    owner = make_user("reseller-free@example.com")
    sub = db.create_sub_account(owner["id"], "client")
    r = TestClient(app).get("/reseller/api/v1/scan", params={"q": "a@example.com"},
                            headers={"X-API-Key": sub["key"]})
    assert r.status_code == 403


# --- monitors -----------------------------------------------------------------

def test_monitor_destination_validation(monkeypatch) -> None:
    _public_dns(monkeypatch)
    assert monitor.validate_destination("webhook", {"webhook_url": "https://example.com/h"}) is None
    assert monitor.validate_destination("webhook", {"url": "https://example.com/h"}) is None
    assert "https" in monitor.validate_destination("webhook", {"webhook_url": "http://example.com/h"})
    assert monitor.validate_destination("discord", {"discord_webhook_url": "https://evil.com/api/webhooks/1"})
    assert monitor.validate_destination(
        "discord", {"discord_webhook_url": "https://discord.com/api/webhooks/1/abc"}) is None
    _public_dns(monkeypatch, "127.0.0.1")
    assert monitor.validate_destination("webhook", {"webhook_url": "https://example.com/h"})


def test_monitors_need_pro() -> None:
    c = login("monitor-free@example.com")
    before = db.count_monitors(db.get_user_by_email("monitor-free@example.com")["id"])
    c.post("/monitors", data={"name": "m", "target": "someone", "target_type": "username",
                              "frequency": "daily", "channel": "email", "channel_config": "{}"})
    assert db.count_monitors(db.get_user_by_email("monitor-free@example.com")["id"]) == before


def test_internal_runner_needs_secret(monkeypatch) -> None:
    monkeypatch.setenv("MONITOR_RUNNER_SECRET", "s3cret-runner")
    c = TestClient(app)
    assert c.post("/internal/run-monitors").status_code == 401
    assert c.post("/internal/run-monitors", headers={"X-Internal-Secret": "wrong"}).status_code == 401


# --- privacy -------------------------------------------------------------------

def test_notes_and_history_are_per_account() -> None:
    a = login("notes-a@example.com")
    a.post("/notes", data={"tool": "t", "target": "secret-target-a", "summary": "private-a"})
    b = login("notes-b@example.com")
    assert "private-a" not in b.get("/notes").text
    assert "private-a" not in TestClient(app).get("/notes").text
    assert "private-a" in a.get("/notes").text


def test_cases_limit_is_enforced() -> None:
    user = make_user("cases-limit@example.com")
    limit = plans.PLANS[user["plan"]].get("cases") or plans.PLANS[user["plan"]].get("max_cases")
    if not isinstance(limit, int) or limit <= 0 or limit > 50:
        pytest.skip("plan has no small case limit")
    c = login("cases-limit@example.com")
    for i in range(limit + 2):
        c.post("/cases", data={"name": f"case {i}", "description": ""})
    assert db.count_cases(user["id"]) == limit


# --- admin / owner panel ----------------------------------------------------------

def test_admin_actions_redirect_back_to_console() -> None:
    user = make_user("prg@example.com")
    admin = admin_client()
    r = admin.post(f"{ADMIN_PATH}/users/{user['id']}/credits", data={"amount": "5"},
                   follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"].startswith(ADMIN_PATH)


def test_owner_panel_routes_exist(monkeypatch) -> None:
    monkeypatch.setenv("OWNER_EMAIL", "panel-owner@example.com")
    monkeypatch.setenv("OWNER_PASSWORD", "panel-owner-pass-1")
    main_mod._bootstrap_owner()
    c = TestClient(app)
    r = c.post("/login", data={"email": "panel-owner@example.com",
                               "password": "panel-owner-pass-1"}, follow_redirects=False)
    assert r.status_code == 303
    target = make_user("panel-target@example.com")
    before = db.get_user(target["id"])["credits"]
    r = c.post(f"/account/owner/users/{target['id']}/credits", data={"amount": "7"},
               follow_redirects=False)
    assert r.status_code == 303
    assert db.get_user(target["id"])["credits"] == before + 7
    # a normal user can't use them
    other = login("panel-nobody@example.com")
    other.post(f"/account/owner/users/{target['id']}/credits", data={"amount": "7"})
    assert db.get_user(target["id"])["credits"] == before + 7


# --- reports -------------------------------------------------------------------------

def test_report_template_merge_and_filename() -> None:
    merged = pro_reports._merge(pro_reports.DEFAULT_TEMPLATE, {"bogus": 1, 5: "x"})
    assert set(merged) == set(pro_reports.DEFAULT_TEMPLATE)
    assert pro_reports._merge(pro_reports.DEFAULT_TEMPLATE, "not a dict") == \
        pro_reports._merge(pro_reports.DEFAULT_TEMPLATE, {})
    name = pro_reports.safe_filename('ev"il\r\n/../name', "pdf")
    assert name.endswith(".pdf")
    assert all(ch.isalnum() or ch in "._-" for ch in name)


def test_corrupt_json_columns_do_not_crash() -> None:
    assert db._json_obj("{not json", {"a": 1}) == {"a": 1}
