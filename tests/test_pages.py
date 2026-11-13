"""Every page renders for every kind of signed-in account.

Added after Monitors and Reports returned "Internal Server Error" on the live
site: the deploy was missing app/templates/monitors.html and reports.html, so
Jinja raised TemplateNotFound. These tests pin two things:

* every template the code renders (and every template those extend/include)
  exists in app/templates, so an incomplete copy or upload fails the suite;
* every GET route answers without a server error for a free user, a Pro user,
  a Team user, the owner account and the admin console, with real-looking data
  (a scan, a case, a monitor with a run and hits, a report template, an order,
  a reseller sub-account) in the database.
"""
from __future__ import annotations

import pathlib
import re

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from test_app import ADMIN_PATH, TOOLS, admin_client, make_user, top_up  # noqa: F401
from app import auth, db, reseller, scanner
from app import main as main_mod
from app.main import app

APP_DIR = pathlib.Path(main_mod.__file__).resolve().parent
TEMPLATE_DIR = APP_DIR / "templates"

# /api/scan/stream holds the connection open; /logout ends the session, so the
# sweep requests it last (see _sweep)
SKIP = {"/api/scan/stream", "/logout"}


def _referenced_templates() -> set[str]:
    names: set[str] = set()
    for py in APP_DIR.glob("*.py"):
        names |= set(re.findall(r'TemplateResponse\(\s*request\s*,\s*"([^"]+\.html)"',
                                py.read_text(encoding="utf-8")))
    for html in TEMPLATE_DIR.glob("*.html"):
        names |= set(re.findall(r'{%-?\s*(?:extends|include|import|from)\s+"([^"]+)"',
                                html.read_text(encoding="utf-8")))
    return names


def test_every_rendered_template_exists() -> None:
    names = _referenced_templates()
    # the pages that broke on the live site must be among them
    assert {"monitors.html", "monitor_detail.html", "monitor_run.html",
            "reports.html"} <= names
    missing = sorted(n for n in names if not (TEMPLATE_DIR / n).is_file())
    assert not missing, f"templates rendered by the app but missing: {missing}"


def test_every_template_compiles() -> None:
    env = main_mod.templates.env
    for html in sorted(TEMPLATE_DIR.glob("*.html")):
        env.get_template(html.name)   # raises on syntax errors


def _get_paths() -> list[str]:
    paths = set()
    for r in list(app.routes) + list(reseller.router.routes):
        if isinstance(r, APIRoute) and "GET" in r.methods:
            paths.add(r.path)
    return sorted(paths)


@pytest.fixture
def world(monkeypatch):
    """Accounts of every tier plus one of each kind of record."""
    async def fake_lookup(kind, value, pro=True):
        return [scanner.Hit("x", "X", kind, "hit", "https://example.com/x", "", 1)]
    monkeypatch.setattr(scanner, "run_lookup", fake_lookup)
    monkeypatch.setenv("OWNER_EMAIL", "sweep-owner@example.com")
    monkeypatch.setenv("OWNER_PASSWORD", "sweep-owner-pass-1")
    main_mod._bootstrap_owner()

    accounts = {}
    for name, plan in (("free", "free"), ("pro", "pro"), ("team", "team")):
        accounts[name] = make_user(f"sweep-{name}@example.com", plan)
    accounts["owner"] = db.get_user_by_email("sweep-owner@example.com")

    ids = {}
    for name, user in accounts.items():
        uid = user["id"]
        top_up(uid, 100)
        results = [{"id": "github", "name": "GitHub", "category": "dev", "status": "hit",
                    "url": "https://github.com/yaknow", "detail": "profile", "ms": 120,
                    "display_name": "yaknow", "avatar": "", "meta": [["Followers", "3"]]}]
        scan_id = db.insert_scan(uid, "username", "yaknow", "yaknow", 1, 10, 10, 1.5, results)
        case_id = db.create_case(uid, f"{name} case", "notes")
        db.add_case_item(case_id, "scan", "yaknow", {"scan_id": scan_id, "found": 1})
        mon_id = db.create_monitor(uid, "username", "yaknow", "daily", "email", {})
        run_id = db.create_monitor_run(mon_id, 1, 10, 1.2, "")
        db.add_monitor_hits(run_id, mon_id, results)
        db.create_report_template(uid, f"{name} template", {"branding": {}})
        db.create_report_generation(uid, scan_id, None, "pdf", "r.pdf")
        sub = db.create_sub_account(uid, f"{name} client")
        order_id = db.create_order(uid, user["email"], "pro", "BTC",
                                   "bc1qpw7n2ck6a6vxc6vm5jhm5tf07kd8430ctt3uyl",
                                   "0.0001 BTC")
        db.add_note("username", "yaknow", "a note", user_id=uid)
        db.add_query("username", "yaknow", True, user_id=uid)
        ids[name] = {"scan_id": scan_id, "case_id": case_id, "monitor_id": mon_id,
                     "run_id": run_id, "sub_id": sub["id"], "order_id": order_id,
                     "tool_id": next(iter(TOOLS)), "rest": "x"}
    return accounts, ids


def _client_for(user: dict) -> TestClient:
    c = TestClient(app, raise_server_exceptions=True)
    c.cookies.set(auth.SESSION_COOKIE, auth.start_session(user["id"]))
    return c


def _sweep(c: TestClient, params: dict) -> dict:
    out = {}
    for path in _get_paths():
        if path in SKIP:
            continue
        url = path
        for key in re.findall(r"{(\w+)(?::\w+)?}", path):
            url = re.sub(r"{%s(?::\w+)?}" % key, str(params[key]), url)
        if url.startswith("/checkout/"):
            url += f"?k={main_mod._order_token(params['order_id'])}"
        r = c.get(url, follow_redirects=False)
        out[path] = r.status_code
    out["/logout"] = c.get("/logout", follow_redirects=False).status_code
    return out


@pytest.mark.parametrize("who", ["free", "pro", "team", "owner"])
def test_every_get_route_renders_for_each_account(world, who) -> None:
    accounts, ids = world
    codes = _sweep(_client_for(accounts[who]), ids[who])
    errors = {p: s for p, s in codes.items() if s >= 500}
    assert not errors, errors
    # the pages that used to 500 must really render (not just redirect)
    assert codes["/monitors"] == 200
    assert codes["/monitors/{monitor_id}"] == 200
    assert codes["/monitors/{monitor_id}/runs/{run_id}"] == 200
    assert codes["/account"] == 200
    if who != "free":
        assert codes["/reports"] == 200
        assert codes["/reports/{scan_id}.pdf"] == 200
        assert codes["/reports/{scan_id}.docx"] == 200


def test_every_get_route_renders_for_the_admin_console(world) -> None:
    accounts, ids = world
    c = admin_client()
    c.cookies.set(auth.SESSION_COOKIE, auth.start_session(accounts["owner"]["id"]))
    codes = _sweep(c, ids["owner"])
    errors = {p: s for p, s in codes.items() if s >= 500}
    assert not errors, errors
    assert codes[ADMIN_PATH] == 200


def test_monitor_and_report_pages_show_their_data(world) -> None:
    accounts, ids = world
    c = _client_for(accounts["team"])
    page = c.get("/monitors")
    assert page.status_code == 200 and "yaknow" in page.text and "Create Monitor" in page.text
    page = c.get("/reports")
    assert page.status_code == 200 and "team template" in page.text
    assert "Generate Report" in page.text
    r = c.post("/reports/generate", data={"scan_id": ids["team"]["scan_id"],
                                          "template_id": 0, "format": "pdf"},
               headers={"Origin": "http://testserver"})
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
    r = c.post("/monitors", data={"kind": "username", "target": "mrbeast",
                                  "frequency": "daily", "channel": "email",
                                  "channel_config": ""},
               headers={"Origin": "http://testserver"}, follow_redirects=False)
    assert r.status_code == 303
    assert c.get(r.headers["location"]).status_code == 200
