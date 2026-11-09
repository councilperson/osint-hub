"""Offline test suite: pages, routing, DB layer, and service logic with
network calls mocked out. Run: python -m pytest tests -q
"""
from __future__ import annotations

import os
import tempfile
import pathlib
import sys

# point the DB at a temp file before importing the app
_tmp = tempfile.mkdtemp(prefix="osint-hub-test-")
os.environ.setdefault("OSINT_DB", str(pathlib.Path(_tmp) / "test.db"))

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from app import db, services  # noqa: E402
from app.main import app, TOOLS, ADMIN_PATH  # noqa: E402

client = TestClient(app)


# --- static pages ------------------------------------------------------------
def test_index_page() -> None:
    r = client.get("/")
    assert r.status_code == 200
    assert "am<b>ana</b>" in r.text
    for tool_id in TOOLS:
        assert f"/tool/{tool_id}" in r.text


def test_tools_and_resources_pages() -> None:
    for tool_id in TOOLS:
        r = client.get(f"/tool/{tool_id}")
        assert r.status_code == 200, tool_id
        assert "placeholder" in r.text  # every tool page renders a query form
    assert client.get("/resources").status_code == 200
    assert client.get("/notes").status_code == 200
    assert client.get("/history").status_code == 200


def test_unknown_tool_404() -> None:
    assert client.get("/tool/not-a-tool").status_code == 404
    assert client.post("/tool/not-a-tool", data={"target": "x"}).status_code == 404


def test_robots_allows_public() -> None:
    r = client.get("/robots.txt")
    assert r.status_code == 200
    assert "Allow: /" in r.text
    assert "Disallow: /" not in r.text  # public site: crawlable


# --- tool runs with mocked services -------------------------------------------
def test_tool_run_logs_history(monkeypatch) -> None:
    def fake(target: str) -> dict:
        return {"summary": services.summary_ok("mock ok"),
                "sections": [
                    {"title": "Mock", "kind": "text", "text": "RESULT_MARKER"},
                    {"title": "Mock list", "kind": "list", "items": ["LIST_MARKER"]},
                    {"title": "Mock kv", "kind": "kv", "rows": [["K", "V_MARKER"]]},
                    {"title": "Mock table", "kind": "table", "head": ["H1"], "rows": [["T_MARKER"]]},
                ]}

    monkeypatch.setitem(TOOLS["whois"], "fn", fake)
    r = client.post("/tool/whois", data={"target": "example.com"})
    assert r.status_code == 200
    for marker in ("RESULT_MARKER", "LIST_MARKER", "V_MARKER", "T_MARKER"):
        assert marker in r.text
    targets = [q["target"] for q in db.recent_queries(10)]
    assert "example.com" in targets


def test_tool_run_error_becomes_section(monkeypatch) -> None:
    def boom(target: str) -> dict:
        raise services.LookupError("Enter a domain or URL.")

    monkeypatch.setitem(TOOLS["dns"], "fn", boom)
    r = client.post("/tool/dns", data={"target": ""})
    assert r.status_code == 200
    assert "Input problem" in r.text

    monkeypatch.setitem(TOOLS["dns"], "fn", lambda t: (_ for _ in ()).throw(RuntimeError("upstream down")))
    r = client.post("/tool/dns", data={"target": "example.com"})
    assert r.status_code == 200
    assert "Lookup failed" in r.text


# --- notes ---------------------------------------------------------------------
def test_notes_crud() -> None:
    client.post("/notes", data={"tool": "Domain ownership (RDAP)",
                                "target": "example.com",
                                "summary": "registered 1995, benign"})
    page = client.get("/notes").text
    assert "registered 1995, benign" in page
    assert "example.com" in page

    # delete
    notes = db.list_notes()
    note_id = notes[0]["id"]
    client.post(f"/notes/{note_id}/delete")
    assert all(n["id"] != note_id for n in db.list_notes())


def test_empty_note_ignored() -> None:
    before = len(db.list_notes())
    client.post("/notes", data={"tool": "", "target": "", "summary": ""})
    assert len(db.list_notes()) == before


# --- unit-tested logic (no network) --------------------------------------------
def test_clean_domain() -> None:
    assert services.clean_domain("https://Example.com/page?x=1") == "example.com"
    assert services.clean_domain("sub.domain.io") == "sub.domain.io"


def test_username_interpretation() -> None:
    assert services._interpret_status(200) == "found?"
    assert services._interpret_status(404) == "gone"
    assert services._interpret_status(410) == "gone"
    assert services._interpret_status(429) == "blocked"
    assert services._interpret_status(500) == "maybe"


def test_registered_domain() -> None:
    assert services.registered_domain("a.b.example.com") == "example.com"
    assert services.registered_domain("site.co.uk") == "site.co.uk"
    assert services.registered_domain("plain.io") == "plain.io"


def test_disposable_list_membership() -> None:
    assert "mailinator.com" in services.DISPOSABLE_DOMAINS
    assert "gmail.com" not in services.DISPOSABLE_DOMAINS


# --- HIBP section (network mocked) --------------------------------------------
class _FakeResp:
    def __init__(self, text="", status_code=200, json_data=None):
        self.text = text
        self.status_code = status_code
        self._json = json_data

    def json(self):
        return self._json


def test_hibp_page_renders() -> None:
    r = client.get("/hibp")
    assert r.status_code == 200
    assert "Pwned-password check" in r.text
    assert "Breach catalog" in r.text


def test_hibp_password_check(monkeypatch) -> None:
    # fake range endpoint: prefix "AAAAA" with suffix "BBB" has 10 hits
    import hashlib

    def fake_get(url, **kw):
        return _FakeResp(text="0000:0\nBBB:10\nCCCC:99\n")

    monkeypatch.setattr(services, "_get", fake_get)
    pw = "anything"  # deterministic sha1 binds suffix; emulate by masking service
    # instead of hard-coding digest, call with the fake and just inspect flow
    real = services.hibp_password_check
    # stub hashlib for determinism? simply verify nonzero path via known text
    sha = hashlib.sha1(pw.encode()).hexdigest().upper()
    suffix = sha[5:]
    text = f"QQQ:0\n{suffix}:10\n"
    monkeypatch.setattr(services, "_get", lambda u, **kw: _FakeResp(text=text))
    res = real(pw)
    assert res["summary"]["level"] == "bad"
    assert "10" in res["summary"]["text"]

    monkeypatch.setattr(services, "_get", lambda u, **kw: _FakeResp(text="QQQ:0\n"))
    res2 = real(pw)
    assert res2["summary"]["level"] == "ok"


def test_hibp_catalog(monkeypatch) -> None:
    data = [
        {"Name": "B1", "Title": "Adobe", "Domain": "adobe.com", "BreachDate": "2013-10-04",
         "PwnCount": 152445165, "DataClasses": ["Email addresses", "Passwords"]},
        {"Name": "B2", "Title": "ExampleCorp", "Domain": "example.com", "BreachDate": "2020-01-01",
         "PwnCount": 500, "DataClasses": ["Email addresses"]},
    ]
    monkeypatch.setattr(services, "_get", lambda u, **kw: _FakeResp(json_data=data, status_code=200))
    services._BREACH_CACHE.update(data=None, ts=0.0)
    out = services.hibp_catalog_query("example")
    assert "1 match(es)" in out["sections"][0]["title"]
    assert out["summary"]["level"] == "warn"
    services._BREACH_CACHE.update(data=None, ts=0.0)


def test_hibp_email_lookup_keyed(monkeypatch) -> None:
    def fake_get(url, **kw):
        assert kw["headers"].get("hibp-api-key") == "TESTKEY"
        return _FakeResp(json_data=[
            {"Name": "ExampleBreach", "Title": "Example", "BreachDate": "2022-02-02",
             "PwnCount": 123, "DataClasses": ["Email addresses", "Passwords"]},
        ], status_code=200)

    monkeypatch.setattr(services, "_get", fake_get)
    out = services.hibp_email_lookup("a@b.com", "TESTKEY")
    assert "1 breach" in out["summary"]["text"]

    monkeypatch.setattr(services, "_get", lambda u, **kw: _FakeResp(status_code=404))
    out_clean = services.hibp_email_lookup("a@b.com", "TESTKEY")
    assert out_clean["summary"]["level"] == "ok"


# --- hidden admin panel -----------------------------------------------------------
def test_admin_hidden_and_gated() -> None:
    client2 = TestClient(app)
    # legacy /admin is dead to the world
    assert client2.get("/admin").status_code == 404
    assert client2.post("/admin/login", data={"token": "x"}).status_code == 404
    # the secret path shows the sign-in form
    r = client2.get(ADMIN_PATH)
    assert r.status_code == 200
    assert "Admin sign-in" in r.text
    # and no public page links to it
    home = client2.get("/").text
    assert ADMIN_PATH not in home
    assert "href=\"/admin" not in home


def test_admin_login_and_clear(monkeypatch) -> None:
    client3 = TestClient(app)
    bad = client3.post(ADMIN_PATH + "/login", data={"token": "wrong"})
    assert "Admin sign-in" in bad.text  # rejected

    good = client3.post(ADMIN_PATH + "/login", data={"token": os.environ.get("ADMIN_TOKEN", "admin12345")})
    assert good.status_code == 200
    page = client3.get(ADMIN_PATH)
    assert page.status_code == 200
    assert "storage actions" in page.text.lower()

    # clear history works then empties
    db.add_query("dns", "admin-clear-test.example")
    r = client3.post(ADMIN_PATH + "/clear-history")
    assert r.status_code == 200
    assert db.recent_queries(5) == []


# --- pro tier -----------------------------------------------------------------------
def test_pro_purchase_gates_and_deactivate() -> None:
    c = TestClient(app)
    # free: export redirects to /pro
    r = c.get("/notes/export.md", follow_redirects=False)
    assert r.status_code == 303
    assert "/pro" in r.headers["location"]

    # demo purchase activates a license server-side
    r = c.post("/pro/purchase", data={"plan": "pro"})
    assert r.status_code == 200
    assert "Activated" in r.text or "license key" in r.text
    assert db.has_pro() is True

    # export now works and returns markdown
    r2 = c.get("/notes/export.md")
    assert r2.status_code == 200
    assert "amana notes" in r2.text

    # deactivate returns to free
    c.post("/pro/deactivate")
    assert db.has_pro() is False


def test_username_platform_limits(monkeypatch) -> None:
    monkeypatch.setattr(services, "_get", lambda u, **kw: _FakeResp(status_code=404))
    limited = services.username_check_batch(["abc"], max_platforms=10)
    assert len(limited["sections"][0]["rows"]) == 10
    full = services.username_check_batch(["abc"])
    assert len(full["sections"][0]["rows"]) == len(services.PLATFORMS)


def test_batch_requires_pro_at_route_level() -> None:
    # free plan: comma-separated input produces the upsell, not results
    c = TestClient(app)
    class _Noop:
        def __call__(self, *a, **kw):  # network would be hit otherwise
            raise AssertionError("network must not be called for the free upsell path")
    original = services.username_check_batch
    services.username_check_batch = _Noop()
    r = c.post("/tool/username", data={"target": "a, b, c"})
    services.username_check_batch = original
    assert r.status_code == 200
    assert "Batch checking is a Pro feature" in r.text


# --- public site & private desk ---------------------------------------------------
def test_public_site_resources() -> None:
    c = TestClient(app)
    home = c.get("/")
    assert home.status_code == 200
    # public site: robots allows crawling and pages are indexable
    assert "Allow: /" in c.get("/robots.txt").text
    assert "noindex" not in home.text
    # free library is generous
    res = c.get("/resources")
    assert "Google Hacking Database" in res.text
    assert "MXToolbox" in res.text
    # private desk is gated
    r = c.get("/resources/private", follow_redirects=False)
    assert r.status_code == 303
    assert "/pro" in r.headers["location"]


def test_private_desk_and_crypto_checkout_for_pro() -> None:
    c = TestClient(app)
    assert c.post("/pro/purchase", data={"plan": "pro"}).status_code == 200
    desk = c.get("/resources/private")
    assert desk.status_code == 200
    assert "private desk" in desk.text.lower()
    assert "Nmap" in desk.text and "AlienVault OTX" in desk.text

    # de-activate so checkout is reachable for a free visitor
    c.post("/pro/deactivate")
    checkout = c.post("/pro/purchase", data={"plan": "pro"})
    assert "amana" in checkout.text.lower()


def test_crypto_checkout_flow() -> None:
    c = TestClient(app)
    # ensure free
    c.post("/pro/deactivate")
    page = c.get("/pro/checkout")
    assert page.status_code == 200
    assert "crypto only" in page.text.lower()
    for coin in ("BTC", "XMR", "LTC"):
        assert coin in page.text
    assert "/pro/purchase" in page.text  # activate endpoint linked
    # pro visitors get bounced back to /pro
    c.post("/pro/purchase", data={"plan": "pro"})
    r = c.get("/pro/checkout", follow_redirects=False)
    assert r.status_code == 303


def test_admin_sees_all_lookups(monkeypatch) -> None:
    c = TestClient(app)
    c.post(ADMIN_PATH + "/login", data={"token": "admin12345"})
    for i in range(60):
        db.add_query("dns", f"bulk-{i}.example")
    page = c.get(ADMIN_PATH)
    assert "All lookups" in page.text
    # more than 50 entries must be visible now
    assert page.text.count("bulk-") >= 60


def test_hibp_password_page_never_logs() -> None:
    before = len(db.recent_queries(500))
    client.post("/hibp/password", data={"password": "whatever-probe-123"})
    after = len(db.recent_queries(500))
    assert before == after

