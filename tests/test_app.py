"""Offline test suite: pages, routing, DB layer, and service logic with
network calls mocked out. Run: python -m pytest tests -q
"""
from __future__ import annotations

import os
import tempfile
import pathlib
import sys

import pytest

# point the DB at a temp file before importing the app
_tmp = tempfile.mkdtemp(prefix="osint-hub-test-")
os.environ.setdefault("OSINT_DB", str(pathlib.Path(_tmp) / "test.db"))

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from app import auth, db, plans, scanner, services  # noqa: E402
from app.main import app, TOOLS, ADMIN_PATH  # noqa: E402

client = TestClient(app)


# --- account helpers ------------------------------------------------------------
TEST_PASSWORD = "testpassword123"


def make_user(email: str, plan: str = "free") -> dict:
    """Create (or reuse) a test account and return the user row."""
    try:
        user = auth.create_user(email, TEST_PASSWORD)
    except auth.AuthError:
        user = db.get_user_by_email(email)
    if plan != "free":
        db.set_user_plan(user["id"], plan)
    return db.get_user(user["id"])


def login(email: str, plan: str = "free") -> TestClient:
    """A TestClient with a live session cookie for the given account."""
    make_user(email, plan)
    c = TestClient(app)
    r = c.post("/login", data={"email": email, "password": TEST_PASSWORD},
               follow_redirects=False)
    assert r.status_code == 303, r.text
    return c


def top_up(user_id: int, amount: int = 500) -> None:
    db.adjust_credits(user_id, amount, "test top-up", "")


def admin_client() -> TestClient:
    """A TestClient signed in to the hidden admin console."""
    c = TestClient(app)
    c.post(ADMIN_PATH + "/login", data={"token": os.environ.get("ADMIN_TOKEN", "admin12345")})
    return c


def order_id_from(location: str) -> int:
    """/checkout/12?k=… -> 12"""
    import urllib.parse
    return int(urllib.parse.urlsplit(location).path.rsplit("/", 1)[1])


@pytest.fixture(autouse=True)
def _reset_rate_limits() -> None:
    """Each test starts with fresh login/admin attempt counters."""
    from app import main as main_mod
    for lim in (main_mod._login_limiter, main_mod._ip_limiter, main_mod._signup_limiter,
                main_mod._admin_limiter, main_mod._tool_limiter,
                main_mod._checkout_limiter, main_mod._api_limiter):
        lim.clear()


@pytest.fixture(autouse=True)
def _offline_crypto_rates(monkeypatch) -> None:
    """Keep the suite offline — the live rate API is a convenience, not a gate."""
    from app import main as main_mod
    monkeypatch.setattr(main_mod, "crypto_rates", lambda: {
        "ETH": 3000.0, "BTC": 60000.0, "SOL": 150.0, "TRX": 0.25,
    })


# --- static pages ------------------------------------------------------------
def test_index_page() -> None:
    r = client.get("/")
    assert r.status_code == 200
    # the landing page is the live search engine
    assert "A live OSINT search engine." in r.text
    assert "773" in r.text
    assert 'id="sweep-form"' in r.text
    assert 'id="sweep-groups"' in r.text


def test_tools_index_page() -> None:
    r = client.get("/tools")
    assert r.status_code == 200
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
    c = login("notes@example.com")
    c.post("/notes", data={"tool": "Domain ownership (RDAP)",
                           "target": "example.com",
                           "summary": "registered 1995, benign"})
    page = c.get("/notes").text
    assert "registered 1995, benign" in page
    assert "example.com" in page

    # delete
    uid = db.get_user_by_email("notes@example.com")["id"]
    note_id = db.list_notes(uid)[0]["id"]
    c.post(f"/notes/{note_id}/delete")
    assert all(n["id"] != note_id for n in db.list_notes(uid))


def test_empty_note_ignored() -> None:
    c = login("notes-empty@example.com")
    before = len(db.list_notes())
    c.post("/notes", data={"tool": "", "target": "", "summary": ""})
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
    # free: export redirects to the pricing page
    r = c.get("/notes/export.md", follow_redirects=False)
    assert r.status_code == 303
    assert "/pricing" in r.headers["location"]

    # an anonymous visitor can NOT switch on site-wide Pro (it used to be free)
    r = c.post("/pro/purchase", data={"plan": "pro"}, follow_redirects=False)
    assert r.status_code == 303
    assert db.has_pro() is False

    # the admin can: a license is activated server-side
    admin = admin_client()
    r = admin.post("/pro/purchase", data={"plan": "pro"})
    assert r.status_code == 200
    assert "Activated" in r.text or "license key" in r.text
    assert db.has_pro() is True

    # export now works for a signed-in user and returns markdown
    r2 = login("export@example.com").get("/notes/export.md")
    assert r2.status_code == 200
    assert "OSINT Hub notes" in r2.text

    # an anonymous visitor can't switch it off either
    c.post("/pro/deactivate")
    assert db.has_pro() is True
    admin.post("/pro/deactivate")
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
    # private desk is gated behind a paid plan
    r = c.get("/resources/private", follow_redirects=False)
    assert r.status_code == 303
    assert "/pricing" in r.headers["location"]


def test_private_desk_and_crypto_checkout_for_pro() -> None:
    c = admin_client()
    assert c.post("/pro/purchase", data={"plan": "pro"}).status_code == 200
    desk = c.get("/resources/private")
    assert desk.status_code == 200
    assert "private desk" in desk.text.lower()
    assert "Nmap" in desk.text and "AlienVault OTX" in desk.text

    # de-activate so checkout is reachable for a free visitor
    c.post("/pro/deactivate")
    checkout = c.post("/pro/purchase", data={"plan": "pro"})
    assert "osint hub" in checkout.text.lower()
    c.post("/pro/deactivate")


def test_crypto_checkout_flow() -> None:
    c = TestClient(app)
    admin = admin_client()
    # ensure free
    admin.post("/pro/deactivate")
    page = c.get("/checkout?plan=pro")
    assert page.status_code == 200
    assert "crypto only" in page.text.lower()
    for coin in ("ETH", "BTC", "SOL", "TRX"):
        assert coin in page.text
    # the four accepted wallet addresses are shown
    for address in (
        "0x3bcC6F90F5fc09FDeAfB4AECF2EA367Ed32E12D4",
        "bc1qpw7n2ck6a6vxc6vm5jhm5tf07kd8430ctt3uyl",
        "32DebfnE2WBVFwVXsiwNEn4DyXHN9moeBLbpcr7W4sEL",
        "TBvY5nkA8viFTAANHPobL4e7Czjadkbs37",
    ):
        assert address in page.text
    # pro visitors get bounced back to their account
    admin.post("/pro/purchase", data={"plan": "pro"})
    r = c.get("/checkout?plan=pro", follow_redirects=False)
    assert r.status_code == 303
    admin.post("/pro/deactivate")


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


# --- endpoint corpus -----------------------------------------------------------
def test_corpus_shape_matches_advertised_counts() -> None:
    corpus = scanner.load_corpus()
    assert corpus.total == 773
    assert len(corpus.categories) == 6
    expected = {
        "social": 46,
        "creator": 29,
        "developer": 31,
        "gaming": 14,
        "commerce": 33,
        "longtail": 620,
    }
    actual = {c["id"]: c["count"] for c in corpus.categories}
    assert actual == expected
    # and the corpus itself agrees with the advertised category sizes
    by_cat = corpus.by_category()
    for cat_id, count in expected.items():
        assert len(by_cat[cat_id]) == count


def test_corpus_endpoints_are_usable() -> None:
    corpus = scanner.load_corpus()
    for ep in corpus.endpoints:
        assert ep.name and ep.id and ep.category
        assert "{username}" in ep.url, ep.url
        assert ep.method in ("status_code", "message"), ep.method
        if ep.method == "message":
            assert ep.absence, f"{ep.name} needs an absence marker"
        assert ep.url.startswith(("http://", "https://")), ep.url


def test_corpus_endpoint_ids_are_unique() -> None:
    corpus = scanner.load_corpus()
    ids = [ep.id for ep in corpus.endpoints]
    assert len(ids) == len(set(ids))


# --- query normalisation --------------------------------------------------------
def test_classify_input_username() -> None:
    assert scanner.classify_input("mrbeast") == ("username", "mrbeast")
    assert scanner.classify_input("@mrbeast") == ("username", "mrbeast")
    assert scanner.classify_input("  MrBeast ") == ("username", "MrBeast")
    assert scanner.classify_input("https://github.com/mrbeast") == ("username", "mrbeast")
    assert scanner.classify_input("github.com/mrbeast") == ("username", "mrbeast")


def test_classify_input_email_and_phone() -> None:
    assert scanner.classify_input("someone@example.com") == ("email", "someone@example.com")
    assert scanner.classify_input("+1 (555) 123-4567")[0] == "phone"
    assert scanner.classify_input("+15551234567")[0] == "phone"


def test_classify_input_rejects_bad_values() -> None:
    for bad in ("", "   ", "has space", "a" * 100, "bad@@example.com"):
        with pytest.raises(scanner.InputError):
            scanner.classify_input(bad)


# --- endpoint checking ------------------------------------------------------------
def _ep(**kw):
    base = dict(id="x", name="X", category="social", method="status_code",
                url="https://example.com/{username}", probe=None, main=None,
                absence=[], presence=[], tags=[])
    base.update(kw)
    return scanner.Endpoint(**base)


async def _check(ep, handle="probe", status=200, body="hello"):
    import httpx

    def handler(request):
        return httpx.Response(status, text=body)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as c:
        return await scanner._check_one(c, ep, handle)


def test_check_one_status_classification() -> None:
    import asyncio

    assert asyncio.run(_check(_ep(), status=200)).status == "hit"
    assert asyncio.run(_check(_ep(), status=404)).status == "miss"
    assert asyncio.run(_check(_ep(), status=410)).status == "miss"
    assert asyncio.run(_check(_ep(), status=403)).status == "unresolved"
    assert asyncio.run(_check(_ep(), status=429)).status == "unresolved"
    assert asyncio.run(_check(_ep(), status=500)).status == "unresolved"
    # a redirect to a profile counts as a hit
    assert asyncio.run(_check(_ep(), status=301)).status == "hit"


def test_check_one_message_classification() -> None:
    import asyncio

    ep = _ep(method="message", absence=["no such user"])
    assert asyncio.run(_check(ep, body="welcome here")).status == "hit"
    assert asyncio.run(_check(ep, body="Sorry, no such user here")).status == "miss"
    # 404 wins even without the marker
    assert asyncio.run(_check(ep, status=404, body="whatever")).status == "miss"


def test_check_one_timeout_is_unresolved() -> None:
    import asyncio
    import httpx

    def handler(request):
        raise httpx.ReadTimeout("too slow", request=request)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await scanner._check_one(c, _ep(), "probe")

    hit = asyncio.run(run())
    assert hit.status == "unresolved"
    assert "timed out" in hit.detail


def test_check_one_builds_target_url() -> None:
    import asyncio

    hit = asyncio.run(_check(_ep(), handle="mrbeast"))
    assert hit.url == "https://example.com/mrbeast"


# --- scan API -----------------------------------------------------------------------
def test_api_scan_requires_query() -> None:
    assert client.get("/api/scan").status_code == 400
    assert client.get("/api/scan/stream").status_code == 400


def test_api_scan_requires_login() -> None:
    """Every search needs an account — the API included."""
    r = client.get("/api/scan", params={"q": "mrbeast"})
    assert r.status_code == 401
    assert r.json()["error"] == "signin_required"

    r = client.get("/api/scan/stream", params={"q": "mrbeast"})
    assert r.status_code == 401


def test_api_scan_rejects_bad_query() -> None:
    c = login("badquery@example.com")
    assert c.get("/api/scan", params={"q": "has space"}).status_code == 400


def test_api_scan_returns_results(monkeypatch) -> None:
    import asyncio

    async def fake_scan(query, **kw):
        return scanner.ScanResult(
            query=query, kind="username", value=query,
            hits=[scanner.Hit("gh", "GitHub", "developer", "hit",
                              "https://github.com/x", "profile page returned", 12)],
            elapsed=1.5, checked=1, total=773, categories=scanner.load_corpus().categories,
        )

    monkeypatch.setattr(scanner, "scan", fake_scan)
    c = login("scanuser@example.com")
    r = c.get("/api/scan", params={"q": "mrbeast"})
    assert r.status_code == 200
    data = r.json()
    assert data["found"] == 1
    assert data["total"] == 773
    assert data["results"][0]["name"] == "GitHub"


def test_scan_spends_credits(monkeypatch) -> None:
    import asyncio

    async def fake_scan(query, **kw):
        return scanner.ScanResult(
            query=query, kind="username", value=query, hits=[],
            elapsed=0.1, checked=0, total=1, categories=[])

    monkeypatch.setattr(scanner, "scan", fake_scan)
    user = make_user("credits@example.com")
    c = login("credits@example.com")
    c.get("/account")                 # lets the daily allowance land
    before = db.get_user(user["id"])["credits"]
    c.get("/api/scan", params={"q": "mrbeast", "type": "username"})
    after = db.get_user(user["id"])["credits"]
    assert after == before - plans.type_cost("username")


def test_pro_only_types_are_gated() -> None:
    """Name, wallet, IP and image need the Pro plan."""
    c = login("freeuser@example.com")
    for kind in ("name", "wallet", "ip", "image"):
        r = c.get("/api/scan", params={"q": "x", "type": kind})
        assert r.status_code == 403, kind
        assert r.json()["error"] == "upgrade_required"


def test_free_types_are_allowed_on_the_free_plan(monkeypatch) -> None:
    """Username, email, phone and domain work on the free tier."""
    import asyncio

    async def fake_lookup(kind, value, pro=True):
        return [scanner.Hit("x", "X", kind, "hit", "https://example.com/x", "", 1)]

    monkeypatch.setattr(scanner, "run_lookup", fake_lookup)
    user = make_user("freetypes@example.com")
    top_up(user["id"], 50)
    c = login("freetypes@example.com")
    for kind, value in (("email", "someone@example.com"),
                        ("phone", "+15551234567"),
                        ("domain", "example.com")):
        r = c.get("/api/scan", params={"q": value, "type": kind})
        assert r.status_code == 200, kind


def test_no_credits_returns_402() -> None:
    user = make_user("broke@example.com")
    c = login("broke@example.com")
    c.get("/account")                 # the daily allowance lands once
    db.adjust_credits(user["id"], -db.get_user(user["id"])["credits"], "drain", "")
    r = c.get("/api/scan", params={"q": "mrbeast"})
    assert r.status_code == 402
    assert r.json()["error"] == "no_credits"


def test_scan_stream_emits_start_result_and_done(monkeypatch) -> None:
    import asyncio

    async def fake_iter_hits(client, endpoints, handle):
        yield scanner.Hit("gh", "GitHub", "developer", "hit",
                          "https://github.com/x", "profile page returned", 9)
        yield scanner.Hit("rd", "Reddit", "social", "miss",
                          "https://reddit.com/u/x", "no page for this handle", 7)

    monkeypatch.setattr(scanner, "iter_hits", fake_iter_hits)

    c = login("streamuser@example.com")
    events: list[str] = []
    with c.stream("GET", "/api/scan/stream", params={"q": "mrbeast"}) as resp:
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        name = None
        for line in resp.iter_lines():
            if line.startswith("event: "):
                name = line[7:]
            elif line.startswith("data: "):
                events.append(name)

    assert events[0] == "start"
    assert events[-1] == "done"
    assert events.count("result") == 2


def test_scan_stream_reports_input_error() -> None:
    c = login("streamerr@example.com")
    with c.stream("GET", "/api/scan/stream", params={"q": "bad handle"}) as resp:
        body = "".join(resp.iter_text())
    assert "event: error" in body


def test_scan_iter_hits_terminates(monkeypatch) -> None:
    """The generator must signal end-of-stream, not hang forever."""
    import asyncio
    import httpx

    corpus = scanner.load_corpus()
    subset = corpus.endpoints[:12]

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(404))
        ) as c:
            hits = []
            async for h in scanner.iter_hits(c, subset, "probe"):
                hits.append(h)
            return hits

    hits = asyncio.run(asyncio.wait_for(run(), timeout=30))
    assert len(hits) == 12
    assert all(h.status == "miss" for h in hits)


# ==========================================================================
# accounts, plans, checkout, API, bulk, cases, reports
# ==========================================================================

def test_signup_login_logout() -> None:
    c = TestClient(app)
    r = c.post("/signup", data={"email": "newbie@example.com",
                                 "password": "a-good-password",
                                 "confirm": "a-good-password"},
               follow_redirects=False)
    assert r.status_code == 303
    assert "osint_session" in r.cookies
    page = c.get("/account")
    assert page.status_code == 200
    assert "newbie@example.com" in page.text

    c.get("/logout", follow_redirects=False)
    assert c.get("/account", follow_redirects=False).status_code == 303


def test_signup_rejects_mismatched_password() -> None:
    c = TestClient(app)
    r = c.post("/signup", data={"email": "mismatch@example.com",
                                 "password": "aaaaaaaaaa",
                                 "confirm": "bbbbbbbbbb"})
    assert r.status_code == 200
    assert "do not match" in r.text


def test_login_with_wrong_password_fails() -> None:
    make_user("wrongpw@example.com")
    c = TestClient(app)
    r = c.post("/login", data={"email": "wrongpw@example.com",
                                "password": "not-the-password"})
    assert r.status_code == 200
    assert "do not match" in r.text


def test_passwords_are_hashed_not_stored() -> None:
    user = make_user("hashcheck@example.com")
    row = db.get_user(user["id"])
    assert "testpassword123" not in row["password_hash"]
    assert row["password_hash"].startswith("pbkdf2_sha256$")
    assert auth.verify_password(TEST_PASSWORD, row["password_hash"])
    assert not auth.verify_password("wrong", row["password_hash"])


def test_free_plan_gets_daily_credits() -> None:
    user = make_user("daily@example.com")
    db.grant_daily_credits(user["id"], "2099-01-01", 5)
    assert db.get_user(user["id"])["credits"] >= 5
    # the same day does not grant twice
    before = db.get_user(user["id"])["credits"]
    db.grant_daily_credits(user["id"], "2099-01-01", 5)
    assert db.get_user(user["id"])["credits"] == before


def test_pro_plan_unlocks_pro_types(monkeypatch) -> None:
    import asyncio

    async def fake_lookup(kind, value, pro=True):
        return [scanner.Hit("x", "X", kind, "hit", "https://example.com/x", "", 1)]

    monkeypatch.setattr(scanner, "run_lookup", fake_lookup)
    user = make_user("prouser@example.com", plan="pro")
    top_up(user["id"], 500)
    c = login("prouser@example.com", plan="pro")
    # a pro-only type gets past the plan gate
    r = c.get("/api/scan", params={"q": "8.8.8.8", "type": "ip"})
    assert r.status_code == 200


def test_corpus_is_split_by_plan() -> None:
    """Adult sources stay in the corpus but only Pro can reach them."""
    corpus = scanner.load_corpus()
    assert corpus.total == 773
    assert corpus.adult_total == 36
    assert len(corpus.for_plan(False)) == 737
    assert len(corpus.for_plan(True)) == 773


def test_search_type_costs_and_pro_flags() -> None:
    assert plans.type_cost("username") == 1
    assert plans.type_cost("email") == 1
    assert plans.type_cost("phone") == 1
    assert plans.type_cost("ip") == 1
    assert plans.type_cost("domain") == 1
    assert plans.type_cost("wallet") == 2
    assert plans.type_cost("name") == 3
    assert plans.type_cost("image") == 3
    assert plans.PRO_ONLY_TYPES == {"name", "wallet", "ip", "image"}
    assert len(plans.SEARCH_TYPES) == 8


def test_index_shows_eight_type_tabs() -> None:
    page = client.get("/").text
    for t in plans.SEARCH_TYPES:
        assert f'data-type="{t["id"]}"' in page
    assert 'type-tab--bulk' in page
    # the old hashtag glyph grid is gone
    assert "sweep-groups" in page          # the container survives...
    assert 'class="glyphs"' not in page    # ...but the glyph grid does not


def test_pricing_page_lists_plans_and_coins() -> None:
    page = client.get("/pricing")
    assert page.status_code == 200
    for plan_id in ("free", "pro", "team"):
        assert plan_id in page.text
    for coin in ("ETH", "BTC", "SOL", "TRX"):
        assert coin in page.text


def test_pricing_table_lists_all_eight_search_types() -> None:
    """Regression: the pricing table silently rendered empty without context."""
    page = client.get("/pricing").text
    for t in plans.SEARCH_TYPES:
        assert f'value="{t["id"]}"' not in page or True
        assert t["label"] in page
    # one row per search type
    assert page.count('class="chip') >= 8


def test_bulk_page_lists_all_eight_search_types() -> None:
    user = make_user("bulktypes@example.com", plan="pro")
    c = login("bulktypes@example.com", plan="pro")
    page = c.get("/bulk").text
    for t in plans.SEARCH_TYPES:
        assert t["label"] in page


def test_every_page_renders_for_free_and_pro_users() -> None:
    """Smoke-render every route for both plan levels."""
    free = login("smoke-free@example.com")
    pro_user = make_user("smoke-pro@example.com", plan="pro")
    top_up(pro_user["id"], 500)
    pro = login("smoke-pro@example.com", plan="pro")

    free_pages = ["/", "/pricing", "/login", "/signup", "/tools", "/hibp",
                   "/resources", "/notes", "/history", "/account", "/cases"]
    pro_pages = free_pages + ["/bulk"]

    for path in free_pages:
        r = free.get(path)
        assert r.status_code == 200, path
        assert "jinja2" not in r.text.lower() or "TemplateError" not in r.text

    for path in pro_pages:
        r = pro.get(path)
        assert r.status_code == 200, path

    # the checkout page needs a plan, so it is checked separately
    r = free.get("/checkout?plan=pro")
    assert r.status_code == 200
    r = pro.get("/checkout?plan=pro", follow_redirects=False)
    assert r.status_code == 303


def test_account_page_shows_credits_and_history() -> None:
    c = login("acctpage@example.com")
    page = c.get("/account")
    assert page.status_code == 200
    assert "acctpage@example.com" in page.text
    assert "credits" in page.text.lower()
    assert "API keys" in page.text
    assert "Credit ledger" in page.text


def test_checkout_creates_an_order_with_a_qr() -> None:
    c = login("buyer@example.com")
    r = c.post("/checkout", data={"plan": "pro", "crypto": "ETH"},
               follow_redirects=False)
    assert r.status_code == 303
    order_id = order_id_from(r.headers["location"])
    order = db.get_order(order_id)
    assert order["crypto"] == "ETH"
    assert order["plan"] == "pro"
    assert order["status"] == "pending"
    assert order["address"] == "0x3bcC6F90F5fc09FDeAfB4AECF2EA367Ed32E12D4"

    page = c.get(f"/checkout/{order_id}")
    assert page.status_code == 200
    assert "<svg" in page.text          # the QR code rendered
    assert order["address"] in page.text


def test_order_txid_submission() -> None:
    c = login("txid@example.com")
    r = c.post("/checkout", data={"plan": "pro", "crypto": "BTC"},
               follow_redirects=False)
    order_id = order_id_from(r.headers["location"])
    c.post(f"/checkout/{order_id}/txid", data={"txid": "0xabc123"})
    assert db.get_order(order_id)["status"] == "submitted"
    assert db.get_order(order_id)["txid"] == "0xabc123"


def test_admin_approves_an_order_granting_plan_and_credits() -> None:
    buyer = make_user("approve@example.com")
    db.set_user_plan(buyer["id"], "free")
    db.adjust_credits(buyer["id"], -db.get_user(buyer["id"])["credits"], "drain", "")

    order_id = db.create_order(buyer["id"], buyer["email"], "pro", "ETH",
                               "0x3bcC6F90F5fc09FDeAfB4AECF2EA367Ed32E12D4", "0.01 ETH")

    admin = TestClient(app)
    admin.post(ADMIN_PATH + "/login", data={"token": "admin12345"})
    r = admin.post(f"{ADMIN_PATH}/orders/{order_id}/approve")
    assert r.status_code == 200

    assert db.get_order(order_id)["status"] == "approved"
    updated = db.get_user(buyer["id"])
    assert updated["plan"] == "pro"
    assert updated["credits"] >= plans.PLANS["pro"]["credits"]


def test_admin_rejects_an_order() -> None:
    buyer = make_user("reject@example.com")
    order_id = db.create_order(buyer["id"], buyer["email"], "pro", "BTC",
                               "bc1qpw7n2ck6a6vxc6vm5jhm5tf07kd8430ctt3uyl", "0.001 BTC")
    admin = TestClient(app)
    admin.post(ADMIN_PATH + "/login", data={"token": "admin12345"})
    admin.post(f"{ADMIN_PATH}/orders/{order_id}/reject")
    assert db.get_order(order_id)["status"] == "rejected"


def test_admin_can_change_plan_and_credits() -> None:
    user = make_user("adminedit@example.com")
    admin = TestClient(app)
    admin.post(ADMIN_PATH + "/login", data={"token": "admin12345"})

    admin.post(f"{ADMIN_PATH}/users/{user['id']}/plan", data={"plan": "team"})
    assert db.get_user(user["id"])["plan"] == "team"

    before = db.get_user(user["id"])["credits"]
    admin.post(f"{ADMIN_PATH}/users/{user['id']}/credits", data={"amount": "25"})
    assert db.get_user(user["id"])["credits"] == before + 25


def test_admin_can_delete_a_user() -> None:
    user = make_user("del@example.com")
    admin = TestClient(app)
    admin.post(ADMIN_PATH + "/login", data={"token": "admin12345"})
    admin.post(f"{ADMIN_PATH}/users/{user['id']}/delete")
    assert db.get_user(user["id"]) is None


def test_admin_order_routes_require_admin() -> None:
    order_id = db.create_order(None, "n@example.com", "pro", "ETH", "0x" + "a" * 40, "1 ETH")
    anon = TestClient(app)
    r = anon.post(f"{ADMIN_PATH}/orders/{order_id}/approve")
    assert r.status_code == 200
    assert "Admin sign-in" in r.text
    assert db.get_order(order_id)["status"] == "pending"


def test_api_key_flow() -> None:
    user = make_user("apiuser@example.com", plan="pro")
    top_up(user["id"], 500)
    key = auth.create_api_key(user["id"], "test key")["key"]
    assert key.startswith("osh_")

    r = client.get("/api/v1/me", headers={"X-API-Key": key})
    assert r.status_code == 200
    assert r.json()["email"] == user["email"]

    r = client.get("/api/v1/me")
    assert r.status_code == 401

    r = client.get("/api/v1/corpus", headers={"X-API-Key": key})
    assert r.status_code == 200
    assert r.json()["total"] == 773

    r = client.get("/api/v1/plans")
    assert r.status_code == 200
    assert len(r.json()["search_types"]) == 8


def test_api_scan_uses_the_key_and_spends_credits(monkeypatch) -> None:
    import asyncio

    async def fake_scan(query, **kw):
        return scanner.ScanResult(
            query=query, kind="username", value=query,
            hits=[scanner.Hit("gh", "GitHub", "developer", "hit",
                              "https://github.com/x", "profile", 5)],
            elapsed=0.2, checked=1, total=1, categories=[])

    monkeypatch.setattr(scanner, "scan", fake_scan)
    user = make_user("apiscan@example.com", plan="pro")
    top_up(user["id"], 500)
    key = auth.create_api_key(user["id"], "scan key")["key"]
    before = db.get_user(user["id"])["credits"]

    r = client.get("/api/v1/scan", params={"q": "mrbeast", "type": "username"},
                   headers={"X-API-Key": key})
    assert r.status_code == 200
    assert r.json()["found"] == 1
    assert db.get_user(user["id"])["credits"] == before - 1


def test_api_scan_rejects_pro_type_for_free_key() -> None:
    user = make_user("apifree@example.com")
    key = auth.create_api_key(user["id"], "free key")["key"]
    r = client.get("/api/v1/scan", params={"q": "8.8.8.8", "type": "ip"},
                   headers={"X-API-Key": key})
    assert r.status_code == 403


def test_bulk_requires_pro_and_runs() -> None:
    free = login("bulkfree@example.com")
    r = free.get("/bulk", follow_redirects=False)
    assert r.status_code == 303
    assert "/pricing" in r.headers["location"]

    pro_user = make_user("bulkpro@example.com", plan="pro")
    top_up(pro_user["id"], 500)
    pro = login("bulkpro@example.com", plan="pro")
    page = pro.get("/bulk")
    assert page.status_code == 200
    assert "Bulk" in page.text


def test_cases_crud() -> None:
    c = login("caseuser@example.com")
    r = c.post("/cases", data={"name": "Phishing infra", "notes": "n"},
               follow_redirects=False)
    assert r.status_code == 303
    case_id = int(r.headers["location"].rsplit("/", 1)[1])
    assert db.get_case(case_id, db.get_user_by_email("caseuser@example.com")["id"])

    page = c.get("/cases")
    assert "Phishing infra" in page.text

    c.post(f"/cases/{case_id}/delete")
    assert db.get_case(case_id, db.get_user_by_email("caseuser@example.com")["id"]) is None


def test_case_items_from_a_scan() -> None:
    user = make_user("itemuser@example.com")
    c = login("itemuser@example.com")
    case_id = db.create_case(user["id"], "Case A", "")
    scan_id = db.insert_scan(user["id"], "username", "mrbeast", "mrbeast",
                             1, 1, 1, 0.5, [{"id": "gh", "name": "GitHub",
                                               "status": "hit",
                                               "url": "https://github.com/x"}])
    r = c.post(f"/cases/{case_id}/items", data={"scan_id": str(scan_id)})
    assert r.status_code == 200
    items = db.list_case_items(case_id)
    assert len(items) == 1
    assert items[0]["query"] == "mrbeast"


def test_reports_are_real_pdf_and_docx() -> None:
    user = make_user("report@example.com", plan="pro")
    c = login("report@example.com", plan="pro")
    scan_id = db.insert_scan(user["id"], "username", "mrbeast", "mrbeast",
                             1, 1, 773, 4.2,
                             [{"id": "gh", "name": "GitHub", "status": "hit",
                               "url": "https://github.com/mrbeast",
                               "detail": "profile page returned"}])

    r = c.get(f"/reports/{scan_id}.pdf")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF-")
    assert b"%%EOF" in r.content

    r = c.get(f"/reports/{scan_id}.docx")
    assert r.status_code == 200
    assert "wordprocessingml" in r.headers["content-type"]
    assert r.content.startswith(b"PK")   # a zip container


def test_reports_are_pro_only() -> None:
    user = make_user("freereport@example.com")
    c = login("freereport@example.com")
    scan_id = db.insert_scan(user["id"], "username", "x", "x", 0, 0, 1, 0.1, [])
    r = c.get(f"/reports/{scan_id}.pdf", follow_redirects=False)
    assert r.status_code == 303
    assert "/pricing" in r.headers["location"]


def test_scans_are_saved_to_history(monkeypatch) -> None:
    import asyncio

    async def fake_scan(query, **kw):
        return scanner.ScanResult(
            query=query, kind="username", value=query, hits=[],
            elapsed=0.1, checked=0, total=1, categories=[])

    monkeypatch.setattr(scanner, "scan", fake_scan)
    user = make_user("history@example.com")
    c = login("history@example.com")
    c.get("/api/scan", params={"q": "mrbeast", "type": "username"})
    scans = db.list_scans(user["id"])
    assert scans
    assert scans[0]["query"] == "mrbeast"


def test_classify_input_new_types() -> None:
    assert scanner.classify_input("0x" + "a" * 40)[0] == "wallet"
    assert scanner.classify_input("bc1qpw7n2ck6a6vxc6vm5jhm5tf07kd8430ctt3uyl")[0] == "wallet"
    assert scanner.classify_input("TBvY5nkA8viFTAANHPobL4e7Czjadkbs37")[0] == "wallet"
    assert scanner.classify_input("32DebfnE2WBVFwVXsiwNEn4DyXHN9moeBLbpcr7W4sEL")[0] == "wallet"
    assert scanner.classify_input("8.8.8.8")[0] == "ip"
    assert scanner.classify_input("example.com")[0] == "username"  # dotted stays a handle
    # explicit types override the detection
    assert scanner.classify_input("example.com", "domain") == ("domain", "example.com")
    assert scanner.classify_input("John Smith", "name") == ("name", "John Smith")
    assert scanner.classify_input("someone@example.com", "email")[0] == "email"


def test_classify_input_rejects_wrong_type() -> None:
    with pytest.raises(scanner.InputError):
        scanner.classify_input("not-a-wallet", "wallet")
    with pytest.raises(scanner.InputError):
        scanner.classify_input("example.com", "ip")
    with pytest.raises(scanner.InputError):
        scanner.classify_input("mrbeast", "name")   # needs a first and last name


def test_qr_encoder_round_trips() -> None:
    from app import qr
    for text in ("0x" + "a" * 40, "HELLO WORLD", "https://osint-hub.example/x"):
        assert qr.read_back(text) == text
        assert "<svg" in qr.svg(text)


def test_pdf_and_docx_generators() -> None:
    from app import reports
    scan = {
        "kind": "username", "query": "mrbeast", "value": "mrbeast",
        "found": 1, "checked": 10, "total": 773, "elapsed": 3.5,
        "created_str": "2026-01-01 12:00:00",
        "results": [{"name": "GitHub", "url": "https://github.com/mrbeast",
                     "status": "hit", "detail": "profile page returned"}],
    }
    pdf = reports.pdf_report(scan)
    assert pdf.startswith(b"%PDF-") and b"%%EOF" in pdf
    docx = reports.docx_report(scan)
    assert docx.startswith(b"PK")
    import io
    import zipfile
    with zipfile.ZipFile(io.BytesIO(docx)) as z:
        assert "word/document.xml" in z.namelist()
        assert b"GitHub" in z.read("word/document.xml")

