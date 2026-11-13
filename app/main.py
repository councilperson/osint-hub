"""OSINT Hub — a live open-source-intelligence search engine.

Scans a username across hundreds of public endpoints and streams each result
back as the source answers. Supports eight identifier types (phone, email,
username, name, wallet, IP, domain, image), accounts, credits, an API, case
storage and crypto-only checkout.

Ethics: built for lawful, authorized research (your own assets, consensual
targets, security research within scope). It deliberately excludes anything
that would dox a person: no people-search brokers, no address aggregation,
no login-walled scraping.
"""
from __future__ import annotations

import asyncio
import datetime
import hashlib
import hmac
import json
import logging
import os
import re
import time
import urllib.parse
from pathlib import Path

import httpx
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import (JSONResponse, PlainTextResponse,
                               RedirectResponse, Response)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from . import (auth, backup, db, monitor, plans, pro_reports, qr, reports,
               reseller, scanner, security, services, stream)

BASE = Path(__file__).resolve().parent
log = logging.getLogger("osint.main")

# restore the DB from off-box backup (no-op unless BACKUP_* env vars are set)
backup.restore(db.DB_PATH)

app = FastAPI(title="OSINT Hub", docs_url=None, redoc_url=None, openapi_url=None,
              lifespan=backup.lifespan_for(lambda: db.DB_PATH))
templates = Jinja2Templates(directory=str(BASE / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
db.init()
security.log_production_warnings()

templates.env.filters.setdefault("br", lambda s: s)
templates.env.filters["safe_url"] = security.safe_url


# --------------------------------------------------------------------------
# owner account (OWNER_EMAIL / OWNER_PASSWORD)
# --------------------------------------------------------------------------

def _owner_email() -> str:
    return auth.normalise_email(os.environ.get("OWNER_EMAIL", "owner@osint-hub.local"))


def _owner_enabled() -> bool:
    """The owner panel only exists when OWNER_PASSWORD is configured — otherwise
    anybody could sign up with the owner address and inherit it."""
    return bool(os.environ.get("OWNER_PASSWORD", ""))


def _is_owner(user: dict | None) -> bool:
    return bool(user and _owner_enabled()
                and auth.normalise_email(user.get("email", "")) == _owner_email())


def _bootstrap_owner() -> None:
    """Create/refresh the owner account. The Team plan is set every boot, but the
    starting credits are granted exactly once (tracked in the ledger), so a
    restart or redeploy no longer hands out another 2,000 credits."""
    password = os.environ.get("OWNER_PASSWORD", "")
    if not password:
        return
    email = _owner_email()
    owner = db.get_user_by_email(email)
    if not owner:
        try:
            owner = auth.create_user(email, password)
        except auth.AuthError as exc:
            log.error("owner account could not be created: %s", exc)
            return
    elif not auth.verify_password(password, owner["password_hash"]):
        # The env var is the source of truth for the owner login. This also
        # locks out anyone who registered the owner address before it was set.
        db.set_user_password(owner["id"], auth.hash_password(password))
        db.delete_sessions_for_user(owner["id"])
    if owner.get("plan") != "team":
        db.set_user_plan(owner["id"], "team")
    if not db.has_ledger_entry(owner["id"], "owner grant", "init"):
        auth.grant_credits(owner["id"], plans.PLANS["team"]["credits"], "owner grant", "init")


_bootstrap_owner()


def _done(section_title: str, text: str) -> dict:
    return {"summary": services.summary_bad(section_title),
            "sections": [{"title": section_title, "kind": "text", "text": text}]}


# --------------------------------------------------------------------------
# hidden admin path: derived from the token so it's never linked in the UI
# --------------------------------------------------------------------------
_token_seed = security.admin_token()
ADMIN_PATH = (
    os.environ.get("ADMIN_PATH", "").rstrip("/")
    or "/hq-" + hashlib.sha256(_token_seed.encode()).hexdigest()[:10]
)


# --------------------------------------------------------------------------
# current user / plan / credits
# --------------------------------------------------------------------------

def _session_token(request: Request) -> str:
    return request.cookies.get(auth.SESSION_COOKIE, "")


def _plan_key(plan_id: str) -> str:
    """The credit-period key: a day for free, a month for paid plans."""
    plan = plans.get_plan(plan_id)
    now = datetime.datetime.now()
    if plan["daily_credits"]:
        return now.strftime("%Y-%m-%d")
    return now.strftime("%Y-%m")


def _refresh_credits(user: dict | None) -> dict | None:
    """Top up the user's allowance for the current period, once per period."""
    if not user:
        return None
    plan = plans.get_plan(auth.effective_plan(user))
    allowance = plan["daily_credits"] or plan["credits"]
    if allowance <= 0:
        return user
    key = _plan_key(plan["id"])
    db.grant_daily_credits(user["id"], key, allowance)
    return db.get_user(user["id"])


@app.middleware("http")
async def _session_state(request: Request, call_next):
    """Resolve the signed-in user and expose plan state to every template.

    Also: rejects cross-site form posts (CSRF) and adds security headers."""
    if not security.same_origin(request):
        resp = PlainTextResponse(
            "This form was submitted from another site, so it was blocked. "
            "Reload the page and try again.", status_code=403)
        security.add_security_headers(request, resp)
        return resp
    if request.url.path.startswith("/static/"):
        resp = await call_next(request)
        security.add_security_headers(request, resp)
        return resp
    user = auth.user_for_token(_session_token(request))
    site_pro = db.has_pro()          # operator licence: unlocks Pro for everyone
    if user:
        user = _refresh_credits(user)
        db.touch_user(user["id"])
    request.state.user = user
    request.state.plan = auth.effective_plan(user)
    request.state.plan_info = auth.plan_of(user)
    request.state.credits = auth.credits_of(user)
    request.state.pro = site_pro or auth.is_pro(user)
    request.state.site_pro = site_pro
    resp = await call_next(request)
    security.add_security_headers(request, resp)
    return resp


def _require_user(request: Request) -> dict | None:
    """Return the user, or a redirect to the login page."""
    if request.state.user:
        return request.state.user
    return None


def _login_redirect(request: Request, next_path: str = "/") -> RedirectResponse:
    target = urllib.parse.quote(next_path or "/", safe="")
    return RedirectResponse(f"/login?next={target}", status_code=303)


def _is_pro(request: Request) -> bool:
    return bool(request.state.pro)


def _spend(request: Request, kind: str, ref: str = "") -> tuple[bool, str]:
    """Charge a search against the user's credit balance (atomically, so two
    searches fired at once cannot both spend the same credits)."""
    user = request.state.user
    if not user:
        return False, "Sign in to run a search."
    cost = plans.type_cost(kind)
    new_balance = auth.try_spend(user["id"], cost, f"{kind} search", ref)
    if new_balance is None:
        balance = auth.credits_of(db.get_user(user["id"]))
        return False, (f"This search costs {cost} credit{'s' if cost != 1 else ''} "
                       f"and your balance is {balance}. "
                       f"Top up on the pricing page or wait for your next allowance.")
    request.state.credits = new_balance
    return True, ""


def _refund(request: Request, kind: str, ref: str = "") -> None:
    user = request.state.user
    if user:
        request.state.credits = auth.refund(
            user["id"], plans.type_cost(kind), f"{kind} search refund (failed)", ref)


def _resolve_kind(query: str, kind: str | None) -> tuple[str, str]:
    """Classify the query BEFORE gating and charging, so an auto-detected Pro
    type (e.g. a pasted wallet address) is gated and priced as that type."""
    return scanner.classify_input(query, kind)


def _safe_error(exc: Exception) -> str:
    """A short, user-facing description of an unexpected failure."""
    if isinstance(exc, (httpx.TimeoutException, asyncio.TimeoutError)):
        return "The source took too long to answer. Try again in a minute."
    if isinstance(exc, httpx.HTTPError):
        return "Could not reach the source (network error). Try again in a minute."
    return f"Something went wrong ({type(exc).__name__}). Try again in a minute."


def _gate_type(request: Request, kind: str) -> str | None:
    """Return an error message when the plan may not use this search type."""
    if plans.is_pro_type(kind) and not _is_pro(request):
        return (f"{plans.TYPE_BY_ID[kind]['label']} search is a Pro feature. "
                f"Upgrade to unlock it.")
    return None



TOOLS: dict[str, dict] = {
    "whois": {
        "title": "Domain ownership (RDAP)",
        "icon": "&#129534;",
        "cat": "domains",
        "blurb": "Registrar, creation/expiry dates, nameservers and status via the modern WHOIS (RDAP).",
        "placeholder": "example.com",
        "fn": services.rdap_whois,
    },
    "dns": {
        "title": "DNS records",
        "icon": "&#128225;",
        "cat": "domains",
        "blurb": "A/AAAA/CNAME/MX/NS/TXT/SOA lookups over the Cloudflare DoH JSON API.",
        "placeholder": "example.com",
        "fn": services.dns_records,
    },
    "ip": {
        "title": "IP & network intelligence",
        "icon": "&#127758;",
        "cat": "network",
        "blurb": "Resolve hosts, geolocate an IP, view ISP/ASN, reverse DNS and network flags.",
        "placeholder": "example.com or 1.1.1.1",
        "fn": services.ip_info,
    },
    "headers": {
        "title": "HTTP headers & redirect chain",
        "icon": "&#128640;",
        "cat": "network",
        "blurb": "Follow redirects manually and inspect final response headers, including missing security headers.",
        "placeholder": "https://example.com",
        "fn": services.http_headers,
    },
    "username": {
        "title": "Username presence check",
        "icon": "&#129701;",
        "cat": "identity",
        "blurb": "Public profile existence across platforms. Free: one handle, 10 platforms. Pro: all 19 + batch handles.",
        "placeholder": "satoru",
        "fn": services.username_check,
    },
    "email": {
        "title": "Email checks",
        "icon": "&#9993;",
        "cat": "identity",
        "blurb": "Syntax, MX deliverability, disposable-domain flagging and Gravatar existence.",
        "placeholder": "someone@example.com",
        "fn": services.email_check,
    },
    "url": {
        "title": "URL analysis",
        "icon": "&#128279;",
        "cat": "web",
        "blurb": "Anatomy of a URL, structural red flags (IP hosts, punycode, shorteners, userinfo) and redirect resolution.",
        "placeholder": "https://example.com/path?q=1",
        "fn": services.url_analyze,
    },
}

RESOURCES: dict[str, list[dict]] = {
    "Search, web & dorks": [
        {"name": "Google advanced operators", "url": "https://support.google.com/websearch/answer/2466433",
         "note": "site:, inurl:, filetype:, cache: — the core skill of web recon (official doc)."},
        {"name": "Google Trends", "url": "https://trends.google.com", "note": "relative search interest over time."},
        {"name": "Bing advanced search", "url": "https://www.bing.com/advanced_search",
         "note": "different index than Google — always worth a second pass."},
        {"name": "DuckDuckGo !bangs", "url": "https://duckduckgo.com/bangs",
         "note": "meta-search shortcuts (!g, !yt, !wiki…)."},
        {"name": "Wayback Machine", "url": "https://web.archive.org", "note": "see how a site looked years ago."},
        {"name": "archive.today", "url": "https://archive.today", "note": "independent snapshot archive; often has pages the Wayback missed."},
        {"name": "Startpage", "url": "https://www.startpage.com", "note": "Google results without tracking; useful for a cleaner second pass."},
        {"name": "Mojeek", "url": "https://www.mojeek.com", "note": "independent crawler with its own index — a genuinely different result set."},
        {"name": "Ahmia", "url": "https://ahmia.fi", "note": "public index of Tor onion sites; useful for leak-site awareness."},
        {"name": "Google Hacking Database (GHDB)", "url": "https://www.exploit-db.com/google-hacking-database",
         "note": "hundreds of community-submitted dorks for finding exposed files and panels."},
    ],
    "Domains, DNS & network": [
        {"name": "rdap.org", "url": "https://rdap.org", "note": "the free WHOIS-replacement layer this site uses."},
        {"name": "Cloudflare DoH", "url": "https://developers.cloudflare.com/1.1.1.1/infrastructure/dns-over-https/",
         "note": "DNS-over-HTTPS JSON API used for the DNS tool."},
        {"name": "ICANN Lookup", "url": "https://lookup.icann.org", "note": "authoritative gTLD registration data."},
        {"name": "IPinfo", "url": "https://ipinfo.io", "note": "polished IP geolocation; free tier."},
        {"name": "RIPEstat", "url": "https://stat.ripe.net", "note": "deep ASN/route/routing-history data for European and global allocations."},
        {"name": "bgp.he.net", "url": "https://bgp.he.net", "note": "Hurricane Edge: free ASN, peering and prefix explorer."},
        {"name": "ViewDNS.info", "url": "https://viewdns.info", "note": "reverse IP lookup & friends (data is historical, not live)."},
        {"name": "crt.sh", "url": "https://crt.sh", "note": "public Certificate Transparency logs — great for subdomain discovery."},
        {"name": "DNS Dumpster", "url": "https://dnsdumpster.com", "note": "one-shot DNS/graph recon of a domain."},
        {"name": "MXToolbox", "url": "https://mxtoolbox.com", "note": "fast MX/SPF/DKIM/blacklist checks for mail infrastructure."},
        {"name": "DNSChecker.org", "url": "https://dnschecker.org", "note": "verify DNS propagation from dozens of global resolvers."},
        {"name": "HackerTarget", "url": "https://hackertarget.com", "note": "free web API tools: zone transfer attempt, open-port check, header scan."},
        {"name": "IntoDNS", "url": "https://intodns.com", "note": "health report on a domain's DNS configuration and nameservers."},
    ],
    "Infrastructure & exposed devices": [
        {"name": "Shodan", "url": "https://www.shodan.io", "note": "search engine for internet-connected devices. Powerful but sensitive — your own scope first."},
        {"name": "Censys Search", "url": "https://censys.io", "note": "similar to Shodan; strong TLS certificate index and analytics."},
        {"name": "ZoomEye", "url": "https://www.zoomeye.org", "note": "Chinese device fingerprinting index with big historic coverage."},
        {"name": "fofa", "url": "https://fofa.info", "note": "asset and vulnerability surface search."},
    ],
    "Reputation & threat intel": [
        {"name": "VirusTotal", "url": "https://www.virustotal.com", "note": "paste a URL / file hash — 70+ engines scan it."},
        {"name": "AbuseIPDB", "url": "https://www.abuseipdb.com", "note": "crowd-sourced abuse reports per IP."},
        {"name": "URLhaus", "url": "https://urlhaus.abuse.ch", "note": "malware distribution URL tracker by abuse.ch."},
        {"name": "Talos Intelligence", "url": "https://www.talosintelligence.com", "note": "Cisco reputation lookups for IP/domain."},
        {"name": "MalwareBazaar", "url": "https://bazaar.abuse.ch", "note": "malware sample repository, free hashes + samples."},
        {"name": "urlscan.io", "url": "https://urlscan.io", "note": "sandboxes any URL and records the requests, DOM and screenshots."},
        {"name": "Joe Sandbox", "url": "https://www.joesandbox.com", "note": "deep behavioral malware reports; public ones are free to search."},
        {"name": "ThreatFox", "url": "https://threatfox.abuse.ch", "note": "searchable IOCs shared by abuse.ch's community."},
    ],
    "Breaches & exposed data": [
        {"name": "Have I Been Pwned?", "url": "https://haveibeenpwned.com", "note": "the official breach-exposure checker; built into this site's Pwned page."},
        {"name": "DeHashed", "url": "https://dehashed.com", "note": "paid aggregator of breach data. Legality varies by jurisdiction."},
        {"name": "Intelligence X", "url": "https://intelx.io", "note": "search engine for pastes, dark-web and leaks; freemium."},
    ],
    "Usernames & identities": [
        {"name": "Sherlock (open source)", "url": "https://github.com/sherlock-project/sherlock",
         "note": "the community's CLI username checker — same idea as this site's username tool."},
        {"name": "WhatsMyName Web", "url": "https://whatsmyname.app", "note": "web front-end for the WhatsMyName username list."},
        {"name": "Maigret", "url": "https://github.com/soxoj/maigret",
         "note": "another open-source username checker with many more sites."},
        {"name": "Gravatar", "url": "https://en.gravatar.com", "note": "email→avatar checks rely on this (what the email tool uses)."},
    ],
    "Imagery, maps & geo": [
        {"name": "Google Earth Web", "url": "https://earth.google.com/web", "note": "free historical satellite imagery in places."},
        {"name": "Bing Maps", "url": "https://www.bing.com/maps", "note": "different aerial coverage than Google; periodic orthophotos."},
        {"name": "Yandex Maps", "url": "https://yandex.com/maps", "note": "strong street-level coverage in Eastern Europe / Central Asia."},
        {"name": "Sentinel Hub playground", "url": "https://apps.sentinel-hub.com/eo-browser/", "note": "free current satellite imagery, several bands."},
        {"name": "EXIFTool", "url": "https://exiftool.org", "note": "the standard tool for photo metadata (GPS, timestamps, device)."},
        {"name": "geohints", "url": "https://geohints.com",
         "note": "reference of country-specific visual markers (paint, plates, poles)."},
        {"name": "SunCalc", "url": "https://www.suncalc.org", "note": "sun position and shadows for any time/place — classic imagery verification."},
        {"name": "OpenStreetMap", "url": "https://www.openstreetmap.org", "note": "crowdsourced map with edits historians can inspect (osm history)."},
        {"name": "PeakVisor web", "url": "https://peakvisor.com", "note": "mountain-panorama identification for geolocating terrain photos."},
    ],
    "Transport, maritime & aircraft": [
        {"name": "MarineTraffic", "url": "https://www.marinetraffic.com", "note": "public vessel positions via AIS."},
        {"name": "FlightRadar24", "url": "https://www.flightradar24.com", "note": "public air traffic; used by journalists for jet-tracking."},
        {"name": "ADS-B Exchange", "url": "https://globe.adsbexchange.com", "note": "unfiltered (non-blocking) aircraft tracker — see what FR24 hides."},
        {"name": "VesselFinder", "url": "https://www.vesselfinder.com", "note": "second AIS source with different coverage than MarineTraffic."},
    ],
    "Social media intel": [
        {"name": "r/osint", "url": "https://www.reddit.com/r/osint/", "note": "the best active community for tradecraft questions."},
        {"name": "OSINT Curious", "url": "https://www.osintcurio.us", "note": "articles, 10-minute tips and podcasts from practitioners."},
    ],
    "Methodology & tradecraft": [
        {"name": "OSINT Framework", "url": "https://osintframework.com", "note": "huge curated tree of OSINT sources."},
        {"name": "IntelTechniques", "url": "https://inteltechniques.com", "note": "Michael Bazzell's tools and books on lawful investigation."},
        {"name": "Bellingcat toolkit", "url": "https://bellingcat.gitbook.io/toolkit",
         "note": "the industry reference, used by professional investigators and journalists."},
        {"name": "OSINT Techniques links", "url": "https://osinttechniques.com/osint-links.html",
         "note": "another broad curated link dump maintained by investigators."},
        {"name": "OPSEC reading lists", "url": "https://github.com/jakecreps/OSINT-Collection", "note": "collection of tools and reading lists."},
        {"name": "UK ICO GDPR guidance", "url": "https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/",
         "note": "if you handle personal data, know your lawful basis."},
        {"name": "Sector035 (Week in OSINT)", "url": "https://sector035.nl", "note": "long-running weekly digest of new tools and techniques."},
    ],
}

# Pro-only "private desk": deeper, more technical sources. All public and
# lawful — the gate is convenience/curation, not legality.
PRO_RESOURCES: dict[str, list[dict]] = {
    "Private desk · Infrastructure recon (authorized scope only)": [
        {"name": "Nmap", "url": "https://nmap.org", "note": "the standard scanner — run it only against systems you own or are authorized to test."},
        {"name": "OWASP Amass", "url": "https://github.com/owasp-amass/amass", "note": "deep subdomain & asset enumeration for scoped engagements."},
        {"name": "subfinder", "url": "https://github.com/projectdiscovery/subfinder", "note": "fast passive subdomain discovery; pairs with httpx."},
        {"name": "httpx", "url": "https://github.com/projectdiscovery/httpx", "note": "bulk probe of live web services across a target list."},
        {"name": "nuclei", "url": "https://github.com/projectdiscovery/nuclei", "note": "template-driven vulnerability scanning — authorized targets only."},
        {"name": "Netlas.io", "url": "https://netlas.io", "note": "internet asset inventory similar to Shodan with a generous free API."},
        {"name": "GreyNoise (community)", "url": "https://viz.greynoise.io", "note": "tells you whether an IP scanning you is internet background noise or targeted."},
    ],
    "Private desk · Threat feeds & pipelines": [
        {"name": "AlienVault OTX", "url": "https://otx.alienvault.com", "note": "community threat-intel pulses; free API for indicator feeds."},
        {"name": "OpenPhish", "url": "https://openphish.com", "note": "continuously updated live phishing URL feed (free community stream)."},
        {"name": "Feodo Tracker", "url": "https://feodotracker.abuse.ch", "note": "C2 server IP/blocklists from the abuse.ch botnet tracker."},
        {"name": "MISP", "url": "https://www.misp-project.org", "note": "self-host threat-sharing platform; feeds from public communities."},
        {"name": "YARA", "url": "https://virustotal.github.io/yara/", "note": "write signature rules against malware families and specimens."},
    ],
    "Private desk · Media verification": [
        {"name": "InVID / WeVerify plugin", "url": "https://www.invid-project.eu/tools-and-services/invid-verification-plugin/",
         "note": "browser toolkit: frame-by-frame breakdown, reverse image search across engines, thumbnails."},
        {"name": "RevEye", "url": "https://chromewebstore.google.com/detail/reverse-image-search/kljmejbpkpbncbppnpigbiohmlenhece",
         "note": "right-click any image into Google/Bing/Yandex/TinEye simultaneously."},
        {"name": "SpiderFoot (self-run)", "url": "https://github.com/smicallef/spiderfoot", "note": "automates 200+ public data sources into one graph; you host it, you control it."},
        {"name": "Wayback CDX API", "url": "https://github.com/internetarchive/wayback",
         "note": "query the archive's full URL index directly — diff what a page looked like over years."},
    ],
    "Private desk · Professional reading": [
        {"name": "Verification Handbook", "url": "https://datajournalism.com/read/handbook/verification-3",
         "note": "the standard text on verifying UGC media, by the EJC."},
        {"name": "First Draft essential guides", "url": "https://firstdraftnews.org/articles-en/",
         "note": "practical guides on tracing social content and misinformation."},
        {"name": "Bellingcat case archives", "url": "https://www.bellingcat.com/category/case-studies/",
         "note": "study how world-class investigations were actually done, step by step."},
        {"name": "Digital First Toolkit", "url": "https://digitalfirst.journalism.com",
         "note": "news-industry maintained link library, updated weekly."},
    ],
}


@app.get("/")
async def index(request: Request, c: str = "all"):
    corpus = scanner.load_corpus()
    pro = _is_pro(request)
    endpoints = corpus.for_plan(pro)
    return templates.TemplateResponse(request, "index.html", {
        "endpoint_total": len(endpoints),
        "corpus_total": corpus.total,
        "adult_total": corpus.adult_total,
        "category_count": len(corpus.categories),
        "search_types": plans.SEARCH_TYPES,
        "user": request.state.user,
        "plan": request.state.plan,
        "credits": request.state.credits,
        "pro": pro,
    })


@app.get("/api/scan/stream")
async def scan_stream(request: Request, q: str = "", type: str = ""):
    """Server-Sent Events stream of live scan results."""
    if not q.strip():
        return PlainTextResponse("Missing query parameter 'q'.", status_code=400)
    if not request.state.user:
        return JSONResponse(
            {"error": "signin_required",
             "message": "Log in to run a search. It only takes a moment."},
            status_code=401)
    kind = (type or "").strip().lower() or None
    gate = _gate_type(request, kind) if kind in plans.TYPE_BY_ID else None
    if gate:
        return JSONResponse({"error": "upgrade_required", "message": gate},
                            status_code=403)
    try:
        kind, _ = _resolve_kind(q.strip(), kind)
    except scanner.InputError as exc:
        # streamed as an SSE error so the page can show it inline; no charge
        return stream.error_response(str(exc))
    gate = _gate_type(request, kind)
    if gate:
        return JSONResponse({"error": "upgrade_required", "message": gate},
                            status_code=403)
    ok, message = _spend(request, kind, q.strip()[:80])
    if not ok:
        return JSONResponse({"error": "no_credits", "message": message},
                            status_code=402)
    return stream.stream_response(request, q.strip(), kind, _is_pro(request))


@app.get("/api/scan")
async def scan_once(request: Request, q: str = "", type: str = ""):
    """Non-streaming scan — returns the whole result set as JSON."""
    if not q.strip():
        return PlainTextResponse("Missing query parameter 'q'.", status_code=400)
    if not request.state.user:
        return JSONResponse(
            {"error": "signin_required",
             "message": "Log in to run a search. It only takes a moment."},
            status_code=401)
    kind = (type or "").strip().lower() or None
    gate = _gate_type(request, kind) if kind in plans.TYPE_BY_ID else None
    if gate:
        return JSONResponse({"error": "upgrade_required", "message": gate},
                            status_code=403)
    try:
        kind, _ = _resolve_kind(q.strip(), kind)
    except scanner.InputError as exc:
        return PlainTextResponse(str(exc), status_code=400)
    gate = _gate_type(request, kind)
    if gate:
        return JSONResponse({"error": "upgrade_required", "message": gate},
                            status_code=403)
    ref = q.strip()[:80]
    ok, message = _spend(request, kind, ref)
    if not ok:
        return JSONResponse({"error": "no_credits", "message": message},
                            status_code=402)
    try:
        result = await scanner.scan(q.strip(), kind=kind, pro=_is_pro(request))
    except scanner.InputError as exc:
        _refund(request, kind, ref)
        return PlainTextResponse(str(exc), status_code=400)
    except Exception as exc:  # noqa: BLE001
        _refund(request, kind, ref)
        log.warning("scan failed: %r", exc)
        return PlainTextResponse(_safe_error(exc) + " No credits were charged.",
                                 status_code=502)
    _save_scan(request, result)
    return {
        "query": result.query,
        "kind": result.kind,
        "value": result.value,
        "checked": result.checked,
        "total": result.total,
        "found": result.found,
        "elapsed": round(result.elapsed, 2),
        "categories": result.categories,
        "results": [
            {
                "id": h.endpoint_id,
                "name": h.name,
                "category": h.category,
                "status": h.status,
                "url": h.url,
                "detail": h.detail,
                "ms": h.ms,
                "display_name": h.display_name,
                "avatar": h.avatar,
                "meta": h.meta,
            }
            for h in result.hits
        ],
    }


def _scan_payload(result: scanner.ScanResult) -> list[dict]:
    return [
        {
            "id": h.endpoint_id,
            "name": h.name,
            "category": h.category,
            "status": h.status,
            "url": h.url,
            "detail": h.detail,
            "ms": h.ms,
            "display_name": h.display_name,
            "avatar": h.avatar,
            "meta": h.meta,
        }
        for h in result.hits
    ]


def _save_scan(request: Request, result: scanner.ScanResult) -> int:
    """Persist a scan for the signed-in user so it can be exported or filed."""
    user = request.state.user
    if not user:
        return 0
    return db.insert_scan(
        user["id"], result.kind, result.query, result.value, result.found,
        result.checked, result.total, result.elapsed, _scan_payload(result))


# --------------------------------------------------------------------------
# accounts
# --------------------------------------------------------------------------

_login_limiter = security.RateLimiter(limit=10, window=300.0)    # per IP+email
_ip_limiter = security.RateLimiter(limit=40, window=300.0)       # per IP
_signup_limiter = security.RateLimiter(limit=5, window=3600.0)   # per IP
_admin_limiter = security.RateLimiter(limit=5, window=900.0)     # per IP
TOO_MANY = "Too many attempts. Wait a few minutes and try again."


def _safe_next(next_path: str) -> str:
    """Only same-site relative paths are allowed as a post-login redirect."""
    n = (next_path or "/").strip()
    if (not n.startswith("/") or n.startswith(("//", "/\\")) or "\\" in n
            or any(ord(c) < 32 or ord(c) == 127 for c in n)):
        return "/"
    return n


def _session_redirect(request: Request, user_id: int, next_path: str) -> RedirectResponse:
    token = auth.start_session(user_id)
    resp = RedirectResponse(_safe_next(next_path), status_code=303)
    security.set_cookie(resp, request, auth.SESSION_COOKIE, token, auth.SESSION_TTL)
    return resp


def _auth_ctx(request: Request, **extra) -> dict:
    ctx = {
        "user": request.state.user,
        "plan": request.state.plan,
        "plan_info": request.state.plan_info,
        "credits": request.state.credits,
        "pro": _is_pro(request),
    }
    ctx.update(extra)
    return ctx


@app.get("/signup")
async def signup_page(request: Request, next: str = "/"):
    if request.state.user:
        return RedirectResponse("/account", status_code=303)
    return templates.TemplateResponse(request, "signup.html",
                                      _auth_ctx(request, next=next, error=None))


@app.post("/signup")
async def signup_submit(request: Request, email: str = Form(""),
                        password: str = Form(""), confirm: str = Form(""),
                        next: str = Form("/")):
    ip = security.client_ip(request)
    try:
        if password != confirm:
            raise auth.AuthError("The two passwords do not match.")
        if not _signup_limiter.hit(ip):
            raise auth.AuthError("Too many new accounts from your network. Try again later.")
        user = await run_in_threadpool(auth.create_user, email, password)
    except auth.AuthError as exc:
        return templates.TemplateResponse(request, "signup.html",
                                          _auth_ctx(request, next=next, error=str(exc)))
    _refresh_credits(db.get_user(user["id"]))
    return _session_redirect(request, user["id"], next)


@app.get("/login")
async def login_page(request: Request, next: str = "/"):
    if request.state.user:
        return RedirectResponse("/account", status_code=303)
    return templates.TemplateResponse(request, "login.html",
                                      _auth_ctx(request, next=next, error=None))


@app.post("/login")
async def login_submit(request: Request, email: str = Form(""),
                       password: str = Form(""), next: str = Form("/")):
    ip = security.client_ip(request)
    key = f"{ip}|{auth.normalise_email(email)}"
    if not _ip_limiter.hit(ip) or not _login_limiter.hit(key):
        return templates.TemplateResponse(request, "login.html",
                                          _auth_ctx(request, next=next, error=TOO_MANY),
                                          status_code=429)
    try:
        user = await run_in_threadpool(auth.authenticate, email, password)
    except auth.AuthError as exc:
        return templates.TemplateResponse(request, "login.html",
                                          _auth_ctx(request, next=next,
                                                    error=str(exc)))
    _login_limiter.reset(key)
    return _session_redirect(request, user["id"], next)


@app.post("/logout")
@app.get("/logout")
async def logout(request: Request):
    auth.end_session(_session_token(request))
    resp = RedirectResponse("/", status_code=303)
    security.delete_cookie(resp, request, auth.SESSION_COOKIE)
    return resp


@app.get("/account")
async def account_page(request: Request):
    user = request.state.user
    if not user:
        return _login_redirect(request, "/account")

    return templates.TemplateResponse(request, "account.html",
                                      _account_ctx(request, user))


def _owner_ctx(user: dict) -> dict:
    if not _is_owner(user):
        return {}
    users = db.list_users()
    return {
        "is_owner": True,
        "all_users": users,
        "all_orders": db.list_orders(500),
        "all_scans": db.recent_queries(200),
        "plan_options": list(plans.PLANS.values()),
        "stats": {
            "total_users": len(users),
            "total_scans": db.count_rows("scans"),
            "total_orders": db.count_rows("orders"),
            "pro_users": sum(1 for u in users if auth.is_pro(u)),
        },
    }


def _account_ctx(request: Request, user: dict, **extra) -> dict:
    ctx = dict(
        ledger=db.credit_ledger(user["id"], 40),
        scans=db.list_scans(user["id"], 40),
        api_keys=db.list_api_keys(user["id"]),
        new_key=None,
        cases=db.list_cases(user["id"]),
        **_owner_ctx(user),
    )
    ctx.update(extra)
    return _auth_ctx(request, **ctx)


@app.post("/account/api-keys")
async def account_new_key(request: Request, name: str = Form("default")):
    user = request.state.user
    if not user:
        return _login_redirect(request, "/account")
    if not auth.plan_of(user).get("api"):
        return RedirectResponse("/pricing", status_code=303)
    if sum(1 for k in db.list_api_keys(user["id"]) if k["active"]) >= 10:
        return templates.TemplateResponse(request, "account.html", _account_ctx(
            request, user, key_error="You already have 10 active keys — revoke one first."))
    created = auth.create_api_key(user["id"], name)
    return templates.TemplateResponse(request, "account.html", _account_ctx(
        request, user, new_key=created["key"]))


@app.post("/account/api-keys/{key_id}/revoke")
async def account_revoke_key(request: Request, key_id: int):
    user = request.state.user
    if not user:
        return _login_redirect(request, "/account")
    db.revoke_api_key(user["id"], key_id)
    return RedirectResponse("/account", status_code=303)


@app.post("/account/password")
async def account_change_password(request: Request, current: str = Form(""),
                                  password: str = Form(""),
                                  confirm: str = Form("")):
    user = request.state.user
    if not user:
        return _login_redirect(request, "/account")
    error = None
    if not auth.verify_password(current, user["password_hash"]):
        error = "Your current password is not correct."
    elif password != confirm:
        error = "The two new passwords do not match."
    elif len(password) < 8:
        error = "Use a password of at least 8 characters."
    elif len(password) > 512:
        error = "That password is too long."
    if error:
        return templates.TemplateResponse(request, "account.html", _account_ctx(
            request, user, password_error=error))
    db.set_user_password(user["id"], auth.hash_password(password))
    # sign out every other device that knew the old password
    auth.end_other_sessions(user["id"], keep_token=_session_token(request))
    return RedirectResponse("/account", status_code=303)



@app.get("/tools")
async def tools_index(request: Request, c: str = "all"):
    cat = c if c in ("all", "identity", "network", "domains", "web") else "all"
    visible = TOOLS if cat == "all" else {k: v for k, v in TOOLS.items() if v["cat"] == cat}
    breach_count = len(services._BREACH_CACHE.get("data") or [])
    if not breach_count:
        try:
            breach_count = len(await run_in_threadpool(services.breach_catalog))
        except Exception:  # noqa: BLE001 — the count is decoration only
            breach_count = 0
    return templates.TemplateResponse(request, "tools.html", {
        "tools": TOOLS,
        "visible_tools": visible,
        "cat": cat,
        "breach_count": f"{breach_count:,}",
    })


@app.get("/resources")
async def resources(request: Request):
    return templates.TemplateResponse(request, "resources.html", {
        "resources": RESOURCES,
        "is_pro": request.state.pro,
        "pro_count": sum(len(v) for v in PRO_RESOURCES.values()),
    })


@app.get("/resources/private")
async def resources_private(request: Request):
    if not _is_pro(request):
        return RedirectResponse("/pricing", status_code=303)
    return templates.TemplateResponse(request, "resources_private.html", {
        "pro_resources": PRO_RESOURCES,
    })


@app.get("/tool/{tool_id}")
async def tool_page(request: Request, tool_id: str, q: str = ""):
    if tool_id not in TOOLS:
        return PlainTextResponse("Unknown tool", status_code=404)
    return templates.TemplateResponse(request, "tool.html", {
        "tools": TOOLS,
        "tool_id": tool_id,
        "tool": TOOLS[tool_id],
        "q": q,
        "results": None,
        "endpoints_total": scanner.load_corpus().total,
    })


_tool_limiter = security.RateLimiter(limit=30, window=60.0)   # per IP


@app.post("/tool/{tool_id}")
async def tool_run(request: Request, tool_id: str, target: str = Form("")):
    if tool_id not in TOOLS:
        return PlainTextResponse("Unknown tool", status_code=404)
    target = target.strip()[:500]
    pro = _is_pro(request)
    user = request.state.user
    uid = user["id"] if user else None
    results = None

    async def run(fn, *args, **kwargs):
        """Run a blocking lookup in a worker thread so one slow site never
        freezes the whole server, and turn failures into readable sections."""
        try:
            out = await run_in_threadpool(fn, *args, **kwargs)
            db.add_query(tool_id, target, user_id=uid)
            return out
        except services.LookupError as exc:
            return _done("Input problem", str(exc))
        except Exception as exc:  # noqa: BLE001
            log.warning("tool %s failed for %r: %r", tool_id, target, exc)
            db.add_query(tool_id, target, ok=False, user_id=uid)
            return _done(f"Lookup failed for {target!r}", _safe_error(exc))

    if not target:
        results = _done("Input problem", "The input was empty — enter something to look up.")
    elif not _tool_limiter.hit(security.client_ip(request)):
        results = _done("Slow down", "You are running lookups very quickly. "
                                     "Wait a minute and try again.")
    elif tool_id == "username":
        parts = [p for p in re.split(r"[,\s]+", target) if p]
        if len(parts) > 1 and not pro:
            results = _done(
                "Batch checking is a Pro feature",
                "The free plan checks one handle at a time (10 platforms). The Pro "
                "tier unlocks all 19 platforms plus batch checking of up to 10 "
                "handles per run — upgrade on the Pro page.")
        elif len(parts) > 1:
            overflow = max(0, len(parts) - 10)
            results = await run(services.username_check_batch, parts[:10])
            if overflow and results.get("summary"):
                results["summary"]["text"] += f" · {overflow} extra handle(s) ignored (10 max)"
        else:
            results = await run(services.username_check, parts[0],
                                max_platforms=None if pro else 10)
    else:
        results = await run(TOOLS[tool_id]["fn"], target)
    return templates.TemplateResponse(request, "tool.html", {
        "tools": TOOLS,
        "tool_id": tool_id,
        "tool": TOOLS[tool_id],
        "q": target,
        "results": results,
        "endpoints_total": scanner.load_corpus().total,
    })


# --------------------------------------------------------------------------
# pricing and crypto checkout
# --------------------------------------------------------------------------

CRYPTO_OPTIONS = [
    {
        "code": "ETH",
        "name": "Ethereum",
        "symbol": "ETH",
        "icon": "◆",
        "coingecko": "ethereum",
        "address": "0x3bcC6F90F5fc09FDeAfB4AECF2EA367Ed32E12D4",
        "note": "Send on the Ethereum mainnet (ERC-20 network).",
    },
    {
        "code": "BTC",
        "name": "Bitcoin",
        "symbol": "BTC",
        "icon": "₿",
        "coingecko": "bitcoin",
        "address": "bc1qpw7n2ck6a6vxc6vm5jhm5tf07kd8430ctt3uyl",
        "note": "Send on the Bitcoin network (native SegWit address).",
    },
    {
        "code": "SOL",
        "name": "Solana",
        "symbol": "SOL",
        "icon": "◎",
        "coingecko": "solana",
        "address": "32DebfnE2WBVFwVXsiwNEn4DyXHN9moeBLbpcr7W4sEL",
        "note": "Send on the Solana mainnet.",
    },
    {
        "code": "TRX",
        "name": "Tron",
        "symbol": "TRX",
        "icon": "▲",
        "coingecko": "tron",
        "address": "TBvY5nkA8viFTAANHPobL4e7Czjadkbs37",
        "note": "Send on the Tron network (TRC-20).",
    },
]

CRYPTO_BY_CODE = {c["code"]: c for c in CRYPTO_OPTIONS}
_RATE_CACHE: dict = {"data": None, "ts": 0.0}


def crypto_rates() -> dict:
    """USD prices for the accepted coins. Keyless, cached for 10 minutes."""
    now = time.time()
    if _RATE_CACHE["data"] and now - _RATE_CACHE["ts"] < 600:
        return _RATE_CACHE["data"]
    ids = ",".join(c["coingecko"] for c in CRYPTO_OPTIONS)
    try:
        r = httpx.get(
            "https://api.coingecko.com/api/v3/simple/price",
            params={"ids": ids, "vs_currencies": "usd"},
            timeout=8.0, headers={"User-Agent": services.UA})
        r.raise_for_status()
        data = r.json()
        out = {}
        for c in CRYPTO_OPTIONS:
            value = (data.get(c["coingecko"]) or {}).get("usd")
            if value:
                out[c["code"]] = float(value)
        if out:
            _RATE_CACHE.update(data=out, ts=now)
            return out
    except Exception:  # noqa: BLE001 — the price is a convenience, not a gate
        pass
    return _RATE_CACHE["data"] or {}


def _crypto_amount(usd: float, code: str, rates: dict) -> str:
    price = rates.get(code)
    if not price:
        return "—"
    amount = usd / price
    if code == "BTC":
        return f"{amount:.8f} BTC"
    if code == "ETH":
        return f"{amount:.6f} ETH"
    if code == "SOL":
        return f"{amount:.4f} SOL"
    return f"{amount:.2f} TRX"


def _plan_price(plan_id: str) -> float:
    plan = plans.get_plan(plan_id)
    raw = plan["price"].replace("$", "").replace("/mo", "").strip()
    try:
        return float(raw)
    except ValueError:
        return 0.0


async def _rates() -> dict:
    return await run_in_threadpool(crypto_rates)


@app.get("/pricing")
async def pricing_page(request: Request):
    rates = await _rates()
    return templates.TemplateResponse(request, "pricing.html", _auth_ctx(
        request,
        plan_cards=[_pricing_card(p, rates) for p in plans.PLANS.values()],
        crypto_options=CRYPTO_OPTIONS,
        search_types=plans.SEARCH_TYPES,
    ))


def _pricing_card(plan: dict, rates: dict) -> dict:
    usd = _plan_price(plan["id"])
    out = dict(plan)
    out["usd"] = usd
    out["crypto_amounts"] = {
        c["code"]: _crypto_amount(usd, c["code"], rates) for c in CRYPTO_OPTIONS
    } if usd else {}
    return out


@app.get("/pro")
async def pro_page(request: Request):
    """Legacy operator licence page — the admin can unlock Pro site-wide here;
    everyone else is pointed at the pricing page."""
    return _pro_page(request)


@app.get("/checkout")
async def checkout_page(request: Request, plan: str = "pro"):
    if _is_pro(request):
        return RedirectResponse("/account", status_code=303)
    plan_id = plan if plan in plans.PLANS else "pro"
    if plan_id == "free":
        return RedirectResponse("/pricing", status_code=303)
    rates = await _rates()
    info = plans.get_plan(plan_id)
    usd = _plan_price(plan_id)
    return templates.TemplateResponse(request, "checkout.html", _auth_ctx(
        request,
        crypto_options=CRYPTO_OPTIONS,
        plan=info,
        plan_id=plan_id,
        usd=usd,
        rates=rates,
        amounts={c["code"]: _crypto_amount(usd, c["code"], rates)
                 for c in CRYPTO_OPTIONS},
        error=None,
        order=None,
    ))


def _order_token(order_id: int) -> str:
    """Unguessable per-order key, so order pages can't be enumerated by id."""
    return hmac.new(security.secret_key().encode(), f"order:{order_id}".encode(),
                    hashlib.sha256).hexdigest()[:24]


def _order_url(order_id: int) -> str:
    return f"/checkout/{order_id}?k={_order_token(order_id)}"


def _can_view_order(request: Request, order: dict, k: str) -> bool:
    user = request.state.user
    if user and order.get("user_id") == user["id"]:
        return True
    if _is_admin(request) or _is_owner(user):
        return True
    return bool(k) and hmac.compare_digest(k, _order_token(order["id"]))


_checkout_limiter = security.RateLimiter(limit=10, window=3600.0)   # per IP


@app.post("/checkout")
async def checkout_submit(request: Request, plan: str = Form("pro"),
                          crypto: str = Form("ETH"), email: str = Form(""),
                          txid: str = Form("")):
    plan_id = plan if plan in plans.PLANS else "pro"
    coin = CRYPTO_BY_CODE.get(crypto.upper())
    user = request.state.user
    email = email.strip()
    error = None
    if not coin:
        error = "Choose one of the accepted coins."
    elif plan_id == "free":
        error = "The free plan does not need checkout."
    elif not user and not email:
        error = "Enter the email address your account uses, or sign in first."
    elif not user and not auth._EMAIL_RE.match(email):
        error = "That email address does not look right."
    elif not _checkout_limiter.hit(security.client_ip(request)):
        error = "Too many orders from your network. Try again later."

    rates = await _rates()
    usd = _plan_price(plan_id)
    if error:
        return templates.TemplateResponse(request, "checkout.html", _auth_ctx(
            request, crypto_options=CRYPTO_OPTIONS,
            plan=plans.get_plan(plan_id), plan_id=plan_id, usd=usd, rates=rates,
            amounts={c["code"]: _crypto_amount(usd, c["code"], rates)
                     for c in CRYPTO_OPTIONS},
            error=error, order=None))

    amount = _crypto_amount(usd, coin["code"], rates)
    order_id = db.create_order(
        user["id"] if user else None,
        (user["email"] if user else auth.normalise_email(email)),
        plan_id, coin["code"], coin["address"], amount, txid.strip()[:190])
    return RedirectResponse(_order_url(order_id), status_code=303)


@app.get("/checkout/{order_id}")
async def checkout_order(request: Request, order_id: int, k: str = ""):
    order = db.get_order(order_id)
    if not order or not _can_view_order(request, order, k):
        return PlainTextResponse("Order not found", status_code=404)
    coin = CRYPTO_BY_CODE.get(order["crypto"])
    plan = plans.get_plan(order["plan"])
    return templates.TemplateResponse(request, "order.html", _auth_ctx(
        request,
        order=order,
        order_key=_order_token(order_id),
        coin=coin,
        plan=plan,
        qr_svg=(qr.svg(coin["address"]) if coin else ""),
    ))


@app.post("/checkout/{order_id}/txid")
async def checkout_submit_txid(request: Request, order_id: int,
                               txid: str = Form(""), k: str = Form("")):
    order = db.get_order(order_id)
    if not order or not _can_view_order(request, order, k):
        return PlainTextResponse("Order not found", status_code=404)
    txid = txid.strip()
    if txid and re.fullmatch(r"[A-Za-z0-9:_\-]{8,190}", txid):
        # only while the order is open — an approved/rejected order stays put
        db.submit_order_txid(order_id, txid)
    return RedirectResponse(_order_url(order_id), status_code=303)


# --- legacy operator licence (site-wide Pro unlock) — admin only -----------

def _pro_page(request: Request, new_key=None, status_code: int = 200):
    return templates.TemplateResponse(request, "pro.html", {
        "new_key": new_key,
        "licenses": db.list_licenses() if _is_admin(request) else [],
        "user": request.state.user,
        "plan": request.state.plan,
        "plan_info": request.state.plan_info,
        "credits": request.state.credits,
        "pro": request.state.pro,
        "is_admin": _is_admin(request),
    }, status_code=status_code)


@app.post("/pro/purchase")
async def pro_purchase(request: Request, plan: str = Form("pro")):
    """Turns on Pro for every visitor. Only the admin may do this — it used to
    be open to anyone, which let any visitor unlock Pro site-wide for free."""
    if not _is_admin(request):
        return RedirectResponse("/pricing", status_code=303)
    new_key = None
    if not db.has_pro():
        new_key = db.activate_license("pro")
        request.state.pro = True
    return _pro_page(request, new_key)


@app.post("/pro/deactivate")
async def pro_deactivate(request: Request):
    if not _is_admin(request):
        return RedirectResponse("/pricing", status_code=303)
    db.deactivate_all()
    request.state.pro = auth.is_pro(request.state.user)
    return _pro_page(request)


@app.get("/pro/checkout")
async def pro_checkout_legacy(request: Request):
    return RedirectResponse("/checkout?plan=pro", status_code=303)


# --------------------------------------------------------------------------
# public API (v1) — X-API-Key
# --------------------------------------------------------------------------

_api_limiter = security.RateLimiter(limit=60, window=60.0)   # per key


def _api_user(request: Request) -> dict | None:
    key = request.headers.get("x-api-key", "").strip()
    if not key or len(key) > 128:
        return None
    return auth.user_for_api_key(key)


def _api_error(message: str, status: int) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


@app.get("/api/v1/me")
async def api_me(request: Request):
    user = _api_user(request)
    if not user:
        return _api_error("missing or invalid X-API-Key", 401)
    user = _refresh_credits(user)
    return {
        "email": user["email"],
        "plan": auth.effective_plan(user),
        "credits": auth.credits_of(user),
        "api": True,
        "endpoints": len(scanner.load_corpus().for_plan(auth.is_pro(user))),
    }


@app.get("/api/v1/corpus")
async def api_corpus(request: Request):
    user = _api_user(request)
    if not user:
        return _api_error("missing or invalid X-API-Key", 401)
    corpus = scanner.load_corpus()
    pro = auth.is_pro(user)
    endpoints = corpus.for_plan(pro)
    return {
        "total": len(endpoints),
        "categories": corpus.categories_for(endpoints),
        "adult_included": pro,
        "endpoints": [
            {"id": e.id, "name": e.name, "category": e.category, "url": e.url}
            for e in endpoints
        ],
    }


@app.get("/api/v1/plans")
async def api_plans(request: Request):
    return {
        "plans": [
            {"id": p["id"], "name": p["name"], "price": p["price"],
             "credits": p["credits"], "daily_credits": p["daily_credits"],
             "features": p["features"]}
            for p in plans.PLANS.values()
        ],
        "search_types": [
            {"id": t["id"], "label": t["label"], "pro": t["pro"], "cost": t["cost"]}
            for t in plans.SEARCH_TYPES
        ],
    }


@app.get("/api/v1/scan")
async def api_scan(request: Request, q: str = "", type: str = ""):
    """Run a search with an API key and get the results as JSON."""
    user = _api_user(request)
    if not user:
        return _api_error("missing or invalid X-API-Key", 401)
    if not q.strip():
        return _api_error("missing query parameter 'q'", 400)
    if not _api_limiter.hit(f"key:{user['api_key_id']}"):
        return _api_error("rate limit exceeded (60 requests per minute)", 429)
    kind = (type or "").strip().lower() or None
    if kind and kind not in plans.SEARCH_TYPE_IDS:
        return _api_error(f"unknown search type {kind!r}", 400)
    if kind and plans.is_pro_type(kind) and not auth.is_pro(user):
        return _api_error(
            f"{plans.TYPE_BY_ID[kind]['label']} search requires the Pro plan", 403)
    try:
        kind, _ = _resolve_kind(q.strip(), kind)
    except scanner.InputError as exc:
        return _api_error(str(exc), 400)
    if plans.is_pro_type(kind) and not auth.is_pro(user):
        return _api_error(
            f"{plans.TYPE_BY_ID[kind]['label']} search requires the Pro plan", 403)
    cost = plans.type_cost(kind)
    ref = q.strip()[:80]
    if auth.try_spend(user["id"], cost, f"api {kind} search", ref) is None:
        balance = auth.credits_of(db.get_user(user["id"]))
        return _api_error(
            f"insufficient credits: {cost} required, {balance} available", 402)
    try:
        result = await scanner.scan(q.strip(), kind=kind, pro=auth.is_pro(user))
    except Exception as exc:  # noqa: BLE001
        auth.refund(user["id"], cost, f"api {kind} search refund (failed)", ref)
        if isinstance(exc, scanner.InputError):
            return _api_error(str(exc), 400)
        log.warning("api scan failed: %r", exc)
        return _api_error(_safe_error(exc) + " No credits were charged.", 502)
    db.insert_scan(user["id"], result.kind, result.query, result.value,
                   result.found, result.checked, result.total, result.elapsed,
                   _scan_payload(result))
    return {
        "query": result.query,
        "kind": result.kind,
        "value": result.value,
        "found": result.found,
        "checked": result.checked,
        "total": result.total,
        "elapsed": round(result.elapsed, 2),
        "credits_remaining": auth.credits_of(db.get_user(user["id"])),
        "results": _scan_payload(result),
    }


# --------------------------------------------------------------------------
# bulk search (BETA)
# --------------------------------------------------------------------------

@app.get("/bulk")
async def bulk_page(request: Request):
    if not request.state.user:
        return _login_redirect(request, "/bulk")
    if not auth.plan_of(request.state.user).get("bulk"):
        return RedirectResponse("/pricing", status_code=303)
    return templates.TemplateResponse(request, "bulk.html", _auth_ctx(
        request, results=None, error=None, kind="username",
        search_types=plans.SEARCH_TYPES))


@app.post("/bulk")
async def bulk_run(request: Request, queries: str = Form(""),
                   kind: str = Form("username")):
    user = request.state.user
    if not user:
        return _login_redirect(request, "/bulk")
    if not auth.plan_of(user).get("bulk"):
        return RedirectResponse("/pricing", status_code=303)
    kind = kind if kind in plans.SEARCH_TYPE_IDS else "username"
    if plans.is_pro_type(kind) and not _is_pro(request):
        return templates.TemplateResponse(request, "bulk.html", _auth_ctx(
            request, results=None, kind=kind,
            search_types=plans.SEARCH_TYPES,
            error=f"{plans.TYPE_BY_ID[kind]['label']} search is a Pro feature."))

    items = [q.strip() for q in re.split(r"[\r\n,]+", queries) if q.strip()][:50]
    if not items:
        return templates.TemplateResponse(request, "bulk.html", _auth_ctx(
            request, results=None, kind=kind,
            search_types=plans.SEARCH_TYPES,
            error="Paste at least one query — one per line, or separated by commas."))

    unit = plans.type_cost(kind)
    cost = unit * len(items)
    if auth.try_spend(user["id"], cost, f"bulk {kind} search", f"{len(items)} items") is None:
        return templates.TemplateResponse(request, "bulk.html", _auth_ctx(
            request, results=None, kind=kind,
            search_types=plans.SEARCH_TYPES,
            error=f"{len(items)} searches cost {cost} credits and your balance is "
                  f"{auth.credits_of(db.get_user(user['id']))}."))

    rows: list[dict] = []
    failed = 0
    for item in items:
        try:
            result = await scanner.scan(item, kind=kind, pro=_is_pro(request))
            _save_scan(request, result)
            rows.append({
                "query": item,
                "kind": result.kind,
                "found": result.found,
                "checked": result.checked,
                "total": result.total,
                "elapsed": round(result.elapsed, 2),
                "hits": [h for h in result.hits if h.is_hit][:25],
                "error": "",
            })
        except Exception as exc:  # noqa: BLE001
            failed += 1
            msg = str(exc) if isinstance(exc, scanner.InputError) else _safe_error(exc)
            rows.append({"query": item, "kind": kind, "found": 0, "checked": 0,
                         "total": 0, "elapsed": 0.0, "hits": [],
                         "error": msg + " (not charged)"})

    if failed:
        auth.refund(user["id"], unit * failed, f"bulk {kind} refund ({failed} failed)", "")
    request.state.credits = auth.credits_of(db.get_user(user["id"]))
    return templates.TemplateResponse(request, "bulk.html", _auth_ctx(
        request, results=rows, error=None, kind=kind,
        search_types=plans.SEARCH_TYPES))


# --------------------------------------------------------------------------
# cloud cases
# --------------------------------------------------------------------------

@app.get("/cases")
async def cases_page(request: Request):
    user = request.state.user
    if not user:
        return _login_redirect(request, "/cases")
    return templates.TemplateResponse(request, "cases.html", _auth_ctx(
        request, cases=db.list_cases(user["id"]), error=None))


@app.post("/cases")
async def cases_create(request: Request, name: str = Form(""),
                        notes: str = Form("")):
    user = request.state.user
    if not user:
        return _login_redirect(request, "/cases")
    name = name.strip()
    if not name:
        return templates.TemplateResponse(request, "cases.html", _auth_ctx(
            request, cases=db.list_cases(user["id"]),
            error="Give the case a name."))
    limit = int(auth.plan_of(user).get("cases") or 0)
    if limit and db.count_cases(user["id"]) >= limit:
        return templates.TemplateResponse(request, "cases.html", _auth_ctx(
            request, cases=db.list_cases(user["id"]),
            error=f"Your plan holds up to {limit} cases. Delete one or upgrade on the "
                  f"pricing page."))
    case_id = db.create_case(user["id"], name, notes)
    return RedirectResponse(f"/cases/{case_id}", status_code=303)


@app.get("/cases/{case_id}")
async def case_page(request: Request, case_id: int):
    user = request.state.user
    if not user:
        return _login_redirect(request, f"/cases/{case_id}")
    case = db.get_case(case_id, user["id"])
    if not case:
        return PlainTextResponse("Case not found", status_code=404)
    return templates.TemplateResponse(request, "case.html", _auth_ctx(
        request, case=case, items=db.list_case_items(case_id),
        scans=db.list_scans(user["id"], 60), error=None))


@app.post("/cases/{case_id}/delete")
async def case_delete(request: Request, case_id: int):
    user = request.state.user
    if not user:
        return _login_redirect(request, "/cases")
    db.delete_case(case_id, user["id"])
    return RedirectResponse("/cases", status_code=303)


@app.post("/cases/{case_id}/items")
async def case_add_item(request: Request, case_id: int, scan_id: int = Form(0)):
    user = request.state.user
    if not user:
        return _login_redirect(request, f"/cases/{case_id}")
    case = db.get_case(case_id, user["id"])
    if not case:
        return PlainTextResponse("Case not found", status_code=404)
    scan = db.get_scan(scan_id, user["id"])
    if not scan:
        return templates.TemplateResponse(request, "case.html", _auth_ctx(
            request, case=case, items=db.list_case_items(case_id),
            scans=db.list_scans(user["id"], 60),
            error="That scan is not in your history."))
    db.add_case_item(case_id, scan["kind"], scan["query"], {
        "scan_id": scan["id"],
        "found": scan["found"],
        "checked": scan["checked"],
        "total": scan["total"],
        "elapsed": scan["elapsed"],
        "results": scan["results"],
    })
    return RedirectResponse(f"/cases/{case_id}", status_code=303)


@app.post("/cases/{case_id}/items/{item_id}/delete")
async def case_delete_item(request: Request, case_id: int, item_id: int):
    user = request.state.user
    if not user:
        return _login_redirect(request, f"/cases/{case_id}")
    db.delete_case_item(item_id, case_id, user["id"])
    return RedirectResponse(f"/cases/{case_id}", status_code=303)


# --------------------------------------------------------------------------
# report export
# --------------------------------------------------------------------------

def _report_scan(request: Request, scan_id: int) -> dict | None:
    user = request.state.user
    if not user:
        return None
    return db.get_scan(scan_id, user["id"])


@app.get("/reports/{scan_id}.pdf")
async def report_pdf(request: Request, scan_id: int):
    scan = _report_scan(request, scan_id)
    if not scan:
        return PlainTextResponse("Report not found", status_code=404)
    if not auth.plan_of(request.state.user).get("reports"):
        return RedirectResponse("/pricing", status_code=303)
    data = reports.pdf_report(scan)
    return Response(
        data,
        media_type="application/pdf",
        headers={"Content-Disposition":
                 f'attachment; filename="osint-scan-{scan_id}.pdf"'})


@app.get("/reports/{scan_id}.docx")
async def report_docx(request: Request, scan_id: int):
    scan = _report_scan(request, scan_id)
    if not scan:
        return PlainTextResponse("Report not found", status_code=404)
    if not auth.plan_of(request.state.user).get("reports"):
        return RedirectResponse("/pricing", status_code=303)
    data = reports.docx_report(scan)
    return Response(
        data,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition":
                 f'attachment; filename="osint-scan-{scan_id}.docx"'})



# --------------------------------------------------------------------------
# Notes & history
# --------------------------------------------------------------------------

def _notes_page(request: Request, **extra):
    user = request.state.user
    ctx = {"notes": db.list_notes(user["id"]) if user else [], "tools": TOOLS,
           "user": user}
    ctx.update(extra)
    return templates.TemplateResponse(request, "notes.html", ctx)


@app.get("/notes")
async def notes(request: Request):
    return _notes_page(request)


@app.post("/notes")
async def notes_add(request: Request, tool: str = Form(""), target: str = Form(""),
                    summary: str = Form("")):
    user = request.state.user
    if not user:
        return _login_redirect(request, "/notes")
    saved = False
    if tool.strip() and target.strip() and summary.strip():
        db.add_note(tool.strip(), target.strip(), summary.strip()[:2000], user_id=user["id"])
        saved = True
    return _notes_page(request, saved=saved)


@app.post("/notes/{note_id}/delete")
async def notes_delete(request: Request, note_id: int):
    user = request.state.user
    if not user:
        return _login_redirect(request, "/notes")
    db.delete_note(note_id, user_id=user["id"])
    return RedirectResponse("/notes", status_code=303)


@app.get("/notes/export.md")
async def notes_export(request: Request):
    user = request.state.user
    if not _is_pro(request) or not user:
        return RedirectResponse("/pricing", status_code=303)
    notes_list = db.list_notes(user["id"])
    lines = ["# OSINT Hub notes", "", f"_Exported {len(notes_list)} note(s)._", ""]
    for note in notes_list:
        lines += [
            f"## {note['target']}",
            f"- **Source:** {note['tool']}",
            f"- **Saved:** {note.get('created_str') or ''}",
            "",
            note["summary"],
            "",
        ]
    body = "\n".join(lines)
    return PlainTextResponse(
        body,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=osint-hub-notes.md"},
    )


@app.get("/history")
async def history(request: Request):
    """Your own lookups only — other visitors' searches are never shown."""
    user = request.state.user
    limit = 500 if _is_pro(request) else 25
    return templates.TemplateResponse(request, "history.html", {
        "queries": db.recent_queries(limit, user_id=user["id"]) if user else [],
        "pro": _is_pro(request),
        "user": user,
    })


# --------------------------------------------------------------------------
# Have I Been Pwned section
# --------------------------------------------------------------------------

def _hibp_key() -> str:
    return os.environ.get("HIBP_API_KEY", "").strip()


async def _hibp_ctx(request: Request, domain: str = "") -> dict:
    domain_result = None
    try:
        domain_result = await run_in_threadpool(services.hibp_catalog_query, domain[:200])
    except Exception as exc:  # noqa: BLE001
        domain_result = _done("Breach catalog unavailable", _safe_error(exc))
    return {
        "keyed": bool(_hibp_key()),
        "domain": domain or "",
        "password_result": None,
        "email_result": None,
        "catalog_count": len(services._BREACH_CACHE.get("data") or [])
                          if services._BREACH_CACHE.get("data") else None,
        "catalog_sections": domain_result["sections"] if domain_result else None,
    }


@app.get("/hibp")
async def hibp_page(request: Request, domain: str = ""):
    return templates.TemplateResponse(request, "hibp.html", await _hibp_ctx(request, domain))


@app.post("/hibp/password")
async def hibp_password(request: Request, password: str = Form("")):
    ctx = await _hibp_ctx(request)
    try:
        ctx["password_result"] = await run_in_threadpool(services.hibp_password_check,
                                                         password[:1024])
        # deliberately NOT logged to history — passwords never touch storage
    except services.LookupError as exc:
        ctx["password_result"] = _done("Input problem", str(exc))
    except Exception as exc:  # noqa: BLE001
        ctx["password_result"] = _done("Password check failed", _safe_error(exc))
    return templates.TemplateResponse(request, "hibp.html", ctx)


@app.post("/hibp/email")
async def hibp_email(request: Request, email: str = Form("")):
    ctx = await _hibp_ctx(request)
    key = _hibp_key()
    if not key:
        ctx["email_result"] = _done(
            "API key required",
            "Set HIBP_API_KEY in your environment and restart uvicorn to enable "
            "this check (see instructions on this page). The free checks "
            "(password + catalog) work without a key.")
    else:
        user = request.state.user
        try:
            ctx["email_result"] = await run_in_threadpool(
                services.hibp_email_lookup, email.strip()[:254], key)
            db.add_query("hibp", email.strip()[:254], user_id=user["id"] if user else None)
        except services.LookupError as exc:
            ctx["email_result"] = _done("Email lookup problem", str(exc))
        except Exception as exc:  # noqa: BLE001
            ctx["email_result"] = _done("Email lookup failed", _safe_error(exc))
    return templates.TemplateResponse(request, "hibp.html", ctx)


# --------------------------------------------------------------------------
# Monitoring & Alerts
# --------------------------------------------------------------------------

def _monitors_page(request: Request, user: dict, error: str | None = None,
                   status_code: int = 200):
    return templates.TemplateResponse(request, "monitors.html", _auth_ctx(
        request,
        monitors=db.list_monitors(user["id"]),
        search_types=plans.SEARCH_TYPES,
        error=error,
        runner_configured=bool(os.environ.get("MONITOR_RUNNER_SECRET")),
    ), status_code=status_code)


@app.get("/monitors")
async def monitors_page(request: Request):
    user = _require_user(request)
    if not user:
        return _login_redirect(request, "/monitors")
    return _monitors_page(request, user)


@app.post("/monitors")
async def monitors_create(request: Request,
                          kind: str = Form("username"),
                          target: str = Form(""),
                          frequency: str = Form("daily"),
                          channel: str = Form("email"),
                          channel_config: str = Form("{}")):
    user = _require_user(request)
    if not user:
        return _login_redirect(request, "/monitors")
    if not auth.is_pro(user):
        return _monitors_page(request, user, "Monitors are part of the Pro and Team plans. "
                              "Upgrade on the pricing page to create one.", 403)
    if db.count_monitors(user["id"]) >= monitor.MAX_MONITORS_PER_USER:
        return _monitors_page(request, user, f"You can keep up to "
                              f"{monitor.MAX_MONITORS_PER_USER} monitors. Delete one first.", 400)
    kind = kind if kind in plans.SEARCH_TYPE_IDS else "username"
    frequency = frequency if frequency in monitor.FREQUENCIES else "daily"
    try:
        _, _value = scanner.classify_input(target, kind)
    except scanner.InputError as exc:
        return _monitors_page(request, user, f"Target problem: {exc}", 400)
    try:
        config = json.loads(channel_config or "{}")
        if not isinstance(config, dict):
            raise ValueError
    except ValueError:
        return _monitors_page(request, user, "The channel config must be a JSON object, "
                              'e.g. {"webhook_url": "https://example.com/hook"}.', 400)
    problem = monitor.validate_destination(channel, config)
    if problem:
        return _monitors_page(request, user, problem, 400)
    monitor_id = db.create_monitor(
        user["id"], kind, target.strip()[:200], frequency, channel, config)
    return RedirectResponse(f"/monitors/{monitor_id}", status_code=303)


@app.get("/monitors/{monitor_id}")
async def monitor_detail(request: Request, monitor_id: int):
    user = _require_user(request)
    if not user:
        return _login_redirect(request, f"/monitors/{monitor_id}")
    monitor = db.get_monitor(monitor_id, user["id"])
    if not monitor:
        return PlainTextResponse("Monitor not found", status_code=404)
    runs = db.list_monitor_runs(monitor_id)
    return templates.TemplateResponse(request, "monitor_detail.html", _auth_ctx(
        request,
        monitor=monitor,
        runs=runs,
    ))


@app.post("/monitors/{monitor_id}/toggle")
async def monitor_toggle(request: Request, monitor_id: int):
    user = _require_user(request)
    if not user:
        return _login_redirect(request, f"/monitors/{monitor_id}")
    monitor = db.get_monitor(monitor_id, user["id"])
    if not monitor:
        return PlainTextResponse("Monitor not found", status_code=404)
    db.update_monitor(monitor_id, user["id"], enabled=not monitor["enabled"])
    return RedirectResponse(f"/monitors/{monitor_id}", status_code=303)


@app.post("/monitors/{monitor_id}/delete")
async def monitor_delete(request: Request, monitor_id: int):
    user = _require_user(request)
    if not user:
        return _login_redirect(request, "/monitors")
    db.delete_monitor(monitor_id, user["id"])
    return RedirectResponse("/monitors", status_code=303)


@app.get("/monitors/{monitor_id}/runs/{run_id}")
async def monitor_run_detail(request: Request, monitor_id: int, run_id: int):
    user = _require_user(request)
    if not user:
        return _login_redirect(request, f"/monitors/{monitor_id}/runs/{run_id}")
    monitor = db.get_monitor(monitor_id, user["id"])
    if not monitor:
        return PlainTextResponse("Monitor not found", status_code=404)
    run = db.get_monitor_run(run_id, monitor_id)
    if not run:
        return PlainTextResponse("Run not found", status_code=404)
    hits = db.list_monitor_hits(run_id)
    return templates.TemplateResponse(request, "monitor_run.html", _auth_ctx(
        request,
        monitor=monitor,
        run=run,
        hits=hits,
    ))


# White-Label API Reseller routes are registered further down, once the admin
# helpers they reuse exist (see reseller.set_templates).


# --------------------------------------------------------------------------
# Professional Reports
# --------------------------------------------------------------------------

DEFAULT_REPORT_TEMPLATE = {
    "branding": {
        "logo_path": "",
        "primary_color": "#3fb950",
        "secondary_color": "#0c0c0e",
        "font_family": "Inter, system-ui, sans-serif",
    },
    "cover_page": {
        "title": "OSINT Intelligence Report",
        "subtitle": "Automated Open Source Intelligence Analysis",
        "show_logo": True,
        "show_date": True,
        "show_classification": True,
        "classification": "CONFIDENTIAL",
    },
    "sections": {
        "executive_summary": True,
        "methodology": True,
        "findings": True,
        "appendix": False,
    },
    "footer": {
        "text": "Generated by OSINT Hub — {date}",
        "show_page_numbers": True,
    },
}


@app.get("/reports")
async def reports_page(request: Request):
    user = _require_user(request)
    if not user:
        return _login_redirect(request, "/reports")
    if not auth.plan_of(user).get("reports"):
        return RedirectResponse("/pricing", status_code=303)
    return templates.TemplateResponse(request, "reports.html", _auth_ctx(
        request,
        templates=db.list_report_templates(user["id"]),
        generations=db.list_report_generations(user["id"]),
        scans=db.list_scans(user["id"], 50),
        default_template=json.dumps(DEFAULT_REPORT_TEMPLATE, indent=2),
    ))


@app.post("/reports/templates")
async def reports_create_template(request: Request,
                                   name: str = Form(...),
                                   template_json: str = Form("{}")):
    user = _require_user(request)
    if not user:
        return _login_redirect(request, "/reports")
    if not auth.plan_of(user).get("reports"):
        return RedirectResponse("/pricing", status_code=303)
    try:
        tmpl = json.loads(template_json[:20000] or "{}")
    except json.JSONDecodeError:
        tmpl = {}
    if not isinstance(tmpl, dict):
        tmpl = {}
    if len(db.list_report_templates(user["id"])) < 50:
        db.create_report_template(user["id"], name.strip()[:100] or "Untitled",
                                  pro_reports._merge(pro_reports.DEFAULT_TEMPLATE, tmpl))
    return RedirectResponse("/reports", status_code=303)


@app.post("/reports/templates/{template_id}/delete")
async def reports_delete_template(request: Request, template_id: int):
    user = _require_user(request)
    if not user:
        return _login_redirect(request, "/reports")
    db.delete_report_template(template_id, user["id"])
    return RedirectResponse("/reports", status_code=303)


@app.post("/reports/generate")
async def reports_generate(request: Request,
                            scan_id: int = Form(...),
                            template_id: int = Form(0),
                            format: str = Form("pdf")):
    user = _require_user(request)
    if not user:
        return _login_redirect(request, "/reports")
    if not auth.plan_of(user).get("reports"):
        return RedirectResponse("/pricing", status_code=303)
    format = format if format in ("pdf", "docx") else "pdf"
    scan = db.get_scan(scan_id, user["id"])
    if not scan:
        return RedirectResponse("/reports", status_code=303)
    tmpl = pro_reports._load_template(user["id"], template_id if template_id else None)
    file_bytes, filename = await run_in_threadpool(
        pro_reports.generate_professional_report, scan, tmpl, format)
    db.create_report_generation(user["id"], scan_id,
                                template_id if template_id else None, format, filename)
    media_type = "application/pdf" if format == "pdf" else \
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    return Response(
        file_bytes,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


# --------------------------------------------------------------------------
# Monitoring Runner (for cron / scheduled task)
# --------------------------------------------------------------------------

_monitor_lock = asyncio.Lock()


@app.post("/internal/run-monitors")
async def internal_run_monitors(request: Request):
    """Internal endpoint for cron to run all monitors. Protect with a secret."""
    secret = request.headers.get("x-internal-secret", "")
    expected = os.environ.get("MONITOR_RUNNER_SECRET", "")
    if not expected or not hmac.compare_digest(secret.encode(), expected.encode()):
        raise HTTPException(401, "Invalid internal secret")
    if _monitor_lock.locked():
        return JSONResponse({"busy": True, "message": "a monitor run is already in progress"},
                            status_code=409)
    async with _monitor_lock:
        result = await monitor.run_all_monitors(
            force=request.query_params.get("force") == "1")
    return JSONResponse(result)


# --------------------------------------------------------------------------
# Admin panel — hidden URL, token-authenticated
# --------------------------------------------------------------------------

ADMIN_COOKIE = "osint_admin"
ADMIN_COOKIE_TTL = 60 * 60 * 12


def _admin_token() -> str:
    return security.admin_token()


def _admin_digest() -> str:
    return hmac.new(
        (_admin_token() + "|" + security.secret_key()).encode(), b"osint-admin",
        hashlib.sha256).hexdigest()


def _is_admin(request: Request) -> bool:
    if security.admin_disabled():
        return False
    cookie = request.cookies.get(ADMIN_COOKIE, "")
    return bool(cookie) and hmac.compare_digest(cookie, _admin_digest())


def _admin_ctx(request: Request, **extra) -> dict:
    is_mod = _is_admin(request)
    ctx = {
        "is_admin": is_mod,
        "db_path": str(db.DB_PATH) if is_mod else "",
        "hibp_keyed": bool(_hibp_key()),
        "pro_state": db.has_pro(),
        "notes": db.list_notes() if is_mod else [],
        "recent": db.recent_queries(5000) if is_mod else [],  # admin sees ALL lookups
        "stats": db.admin_stats() if is_mod else {},
        "is_default_token": security.admin_token_is_default(),
        "admin_disabled": security.admin_disabled(),
        "security_warnings": security.production_warnings() if is_mod else [],
        "backup_enabled": backup.enabled(),
        "admin_path": ADMIN_PATH,
        # account administration
        "users": db.list_users() if is_mod else [],
        "orders": db.list_orders(200) if is_mod else [],
        "plan_options": list(plans.PLANS.values()),
        "crypto_options": CRYPTO_OPTIONS,
    }
    ctx.update(extra)
    if not is_mod:
        ctx.update({"notes": [], "recent": [], "stats": {}, "users": [],
                    "orders": []})
    return ctx


def _admin_page(request: Request, status_code: int = 200, **extra):
    return templates.TemplateResponse(request, "admin.html",
                                      _admin_ctx(request, **extra), status_code=status_code)


def _admin_done() -> RedirectResponse:
    """Post/Redirect/Get: after an admin action, go back to the console."""
    return RedirectResponse(ADMIN_PATH, status_code=303)


@app.get(ADMIN_PATH)
async def admin_home(request: Request):
    return _admin_page(request, login_error=False)


@app.post(ADMIN_PATH + "/login")
async def admin_login(request: Request, token: str = Form("")):
    if security.admin_disabled():
        return _admin_page(request, status_code=403, login_error=True)
    ip = security.client_ip(request)
    if not _admin_limiter.hit(ip):
        return _admin_page(request, status_code=429, login_error=True, too_many=True)
    token = token.strip()
    if not hmac.compare_digest(token.encode(), _admin_token().encode()):
        await asyncio.sleep(0.6)  # slow guessing down without blocking other visitors
        return _admin_page(request, login_error=True)
    _admin_limiter.reset(ip)
    resp = RedirectResponse(ADMIN_PATH, status_code=303)
    security.set_cookie(resp, request, ADMIN_COOKIE, _admin_digest(), ADMIN_COOKIE_TTL)
    return resp


@app.post(ADMIN_PATH + "/logout")
async def admin_logout(request: Request):
    resp = RedirectResponse(ADMIN_PATH, status_code=303)
    security.delete_cookie(resp, request, ADMIN_COOKIE)
    return resp


def _admin_guard(request: Request):
    """Return a login page if the admin cookie is missing, else None."""
    if _is_admin(request):
        return None
    return _admin_page(request, login_error=True)


@app.post(ADMIN_PATH + "/clear-history")
async def admin_clear_history(request: Request):
    guard = _admin_guard(request)
    if guard:
        return guard
    db.clear_history()
    return _admin_done()


@app.post(ADMIN_PATH + "/clear-notes")
async def admin_clear_notes(request: Request):
    guard = _admin_guard(request)
    if guard:
        return guard
    db.clear_notes()
    return _admin_done()


@app.post(ADMIN_PATH + "/delete-query/{qid}")
async def admin_delete_query(request: Request, qid: int):
    guard = _admin_guard(request)
    if guard:
        return guard
    db.delete_query(qid)
    return _admin_done()


@app.post(ADMIN_PATH + "/delete-note/{note_id}")
async def admin_delete_note(request: Request, note_id: int):
    guard = _admin_guard(request)
    if guard:
        return guard
    db.delete_note(note_id)
    return _admin_done()


# --- shared account-administration actions (admin console + owner panel) ----

def _approve_order(order_id: int) -> bool:
    """Approve an order and grant its plan + credits exactly once."""
    order = db.get_order(order_id)
    if not order or not db.approve_order_once(order_id):
        return False
    plan_id = order["plan"] if order["plan"] in plans.PLANS else "pro"
    # Find the account this order belongs to — by id, then by email.
    user = db.get_user(order["user_id"]) if order.get("user_id") else None
    if not user and order.get("email"):
        user = db.get_user_by_email(auth.normalise_email(order["email"]))
    if user:
        db.set_user_plan(user["id"], plan_id)
        plan = plans.get_plan(plan_id)
        auth.grant_credits(user["id"], plan["credits"] or 0,
                           f"{plan['name']} plan activation", f"order:{order_id}")
    return True


def _set_plan(user_id: int, plan: str, who: str) -> bool:
    if plan not in plans.PLANS:
        plan = plans.DEFAULT_PLAN
    if not db.get_user(user_id):
        return False
    db.set_user_plan(user_id, plan)
    db.adjust_credits(user_id, 0, f"plan changed to {plan} by {who}", "")
    return True


def _adjust(user_id: int, amount: str, who: str) -> bool:
    if not db.get_user(user_id):
        return False
    try:
        delta = max(-1_000_000, min(1_000_000, int(amount)))
    except (TypeError, ValueError):
        delta = 0
    if delta:
        db.adjust_credits(user_id, delta, f"credit adjustment by {who}", "")
    return True


def _grant_plan_credits(user_id: int, who: str) -> bool:
    user = db.get_user(user_id)
    if not user:
        return False
    plan = plans.get_plan(auth.effective_plan(user))
    allowance = plan["credits"] or plan["daily_credits"]
    if allowance:
        db.adjust_credits(user_id, allowance, f"{plan['name']} credit top-up", f"{who} grant")
    return True


def _set_txid(order_id: int, txid: str) -> bool:
    order = db.get_order(order_id)
    if not order:
        return False
    db.set_order_status(order_id, order["status"], txid.strip()[:190])
    return True


# --- crypto orders: approve / reject ---------------------------------------

@app.post(ADMIN_PATH + "/orders/{order_id}/approve")
async def admin_approve_order(request: Request, order_id: int):
    guard = _admin_guard(request)
    if guard:
        return guard
    if not db.get_order(order_id):
        return PlainTextResponse("Order not found", status_code=404)
    _approve_order(order_id)
    return _admin_done()


@app.post(ADMIN_PATH + "/orders/{order_id}/reject")
async def admin_reject_order(request: Request, order_id: int):
    guard = _admin_guard(request)
    if guard:
        return guard
    if not db.get_order(order_id):
        return PlainTextResponse("Order not found", status_code=404)
    db.set_order_status(order_id, "rejected")
    return _admin_done()


@app.post(ADMIN_PATH + "/orders/{order_id}/txid")
async def admin_set_order_txid(request: Request, order_id: int,
                               txid: str = Form("")):
    guard = _admin_guard(request)
    if guard:
        return guard
    if not _set_txid(order_id, txid):
        return PlainTextResponse("Order not found", status_code=404)
    return _admin_done()


# --- user administration ----------------------------------------------------

@app.post(ADMIN_PATH + "/users/{user_id}/plan")
async def admin_set_user_plan(request: Request, user_id: int, plan: str = Form("free")):
    guard = _admin_guard(request)
    if guard:
        return guard
    if not _set_plan(user_id, plan, "admin"):
        return PlainTextResponse("User not found", status_code=404)
    return _admin_done()


@app.post(ADMIN_PATH + "/users/{user_id}/credits")
async def admin_set_user_credits(request: Request, user_id: int,
                                 amount: str = Form("0")):
    guard = _admin_guard(request)
    if guard:
        return guard
    if not _adjust(user_id, amount, "admin"):
        return PlainTextResponse("User not found", status_code=404)
    return _admin_done()


@app.post(ADMIN_PATH + "/users/{user_id}/grant-plan-credits")
async def admin_grant_plan_credits(request: Request, user_id: int):
    """Top a user up with the full allowance of their current plan."""
    guard = _admin_guard(request)
    if guard:
        return guard
    if not _grant_plan_credits(user_id, "admin"):
        return PlainTextResponse("User not found", status_code=404)
    return _admin_done()


@app.post(ADMIN_PATH + "/users/{user_id}/delete")
async def admin_delete_user(request: Request, user_id: int):
    guard = _admin_guard(request)
    if guard:
        return guard
    if not db.get_user(user_id):
        return PlainTextResponse("User not found", status_code=404)
    db.delete_user(user_id)
    return _admin_done()


# --- owner panel on /account (signed in as OWNER_EMAIL) ----------------------
# The account page's owner tools used to post to /admin/..., which 404s, so
# every button there was dead. They now have their own owner-only routes.

def _owner_guard(request: Request):
    user = request.state.user
    if not user:
        return _login_redirect(request, "/account")
    if not _is_owner(user):
        return PlainTextResponse("Not Found", status_code=404)
    return None


def _owner_done() -> RedirectResponse:
    return RedirectResponse("/account#owner", status_code=303)


@app.post("/account/owner/users/{user_id}/plan")
async def owner_set_user_plan(request: Request, user_id: int, plan: str = Form("free")):
    guard = _owner_guard(request)
    if guard:
        return guard
    _set_plan(user_id, plan, "owner")
    return _owner_done()


@app.post("/account/owner/users/{user_id}/credits")
async def owner_set_user_credits(request: Request, user_id: int, amount: str = Form("0")):
    guard = _owner_guard(request)
    if guard:
        return guard
    _adjust(user_id, amount, "owner")
    return _owner_done()


@app.post("/account/owner/users/{user_id}/grant-plan-credits")
async def owner_grant_plan_credits(request: Request, user_id: int):
    guard = _owner_guard(request)
    if guard:
        return guard
    _grant_plan_credits(user_id, "owner")
    return _owner_done()


@app.post("/account/owner/orders/{order_id}/approve")
async def owner_approve_order(request: Request, order_id: int):
    guard = _owner_guard(request)
    if guard:
        return guard
    _approve_order(order_id)
    return _owner_done()


@app.post("/account/owner/orders/{order_id}/reject")
async def owner_reject_order(request: Request, order_id: int):
    guard = _owner_guard(request)
    if guard:
        return guard
    if db.get_order(order_id):
        db.set_order_status(order_id, "rejected")
    return _owner_done()


@app.post("/account/owner/orders/{order_id}/txid")
async def owner_set_order_txid(request: Request, order_id: int, txid: str = Form("")):
    guard = _owner_guard(request)
    if guard:
        return guard
    _set_txid(order_id, txid)
    return _owner_done()


reseller.set_templates(templates, admin_ctx=_admin_ctx, is_admin=_is_admin)
app.include_router(reseller.reseller_router)


# legacy /admin used to exist — now it, and anything under it, 404s to keep
# the console's location from being advertised
@app.api_route("/admin/{rest:path}", methods=["GET", "POST"])
async def _admin_legacy_404(rest: str = ""):
    return PlainTextResponse("Not Found", status_code=404)


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots():
    # public site: crawl everything except nothing advertised — the admin
    # console's path is secret and never appears in any page or sitemap
    return "User-agent: *\nAllow: /\n"
