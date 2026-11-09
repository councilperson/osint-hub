"""amana — a public open-source-intelligence toolbox.

Ethics: built for lawful, authorized research (your own assets, consensual
targets, security research within scope). It deliberately excludes anything
that would dox a person: no people-search brokers, no address aggregation,
no login-walled scraping.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import db, services

BASE = Path(__file__).resolve().parent

app = FastAPI(title="amana", docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory=str(BASE / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
db.init()

templates.env.filters.setdefault("br", lambda s: s)


def _done(section_title: str, text: str) -> dict:
    return {"summary": services.summary_bad(section_title),
            "sections": [{"title": section_title, "kind": "text", "text": text}]}


# --------------------------------------------------------------------------
# hidden admin path: derived from the token so it's never linked in the UI
# --------------------------------------------------------------------------
_token_seed = os.environ.get("ADMIN_TOKEN", "admin12345")
ADMIN_PATH = (
    os.environ.get("ADMIN_PATH", "").rstrip("/")
    or "/hq-" + hashlib.sha256(_token_seed.encode()).hexdigest()[:10]
)


@app.middleware("http")
async def _pro_state(request: Request, call_next):
    request.state.pro = db.has_pro()
    return await call_next(request)


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
    cat = c if c in ("all", "identity", "network", "domains", "web") else "all"
    visible = TOOLS if cat == "all" else {k: v for k, v in TOOLS.items() if v["cat"] == cat}
    breach_count = len(services._BREACH_CACHE.get("data") or [])
    if not breach_count:
        try:
            breach_count = len(services.breach_catalog())
        except Exception:  # noqa: BLE001
            breach_count = 0
    return templates.TemplateResponse(request, "index.html", {
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
    if not db.has_pro():
        return RedirectResponse("/pro", status_code=303)
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
    })


@app.post("/tool/{tool_id}")
async def tool_run(request: Request, tool_id: str, target: str = Form("")):
    if tool_id not in TOOLS:
        return PlainTextResponse("Unknown tool", status_code=404)
    target = target.strip()
    pro = db.has_pro()
    results = None
    if not target:
        results = _done("Input problem", "The input was empty — enter something to look up.")
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
            parts = parts[:10]
            try:
                results = services.username_check_batch(parts)
                if overflow:
                    results["summary"]["text"] += f" · {overflow} extra handle(s) ignored (10 max)"
                db.add_query(tool_id, target)
            except services.LookupError as exc:
                results = _done("Input problem", str(exc))
            except Exception as exc:  # noqa: BLE001
                results = _done(f"Lookup failed for {target!r}",
                                f"{type(exc).__name__}: {exc} — network unreachable or target missing.")
        else:
            try:
                results = services.username_check(parts[0], max_platforms=None if pro else 10)
                db.add_query(tool_id, target)
            except services.LookupError as exc:
                results = _done("Input problem", str(exc))
            except Exception as exc:  # noqa: BLE001
                results = _done(f"Lookup failed for {target!r}",
                                f"{type(exc).__name__}: {exc} — network unreachable or target missing.")
    else:
        try:
            results = TOOLS[tool_id]["fn"](target)
            db.add_query(tool_id, target)
        except services.LookupError as exc:
            results = _done("Input problem", str(exc))
        except Exception as exc:  # noqa: BLE001
            results = _done(f"Lookup failed for {target!r}",
                            f"{type(exc).__name__}: {exc} — network unreachable or target missing.")
    return templates.TemplateResponse(request, "tool.html", {
        "tools": TOOLS,
        "tool_id": tool_id,
        "tool": TOOLS[tool_id],
        "q": target,
        "results": results,
    })


# --------------------------------------------------------------------------
# Pro tier
# --------------------------------------------------------------------------

@app.get("/pro")
async def pro_page(request: Request):
    return templates.TemplateResponse(request, "pro.html", {
        "new_key": None,
        "licenses": db.list_licenses(),
    })


# crypto-only checkout: price shown is the intro rate ($4.99) for the
# launch window, then the standard $9/mo
INTRO_PRICE = "$4.99"
STANDARD_PRICE = "$9"
CRYPTO_OPTIONS = [
    {"code": "BTC", "name": "Bitcoin", "icon": "&#132076;"},
    {"code": "XMR", "name": "Monero", "icon": "&#128477;"},
    {"code": "LTC", "name": "Litecoin", "icon": "&#133072;"},
]


@app.get("/pro/checkout")
async def pro_checkout(request: Request):
    if request.state.pro:
        return RedirectResponse("/pro", status_code=303)
    return templates.TemplateResponse(request, "checkout.html", {
        "crypto_options": CRYPTO_OPTIONS,
        "intro_price": INTRO_PRICE,
        "standard_price": STANDARD_PRICE,
    })


@app.post("/pro/purchase")
async def pro_purchase(request: Request, plan: str = Form("pro")):
    if plan != "pro":
        plan = "pro"
    new_key = None
    if not db.has_pro():
        new_key = db.activate_license(plan)
        request.state.pro = True  # mark this render as Pro immediately
    return templates.TemplateResponse(request, "pro.html", {
        "new_key": new_key,
        "licenses": db.list_licenses(),
    })


@app.post("/pro/deactivate")
async def pro_deactivate(request: Request):
    db.deactivate_all()
    request.state.pro = False
    return templates.TemplateResponse(request, "pro.html", {
        "new_key": None,
        "licenses": db.list_licenses(),
    })


# --------------------------------------------------------------------------
# Notes & history
# --------------------------------------------------------------------------

@app.get("/notes")
async def notes(request: Request):
    return templates.TemplateResponse(request, "notes.html", {
        "notes": db.list_notes(),
        "tools": TOOLS,
    })


@app.post("/notes")
async def notes_add(request: Request, tool: str = Form(""), target: str = Form(""),
                    summary: str = Form("")):
    if tool and target and summary:
        db.add_note(tool, target, summary.strip()[:2000])
    return templates.TemplateResponse(request, "notes.html", {
        "notes": db.list_notes(),
        "tools": TOOLS,
        "saved": True,
    })


@app.post("/notes/{note_id}/delete")
async def notes_delete(request: Request, note_id: int):
    db.delete_note(note_id)
    return templates.TemplateResponse(request, "notes.html", {
        "notes": db.list_notes(),
        "tools": TOOLS,
    })


@app.get("/notes/export.md")
async def notes_export(request: Request):
    if not db.has_pro():
        return RedirectResponse("/pro", status_code=303)
    lines = ["# amana notes", "", f"_Exported {len(db.list_notes())} note(s)._", ""]
    for note in db.list_notes():
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
        headers={"Content-Disposition": "attachment; filename=amana-notes.md"},
    )


@app.get("/history")
async def history(request: Request):
    limit = 500 if request.state.pro else 25
    return templates.TemplateResponse(request, "history.html", {
        "queries": db.recent_queries(limit),
        "pro": request.state.pro,
    })


# --------------------------------------------------------------------------
# Have I Been Pwned section
# --------------------------------------------------------------------------

def _hibp_key() -> str:
    return os.environ.get("HIBP_API_KEY", "").strip()


def _hibp_ctx(request: Request, domain: str = "") -> dict:
    domain_result = None
    try:
        domain_result = services.hibp_catalog_query(domain)
    except Exception as exc:  # noqa: BLE001
        domain_result = _done("Breach catalog unavailable",
                              f"{type(exc).__name__}: {exc}")
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
    return templates.TemplateResponse(request, "hibp.html", _hibp_ctx(request, domain))


@app.post("/hibp/password")
async def hibp_password(request: Request, password: str = Form("")):
    ctx = _hibp_ctx(request)
    try:
        ctx["password_result"] = services.hibp_password_check(password)
        # deliberately NOT logged to history — passwords never touch storage
    except services.LookupError as exc:
        ctx["password_result"] = _done("Input problem", str(exc))
    except Exception as exc:  # noqa: BLE001
        ctx["password_result"] = _done("Password check failed",
                                       f"{type(exc).__name__}: {exc}")
    return templates.TemplateResponse(request, "hibp.html", ctx)


@app.post("/hibp/email")
async def hibp_email(request: Request, email: str = Form("")):
    ctx = _hibp_ctx(request)
    key = _hibp_key()
    if not key:
        ctx["email_result"] = _done(
            "API key required",
            "Set HIBP_API_KEY in your environment and restart uvicorn to enable "
            "this check (see instructions on this page). The free checks "
            "(password + catalog) work without a key.")
    else:
        try:
            ctx["email_result"] = services.hibp_email_lookup(email, key)
            db.add_query("hibp", email)
        except services.LookupError as exc:
            ctx["email_result"] = _done("Email lookup problem", str(exc))
        except Exception as exc:  # noqa: BLE001
            ctx["email_result"] = _done("Email lookup failed",
                                        f"{type(exc).__name__}: {exc}")
    return templates.TemplateResponse(request, "hibp.html", ctx)


# --------------------------------------------------------------------------
# Admin panel — hidden URL, token-authenticated
# --------------------------------------------------------------------------

ADMIN_COOKIE = "osint_admin"


def _admin_token() -> str:
    return os.environ.get("ADMIN_TOKEN", "admin12345")


def _admin_digest() -> str:
    secret = os.environ.get("SECRET_KEY", "osint-hub-local-secret")
    return hmac.new(
        (_admin_token() + "|" + secret).encode(), b"osint-admin",
        hashlib.sha256).hexdigest()


def _is_admin(request: Request) -> bool:
    cookie = request.cookies.get(ADMIN_COOKIE, "")
    return hmac.compare_digest(cookie, _admin_digest())


def _admin_ctx(request: Request, **extra) -> dict:
    is_mod = _is_admin(request)
    ctx = {
        "is_admin": is_mod,
        "db_path": str(db.DB_PATH),
        "hibp_keyed": bool(_hibp_key()),
        "pro_state": db.has_pro(),
        "notes": db.list_notes() if is_mod else [],
        "recent": db.recent_queries(5000) if is_mod else [],  # admin sees ALL lookups
        "stats": db.admin_stats() if is_mod else {},
        "is_default_token": _admin_token() == "admin12345",
    }
    ctx.update(extra)
    if not is_mod:
        ctx.update({"notes": [], "recent": [], "stats": {}})
    return ctx


@app.get(ADMIN_PATH)
async def admin_home(request: Request, login_error: bool = False):
    return templates.TemplateResponse(request, "admin.html",
                                      _admin_ctx(request, login_error=False))


@app.post(ADMIN_PATH + "/login")
async def admin_login(request: Request, token: str = Form("")):
    token = token.strip()
    if not hmac.compare_digest(token, _admin_token()):
        import time as _time
        _time.sleep(0.6)  # blunt brute-force deterrent on the local UI
        return templates.TemplateResponse(request, "admin.html",
                                          _admin_ctx(request, login_error=True))
    resp = templates.TemplateResponse(request, "admin.html", _admin_ctx(request))
    resp.set_cookie(ADMIN_COOKIE, _admin_digest(), httponly=True,
                    samesite="lax", max_age=60 * 60 * 12)
    return resp


@app.post(ADMIN_PATH + "/logout")
async def admin_logout(request: Request):
    resp = templates.TemplateResponse(request, "admin.html",
                                      _admin_ctx(request, login_error=False))
    resp.delete_cookie(ADMIN_COOKIE)
    return resp


@app.post(ADMIN_PATH + "/clear-history")
async def admin_clear_history(request: Request):
    if not _is_admin(request):
        return templates.TemplateResponse(request, "admin.html",
                                          _admin_ctx(request, login_error=True))
    db.clear_history()
    return templates.TemplateResponse(request, "admin.html", _admin_ctx(request))


@app.post(ADMIN_PATH + "/clear-notes")
async def admin_clear_notes(request: Request):
    if not _is_admin(request):
        return templates.TemplateResponse(request, "admin.html",
                                          _admin_ctx(request, login_error=True))
    db.clear_notes()
    return templates.TemplateResponse(request, "admin.html", _admin_ctx(request))


@app.post(ADMIN_PATH + "/delete-query/{qid}")
async def admin_delete_query(request: Request, qid: int):
    if not _is_admin(request):
        return templates.TemplateResponse(request, "admin.html",
                                          _admin_ctx(request, login_error=True))
    db.delete_query(qid)
    return templates.TemplateResponse(request, "admin.html", _admin_ctx(request))


@app.post(ADMIN_PATH + "/delete-note/{note_id}")
async def admin_delete_note(request: Request, note_id: int):
    if not _is_admin(request):
        return templates.TemplateResponse(request, "admin.html",
                                          _admin_ctx(request, login_error=True))
    db.delete_note(note_id)
    return templates.TemplateResponse(request, "admin.html", _admin_ctx(request))


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
