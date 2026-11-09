"""Outbound lookup helpers for the OSINT Hub.

Design rules:
 - every request uses a short timeout and a shared, honest User-Agent;
 - sources used are public and free: Cloudflare DoH (DNS), rdap.org (WHOIS),
   ip-api.com (IP geo), official status endpoints (Bluesky/Reddit), and
   plain public profile URLs for username checks;
 - nothing here logs in to any platform, scrapes protected content, or
   targets private information about a specific person.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import ipaddress
import re
import time
import urllib.parse
from typing import Any, Callable

import httpx

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)
DOH = "https://cloudflare-dns.com/dns-query"
IPAPI = "http://ip-api.com/json/"
SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "is.gd", "goo.gl", "ow.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "t2m.io", "rb.gy", "lnkd.in",
}
MULTI_PART_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au",
    "co.jp", "or.jp", "ne.jp", "com.br", "com.mx", "co.nz", "co.in",
}
DISPOSABLE_DOMAINS = {
    "mailinator.com", "yopmail.com", "guerrillamail.com", "sharklasers.com",
    "10minutemail.com", "10minutemail.net", "temp-mail.org", "temp-mail.io",
    "trashmail.com", "trash-mail.com", "throwawaymail.com", "getnada.com",
    "maildrop.cc", "dispostable.com", "fakeinbox.com", "mailnesia.com",
    "mytemp.email", "tempmail.plus", "tempmailo.com", "mintemail.com",
    "burnermail.io", "spam4.me", "grr.la", "1secmail.com", "moakt.com",
    "emailondeck.com", "discard.email", "spambog.com", "dropmail.me",
}

_EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")


class LookupError(Exception):
    """Raised when a lookup cannot produce a meaningful result."""


def _get(
    url: str,
    *,
    params: dict | None = None,
    headers: dict | None = None,
    timeout: float = 12.0,
    follow: bool = False,
) -> httpx.Response:
    with httpx.Client(
        timeout=timeout,
        follow_redirects=follow,
        headers={"User-Agent": UA, **(headers or {})},
    ) as client:
        return client.get(url, params=params)


def _json_get(url: str, **kwargs: Any) -> Any:
    r = _get(url, headers={"Accept": "application/json"}, **kwargs)
    assert r.status_code < 500, f"upstream {r.status_code} from {url}"
    try:
        return r.json()
    except ValueError:
        raise LookupError(f"non-JSON response from {url}") from None


def summary_ok(text: str) -> dict:
    return {"text": text, "level": "ok"}


def summary_bad(text: str) -> dict:
    return {"text": text, "level": "bad"}


def summary_warn(text: str) -> dict:
    return {"text": text, "level": "warn"}


def clean_domain(target: str) -> str:
    """Pull a bare hostname out of messy user input (`https://a.com/x` -> a.com)."""
    t = target.strip()
    if not t:
        raise LookupError("Enter a domain or URL.")
    t = t.strip(".")
    if "://" not in t:
        t = "http://" + t
    host = urllib.parse.urlsplit(t).hostname
    if not host:
        raise LookupError("Could not parse a hostname from that input.")
    return host.lower()


def clean_handle(target: str) -> str:
    t = target.strip()
    if "://" in t or "/" in t:
        t = urllib.parse.urlsplit(
            t if "://" in t else "http://" + t
        ).path.strip("/@")
    return t.lstrip("@").strip()


# --------------------------------------------------------------------------
# DNS (via DoH JSON API)
# --------------------------------------------------------------------------

def _doh(name: str, qtype: str) -> list[dict]:
    data = _json_get(DOH, params={"name": name, "type": qtype},
                     headers={"Accept": "application/dns-json"})
    return [a for a in data.get("Answer", []) if a.get("type")]


def resolve4(name: str) -> str | None:
    try:
        answers = _doh(name, "A")
    except Exception:  # noqa: BLE001
        return None
    for a in answers:
        if a.get("type") == 1 and a.get("data"):
            return a["data"]
    return None


def dns_records(target: str) -> dict:
    domain = clean_domain(target)
    types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]
    rows: list[list[str]] = []
    for qtype in types:
        try:
            answers = _doh(domain, qtype)
        except LookupError as exc:
            rows.append([qtype, f"lookup failed: {exc}"])
            continue
        except Exception:  # noqa: BLE001
            rows.append([qtype, "lookup failed (network?)"])
            continue
        if not answers:
            rows.append([qtype, "\u2014"])
            continue
        if qtype == "TXT":
            # TXT answers arrive as space-joined strings
            datas = [a.get("data", "").replace('" ', "").replace('"', "")
                     for a in answers]
            rows.append([qtype, "\n".join(datas[:25])])
        elif len(answers) <= 8:
            rows.append([qtype, "  ·  ".join(str(a.get("data", "")) for a in answers)])
        else:
            rows.append([qtype, ", ".join(str(a.get("data", "")) for a in answers[:12]) + " …"])

    return {
        "summary": summary_ok(f"DNS records for {domain}"),
        "sections": [
            {"title": f"Records for {domain} (via Cloudflare DoH)",
             "kind": "kv",
             "rows": [[t, v] for t, v in rows]},
            {"title": "How to read this",
             "kind": "list",
             "items": [
                 "MX = mail servers; NS = zone delegation; TXT often contains SPF (mail policy) and verification tokens.",
                 "Missing MX with a valid domain usually means it does not receive mail.",
                 "The DoH JSON API is public; answers are equivalent to a UDP-53 lookup.",
             ]},
        ],
    }


# --------------------------------------------------------------------------
# WHOIS via RDAP
# --------------------------------------------------------------------------

def rdap_whois(target: str) -> dict:
    domain = clean_domain(target)
    data = _json_get(f"https://rdap.org/domain/{domain}", follow=True)
    if not data or data.get("errorCode"):
        raise LookupError(f"RDAP returned no data for {domain} (errorCode={data.get('errorCode')}).")

    events: dict[str, str] = {}
    for ev in data.get("events", []) or []:
        action = ev.get("eventAction", "")
        date = str(ev.get("eventDate", ""))[:10]
        if action and date:
            events[action] = date

    registrar, registrar_link = "", ""
    for ent in data.get("entities", []) or []:
        roles = ent.get("roles", []) or []
        if "registrar" not in roles:
            continue
        for v in (ent.get("vcardArray") or [None, []])[1]:
            if v and v[0] == "fn":
                registrar = str(v[3])
        if ent.get("links"):
            registrar_link = ent["links"][0].get("href", "")
        break

    nameservers = ", ".join(
        str(ns.get("ldhName", "")).lower()
        for ns in (data.get("nameservers") or [])
    ) or "\u2014"

    secure_dns = data.get("secureDNS") or {}
    dnssec = "signed zone (DNSSEC)" if secure_dns.get("delegationSigned") else "not signed"

    kv = [
        ["Domain", domain],
        ["Registrar", registrar or "\u2014"],
        ["Registered", events.get("registration", "\u2014")],
        ["Last changed", events.get("last changed", "\u2014")],
        ["Expiry", events.get("expiration", "\u2014")],
        ["Status", ", ".join(data.get("status", []) or []) or "\u2014"],
        ["Nameservers", nameservers],
        ["DNSSEC", dnssec],
    ]
    sections = [
        {"title": f"RDAP registration data · {domain}", "kind": "kv", "rows": kv},
    ]
    if registrar_link:
        sections.append({"title": "Registrar record", "kind": "kv",
                         "rows": [["URL", registrar_link]]})
    sections.append({
        "title": "Notes",
        "kind": "list",
        "items": [
            "RDAP is the modern replacement for whois; coverage depends on each registry's RDAP service.",
            "Creation dates are useful for spotting throw-away domains in phishing/scam analysis.",
            "No API key needed — rdap.org routes to the authoritative registry.",
        ],
    })
    return {"summary": summary_ok(f"Registration data for {domain}"),
            "sections": sections}


# --------------------------------------------------------------------------
# IP / network
# --------------------------------------------------------------------------

def ip_info(target: str) -> dict:
    t = target.strip().replace("http://", "").replace("https://", "").strip("/")
    t = t.split("/")[0].split(":")[0]
    if not t:
        raise LookupError("Enter an address.")

    sections: list[dict] = []
    try:
        ip = ipaddress.ip_address(t)
    except ValueError:
        ip = None

    if ip is None:
        domain = clean_domain(t)
        resolved = resolve4(domain)
        if not resolved:
            raise LookupError(f"Could not resolve {domain} to an IPv4 address.")
        sections.append({"title": "Resolution", "kind": "kv",
                         "rows": [["Host", domain], ["A", resolved]]})
        target_ip = resolved
    else:
        target_ip = str(ip)

    data = _json_get(IPAPI + urllib.parse.quote(target_ip),
                     params={"fields": ("status,message,country,countryCode,"
                                        "regionName,city,zip,lat,lon,timezone,"
                                        "isp,org,as,asname,reverse,mobile,proxy,hosting,query")})
    if data.get("status") != "success":
        raise LookupError(f"ip-api.com could not look that up: {data.get('message', 'unknown error')}")

    flags = []
    if data.get("proxy"):
        flags.append("flagged as proxy / anonymizer")
    if data.get("mobile"):
        flags.append("mobile network")
    if data.get("hosting"):
        flags.append("hosting / datacenter range")

    geo_rows = [
        ["IP", data.get("query", target_ip)],
        ["Country", f"{data.get('country', '')} ({data.get('countryCode', '')})"],
        ["Region", data.get("regionName", "\u2014")],
        ["City", data.get("city", "\u2014")],
        ["Postcode", data.get("zip", "\u2014")],
        ["Coordinates", f"{data.get('lat', '')}, {data.get('lon', '')}"],
        ["Timezone", data.get("timezone", "\u2014")],
        ["ISP / org", " / ".join(str(x) for x in (data.get("isp", ""), data.get("org", "")) if x) or "\u2014"],
        ["ASN", data.get("asname") and f"{data.get('as')} ({data.get('asname')})" or data.get("as", "\u2014")],
        ["Network flags", ", ".join(flags) or "\u2014"],
    ]
    sections.insert(0, {"title": f"IP intelligence · {target_ip}", "kind": "kv", "rows": geo_rows})

    if ":" not in target_ip:
        rev = ".".join(reversed(target_ip.split("."))) + ".in-addr.arpa"
        try:
            ptr = ", ".join(str(a.get("data", "")) for a in _doh(rev, "PTR"))
        except Exception:  # noqa: BLE001
            ptr = ""
        if ptr:
            sections.append({"title": "Reverse DNS", "kind": "kv", "rows": [["PTR", ptr]]})

    sections.append({
        "title": "Notes",
        "kind": "list",
        "items": [
            "Geolocation is approximate — sourced from ip-api.com's free database (most useful at city/country level).",
            "'Proxy / hosting' flags are heuristic; a flagged hosting IP is normal for cloud providers.",
            "For threats and reputation, paste the IP into VirusTotal or AbuseIPDB (see Resources).",
        ],
    })
    return {"summary": summary_ok(f"IP data for {data.get('query', target_ip)}"),
            "sections": sections}


# --------------------------------------------------------------------------
# HTTP headers + redirect chain
# --------------------------------------------------------------------------

def _assert_public_host(url: str) -> None:
    """Refuse to fetch loopback/private/link-local hosts (SSRF guard for a public deployment)."""
    import socket
    host = urllib.parse.urlsplit(url).hostname or ""
    if not host:
        raise LookupError("Could not parse that URL.")
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        raise LookupError("Could not resolve that host.") from None
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not ip.is_global:
            raise LookupError("That address is private or internal, so it can't be fetched.")


def _redirect_chain(url: str, max_hops: int = 7) -> tuple[list[dict], dict]:
    hops: list[dict] = []
    final_headers: dict = {}
    with httpx.Client(timeout=12, follow_redirects=False, headers={"User-Agent": UA}) as client:
        current = url
        for _ in range(max_hops):
            _assert_public_host(current)
            req = client.build_request("GET", current)
            resp = client.send(req, stream=True)
            try:
                hops.append({
                    "url": current,
                    "status": resp.status_code,
                    "location": resp.headers.get("location", ""),
                })
                final_headers = resp.headers
            finally:
                resp.close()
            if resp.is_redirect and resp.headers.get("location"):
                nxt = urllib.parse.urljoin(current, resp.headers["location"])
                if nxt == current:
                    break
                current = nxt
                continue
            break
    if not hops:
        raise LookupError("No response from that URL.")
    return hops, final_headers


_SECURITY_HEADERS = [
    ("content-security-policy", "limits what scripts/resources the page may load"),
    ("strict-transport-security", "forces HTTPS for future visits"),
    ("x-content-type-options", "stops MIME-sniffing"),
    ("referrer-policy", "limits what referrers leak"),
    ("x-frame-options", "anti-clickjacking"),
]


def http_headers(target: str) -> dict:
    t = target.strip()
    if not t:
        raise LookupError("Enter a URL.")
    if "://" not in t:
        t = "https://" + t
    parsed = urllib.parse.urlsplit(t)
    if not parsed.netloc:
        raise LookupError("Could not parse that URL.")

    hops, headers = _redirect_chain(t)
    interesting = [
        "server", "content-type", "content-length", "last-modified",
        "cache-control", "content-security-policy", "strict-transport-security",
        "x-content-type-options", "referrer-policy", "permissions-policy",
        "x-frame-options", "x-powered-by", "cf-ray", "set-cookie",
    ]
    kv = [["Final status", str(hops[-1]["status"])]]
    kv += [[k, headers.get(k, "\u2014")[:300]] for k in interesting]
    missing = [f"{h} — {why}" for h, why in _SECURITY_HEADERS if h not in headers]

    sections = [
        {"title": "Redirect chain (first hops)", "kind": "table",
         "head": ["#", "URL", "Status", "Redirects to"],
         "rows": [[str(i), h["url"], str(h["status"]), h["location"] or "—"]
                  for i, h in enumerate(hops, 1)]},
        {"title": "Final response headers", "kind": "kv", "rows": kv},
        {"title": "Security headers: missing", "kind": "list", "items": missing},
        {"title": "Notes", "kind": "list", "items": [
            "Missing security headers are not a vulnerability by themselves — they signal CI hardening.",
            "Server / X-Powered-By reveal tech stack; useful for fingerprinting a target's infra.",
            "Request sizes are tiny; the body stream is closed immediately (no content is downloaded).",
        ]},
    ]
    return {"summary": summary_ok(f"{hops[-1]['status']} · {hops[-1]['url']}"),
            "sections": sections}


# --------------------------------------------------------------------------
# Username presence
# --------------------------------------------------------------------------

_GONE_CODES = {404, 410}


def _interpret_status(code: int) -> str:
    if code == 200:
        return "found?"
    if code in _GONE_CODES:
        return "gone"
    if code in (301, 302, 303, 307, 308):
        return "maybe"
    if code in (403, 429, 401):
        return "blocked"
    return "maybe"


PLATFORMS: list[dict] = [
    {"name": "GitHub", "url": "https://github.com/{h}",
     "note": "status-code check is reliable"},
    {"name": "GitLab", "url": "https://gitlab.com/{h}"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{h}/about.json",
     "predict": lambda code, body: (
         "found?" if code == 200 and '"id"' in body
         else "gone" if code == 200 or code == 404
         else _interpret_status(code)),
     "note": "about.json; datacenter IPs may be blocked"},
    {"name": "Telegram", "url": "https://t.me/{h}",
     "predict": lambda code, body: (
         "found?" if "tgme_page_title" in body or "tgme_page_extra" in body
         else "gone" if "If you have Telegram" in body
         else "maybe"),
     "note": "body-based check"},
    {"name": "Bluesky", "url": "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle={h}.bsky.social",
     "predict": lambda code, body: ("found?" if code == 200 and '"did"' in body
                                    else "gone" if code in (200, 400) else "maybe"),
     "note": "checks your-handle.bsky.social via official API"},
    {"name": "Mastodon", "url": "https://mastodon.social/@{h}"},
    {"name": "YouTube", "url": "https://www.youtube.com/@{h}",
     "note": "@handle form"},
    {"name": "Twitch", "url": "https://m.twitch.tv/{h}",
     "note": "mobile host avoids redirect surprises"},
    {"name": "Steam", "url": "https://steamcommunity.com/id/{h}",
     "predict": lambda code, body: ("gone" if "could not be found" in body else "found?"),
     "note": "custom-URL profiles"},
    {"name": "Medium", "url": "https://medium.com/@{h}"},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{h}"},
    {"name": "Vimeo", "url": "https://vimeo.com/{h}"},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{h}"},
    {"name": "Keybase", "url": "https://keybase.io/{h}"},
    {"name": "Bitbucket", "url": "https://bitbucket.org/{h}/"},
    {"name": "Tumblr", "url": "https://{h}.tumblr.com",
     "note": "subdomain form"},
    {"name": "X (Twitter)", "url": "https://x.com/{h}",
     "note": "often bot-blocked from datacenter IPs"},
    {"name": "Instagram", "url": "https://www.instagram.com/{h}/",
     "note": "login-walled; result often inconclusive"},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{h}",
     "note": "bot-blocking may skew results"},
]


def _probe(handle: str, p: dict) -> dict:
    url = p["url"].format(h=handle)
    try:
        r = _get(url, timeout=8)
        predict = p.get("predict")
        status = predict(r.status_code, r.text) if predict else _interpret_status(r.status_code)
        return {"handle": handle, "platform": p["name"], "url": url,
                "status": status, "note": p.get("note", "")}
    except httpx.HTTPError as exc:
        return {"handle": handle, "platform": p["name"], "url": url,
                "status": "unreachable", "note": f"{type(exc).__name__}"}


_RESULT_NOTES = [
    "'found?' means a fetchable public page — verify it by opening the URL.",
    "'gone' means the platform clearly says the profile does not exist.",
    "'maybe / blocked / unreachable' means the platform hides results (login walls, bot defenses, timeouts) — treat as inconclusive, not negative.",
    "This checks public existence only. It never logs in and never reads protected content.",
]


def username_check_batch(handles: list[str], max_platforms: int | None = None) -> dict:
    handles = [h for h in handles if h][:10]
    if not handles:
        raise LookupError("Enter at least one username.")
    if max_platforms and max_platforms < len(PLATFORMS):
        platforms = PLATFORMS[:max_platforms]
        extra_note = (
            f"Free plan covers {max_platforms} of {len(PLATFORMS)} platforms "
            "per check — the Pro tier unlocks all platforms, more platforms per check, and batch handles."
        )
    else:
        platforms = PLATFORMS
        extra_note = None

    tasks = [(h, p) for h in handles for p in platforms]
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        rows = list(pool.map(lambda t: _probe(t[0], t[1]), tasks))

    rows_data = [[r["handle"], r["platform"], r["url"], r["status"], r["note"]] for r in rows]
    found = sum(1 for r in rows if r["status"] == "found?")
    gone = sum(1 for r in rows if r["status"] == "gone")

    notes = list(_RESULT_NOTES)
    if extra_note:
        notes.insert(0, extra_note)
    sections = [
        {"title": f"Presence for {len(handles)} handle(s) · {len(rows)} checks",
         "kind": "table",
         "head": ["Handle", "Platform", "URL", "Status", "Note"],
         "rows": rows_data},
        {"title": "Notes", "kind": "list", "items": notes},
    ]
    return {"summary": summary_ok(f"{found} likely match(es), {gone} confirmed-missing · {len(handles)} handle(s)"),
            "sections": sections}


def username_check(target: str, max_platforms: int | None = None) -> dict:
    handle = clean_handle(target)
    if not handle or any(c in handle for c in "?&# ") or handle.startswith('/'):
        raise LookupError("Enter a plain username (letters, digits, dots, hyphens, underscores).")
    if len(handle) > 64:
        raise LookupError("That's too long to be a username.")
    return username_check_batch([handle], max_platforms=max_platforms)


# --------------------------------------------------------------------------
# Email checks
# --------------------------------------------------------------------------

def gravatar_url(email: str) -> str:
    digest = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    return f"https://www.gravatar.com/avatar/{digest}"


def email_check(target: str) -> dict:
    email = target.strip()
    if not _EMAIL_RE.match(email):
        raise LookupError("That doesn't look like a valid email address.")
    domain = email.rsplit("@", 1)[1].lower()

    try:
        mx = ", ".join(str(a.get("data", "")) for a in _doh(domain, "MX"))
    except Exception:  # noqa: BLE001
        mx = ""

    disposable = domain in DISPOSABLE_DOMAINS or domain.endswith(".10minutemail.net")
    gravatar_status = ""
    gravatar = gravatar_url(email)
    try:
        r = _get(gravatar + "?d=404", timeout=8)
        gravatar_status = {200: "exists — this email has an avatar registered on Gravatar",
                           404: "no Gravatar account for this email"}.get(r.status_code, f"HTTP {r.status_code}")
    except httpx.HTTPError as exc:
        gravatar_status = f"unreachable ({type(exc).__name__})"

    verdict = "mail domain looks deliverable" if mx else "no MX record — likely cannot receive mail"
    sections = [
        {"title": f"Email checks · {email}", "kind": "kv", "rows": [
            ["Syntax", "valid"],
            ["Mail domain", domain],
            ["MX record", mx or "\u2014 none \u2014"],
            ["Verdict", verdict],
            ["Disposable domain", "yes — throwaway mail provider" if disposable else "not on the known disposable list"],
            ["Gravatar", gravatar_status],
            ["Gravatar URL", gravatar],
        ]},
        {"title": "Honest limits", "kind": "list", "items": [
            "MX presence says the domain can receive mail — it cannot confirm this exact mailbox exists.",
            "SMTP RCPT-probing (pinging the mailbox) is deliberately not performed.",
            f"For breach data use the official check at haveibeenpwned.com (automation needs their API key) — {email} can be pasted there manually.",
            "A disposable hit means the address is throwaway, not fraudulent.",
        ]},
    ]
    return {"summary": summary_warn(verdict), "sections": sections}


# --------------------------------------------------------------------------
# URL analysis
# --------------------------------------------------------------------------

def registered_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) >= 3 and "." .join(labels[-2:]) in MULTI_PART_TLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def url_analyze(target: str) -> dict:
    t = target.strip()
    if not t:
        raise LookupError("Enter a URL.")
    if "://" not in t:
        t = "https://" + t
    p = urllib.parse.urlsplit(t)
    host = (p.hostname or "").lower()
    if not host:
        raise LookupError("Could not parse that URL.")

    flags: list[str] = []
    try:
        ipaddress.ip_address(host)
        flags.append("Host is a raw IP address instead of a domain")
    except ValueError:
        pass
    if host.startswith("xn--") or ".xn--" in host:
        flags.append("Internationalized/punycode domain (xn--…) — can spoof lookalike domains")
    if host in SHORTENERS:
        flags.append("Known URL shortener — resolve the redirect before trusting it")
    if "@" in p.netloc:
        flags.append("UserInfo (@) in the URL — the visible host is not the real destination")
    if len(t) > 120:
        flags.append("Unusually long URL")
    label_counts = host.count(".") 
    if label_counts > 3:
        flags.append(f"Many subdomain levels ({label_counts} dots) — often padding to mimic trusted names")
    if p.scheme == "http":
        flags.append("Plain HTTP — credentials/GET parameters are unencrypted")

    data = {
        "summary": summary_ok(("flags present · " + host) if flags else f"no structural flags · {host}"),
        "sections": [
            {"title": "Anatomy", "kind": "kv", "rows": [
                ["Scheme", p.scheme],
                ["Host", host],
                ["Registered domain (approx.)", registered_domain(host)],
                ["Port", str(p.port or ("443" if p.scheme == "https" else "80"))],
                ["Path", p.path or "/"],
                ["Query", p.query or "\u2014"],
                ["Fragment", p.fragment or "\u2014"],
            ]},
            {"title": "Structural flags", "kind": "list",
             "items": flags if flags else ["None — the URL looks structurally ordinary."]},
        ],
    }

    # try to follow redirects for non-shortener checks too (cheap, small timeout)
    if hops := _safe_chain(t):
        data["sections"].insert(1, {
            "title": "Redirect chain", "kind": "table",
            "head": ["#", "URL", "Status", "Redirects to"],
            "rows": [[str(i), h["url"], str(h["status"]), h["location"] or "—"]
                     for i, h in enumerate(hops, 1)],
        })
        data["summary"] = summary_ok(f"mechanical check · {len(hops)} hop(s)")
    return data


def _safe_chain(url: str) -> list[dict] | None:
    try:
        hops, _ = _redirect_chain(url, max_hops=5)
    except (httpx.HTTPError, LookupError):
        return None
    return hops


# --------------------------------------------------------------------------
# Have I Been Pwned (public endpoints + optional keyed account lookup)
# --------------------------------------------------------------------------

HIBP_CATALOG_URL = "https://haveibeenpwned.com/api/v3/breaches"
HIBP_ACCOUNT_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/"
HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"
_BREACH_CACHE: dict = {"data": None, "ts": 0.0}
_BREACH_TTL = 600.0


def breach_catalog() -> list[dict]:
    """All indexed breaches from the public HIBP endpoint (no key), cached 10 min."""
    now = time.time()
    if _BREACH_CACHE["data"] and now - _BREACH_CACHE["ts"] < _BREACH_TTL:
        return _BREACH_CACHE["data"]
    r = _get(HIBP_CATALOG_URL, headers={"Accept": "application/json"}, timeout=25)
    if r.status_code == 403:
        raise LookupError("HIBP catalog returned 403 — the User-Agent may be blocked. Retry shortly.")
    if r.status_code != 200:
        raise LookupError(f"HIBP catalog unavailable (HTTP {r.status_code}).")
    data = r.json()
    _BREACH_CACHE.update(data=data, ts=now)
    return data


def hibp_password_check(password: str) -> dict:
    """k-anonymity lookup: only the 5-char SHA-1 prefix leaves the machine."""
    pw = password.strip()
    if not pw:
        raise LookupError("Type a password first.")
    if len(pw) > 256:
        raise LookupError("That's too long to be a real password.")
    sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    r = _get(HIBP_RANGE_URL + prefix, timeout=15)
    if r.status_code != 200:
        raise LookupError(f"Pwned Passwords API unavailable (HTTP {r.status_code}).")
    count = 0
    for line in r.text.splitlines():
        line = line.strip()
        if ":" in line and line.split(":", 1)[0] == suffix:
            count = int(line.split(":", 1)[1])
            break

    verdict = (f"pwned — seen {count:,} times in public breach dumps"
               if count else "not found in any known public breach corpus")
    sections = [
        {"title": "Result", "kind": "kv", "rows": [
            ["SHA-1 prefix sent", f"{prefix}***** (k-anonymity window)"],
            ["Occurrences in breaches", f"{count:,}"],
            ["Verdict", "WEAK — do not use this password anywhere" if count >= 1_000
                        else ("Previously leaked — avoid it" if count else "Looks safe — consider a 16+ char passphrase anyway")],
        ]},
        {"title": "How this is safe", "kind": "list", "items": [
            "The password itself never leaves this app — only 5 hash characters, matched against a server-side list of hash suffixes.",
            "A pwned hit means the password (or the hash you share) has appeared in a leaked corpus; others may have reused your phrasing.",
            "Recommendation: unique 16+ character passphrases per site + a password manager.",
            "Data from pwnedpasswords.com, by the HIBP project. Not stored anywhere locally.",
        ]},
    ]
    return {"summary": summary_bad(verdict) if count else summary_ok(verdict),
            "sections": sections}


def hibp_catalog_query(domain: str = "", limit: int = 25) -> dict:
    data = breach_catalog()
    flt = domain.strip().lower()
    if flt:
        rows_data = [
            b for b in data
            if flt in (b.get("Domain", "") or "").lower()
            or flt in (b.get("Title", "") or "").lower()
            or flt in (b.get("Name", "") or "").lower()
        ]
    else:
        rows_data = data

    rows_data.sort(key=lambda b: b.get("PwnCount", 0) or 0, reverse=True)
    rows = []
    for b in rows_data[:limit]:
        classes = b.get("DataClasses", []) or []
        shown = "; ".join(classes[:3]) + (f" +{len(classes) - 3} more" if len(classes) > 3 else "")
        rows.append([
            b.get("Title", "?"),
            b.get("Domain", "—"),
            str(b.get("BreachDate", "—")),
            f"{b.get('PwnCount', 0):,}",
            shown or "—",
        ])

    sections: list[dict] = [
        {"title": f"{len(rows_data)} match(es)" + (f" · showing {len(rows)}" if len(rows_data) > limit else ""),
         "kind": "table",
         "head": ["Breach", "Domain", "Date", "Accounts", "Data classes"],
         "rows": rows},
    ]
    exact = next((b for b in rows_data
                  if (b.get("Domain", "") or "").lower() == flt), None)
    if exact:
        sections.append({"title": f"Spotlight · {exact.get('Title', '')}", "kind": "kv", "rows": [
            ["Domain", exact.get("Domain", "—")],
            ["Breach date", exact.get("BreachDate", "—")],
            ["Added to HIBP", str(exact.get("AddedDate", "—"))[:10]],
            ["Accounts pwned", f"{exact.get('PwnCount', 0):,}"],
            ["Verified", "yes" if exact.get("IsVerified") else "unverified"],
            ["References", ", ".join(b.get("MediaReferences", [])[:2]) or "—"],
        ]})
        sections.append({"title": "What was exposed", "kind": "chips",
                         "items": [str(c) for c in (exact.get("DataClasses") or [])]})
        desc = exact.get("Description", "").replace("<br>", " ").replace("\r", " ").replace("\n", " ").strip()
        sections.append({"title": "About this breach", "kind": "text", "text": desc})
    sections.append({"title": "Notes", "kind": "list", "items": [
        "PwnCount is the number of accounts in that breach, not that they belong to you.",
        "For your own email, use the email lookup (API key) or haveibeenpwned.com.",
    ]})
    return {"summary": summary_warn(f"{len(rows_data)} breach(es) for \u201c{flt}\u201d" if flt else f"catalog highlights"),
            "sections": sections}


def hibp_email_lookup(email: str, api_key: str) -> dict:
    email = email.strip()
    if not _EMAIL_RE.match(email):
        raise LookupError("That doesn't look like a valid email address.")
    url = HIBP_ACCOUNT_URL + urllib.parse.quote(email) + "?truncateResponse=false"
    r = _get(url, headers={"hibp-api-key": api_key.strip(),
                           "Accept": "application/json"}, timeout=20)
    if r.status_code == 404:
        return {"summary": summary_ok(f"{email} \u2014 appears in NO known breaches"),
                "sections": [{"title": "Result", "kind": "text",
                              "text": "Not found in any breach HIBP has indexed. "
                                      "Good news — but new breaches surface continuously, so treat it as a snapshot."}]}
    if r.status_code == 401:
        raise LookupError("HIBP rejected the API key (401). Check the key and your subscription.")
    if r.status_code == 429:
        raise LookupError("Rate limited by HIBP (429). The email-tier allows one request per 1.5 s — wait a few seconds.")
    if r.status_code != 200:
        raise LookupError(f"HIBP email lookup failed (HTTP {r.status_code}).")
    breaches = r.json()
    breaches.sort(key=lambda b: b.get("BreachDate", ""), reverse=True)
    rows = [
        [b.get("Title", "?"), str(b.get("BreachDate", "?")),
         f"{b.get('PwnCount', 0):,}", "; ".join(b.get("DataClasses", []) or [])]
        for b in breaches
    ]
    sections = [
        {"title": f"{len(breaches)} breach(es) known for {email}",
         "kind": "table",
         "head": ["Breach", "Date", "Accounts in breach", "Data exposed"],
         "rows": rows},
        {"title": "What to do next", "kind": "list", "items": [
            "Change the password on every affected site — especially anywhere you reused it.",
            "Turn on two-factor authentication; prefer app/passkey-based 2FA over SMS where possible.",
            "A breach hit does not prove the password failed — it can be any name/email/address field breach dumped.",
            "Check the linked breach above for exactly which fields leaked.",
        ]},
    ]
    return {"summary": summary_bad(f"{email} \u2014 FOUND in {len(breaches)} breach(es)"),
            "sections": sections}
