"""The non-username search types: wallet, name, IP, domain and image.

Everything here talks to public, keyless endpoints — block explorers, the
Cloudflare DNS-over-HTTPS resolver, ip-api.com and the public reverse-image
search engines. Nothing logs in and nothing needs an API key.

Every lookup returns a list of `scanner.Hit` objects so the live SSE stream
and the result cards can render all search types the same way.
"""
from __future__ import annotations

import asyncio
import html
import json
import re
import time
import urllib.parse
from typing import Any

import httpx

from .scanner import Hit, UA, detect_wallet

JSON_HEADERS = {"User-Agent": UA, "Accept": "application/json"}
BROWSER_HEADERS = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


class LookupError(Exception):
    """Raised when a lookup cannot produce a meaningful result."""


def _hit(eid: str, name: str, cat: str, status: str, url: str,
         detail: str = "", ms: int = 0, display: str = "",
         avatar: str = "", meta: list | None = None) -> Hit:
    return Hit(eid, name, cat, status, url, detail, ms, display, avatar, meta or [])


def _fmt_amount(value: float | int | None, symbol: str) -> str:
    if value is None:
        return "—"
    v = float(value)
    if v >= 1_000_000:
        return f"{v / 1_000_000:,.4f}M {symbol}"
    if v >= 1000:
        return f"{v / 1000:,.3f}k {symbol}"
    if v >= 1:
        return f"{v:,.4f} {symbol}"
    return f"{v:.8f} {symbol}"


# ==========================================================================
# crypto wallets
# ==========================================================================

async def wallet_lookup(value: str) -> list[Hit]:
    """On-chain balance and activity for ETH, BTC, SOL or TRX."""
    chain = detect_wallet(value)
    if not chain:
        raise LookupError("That is not a valid ETH, BTC, SOL or TRX address.")
    if chain == "BTC":
        return await _wallet_btc(value)
    if chain == "ETH":
        return await _wallet_eth(value)
    if chain == "SOL":
        return await _wallet_sol(value)
    return await _wallet_trx(value)


async def _wallet_btc(addr: str) -> list[Hit]:
    hits: list[Hit] = []
    started = time.perf_counter()
    url = f"https://blockstream.info/api/address/{addr}"
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0),
                                     headers=JSON_HEADERS,
                                     follow_redirects=True) as client:
            r = await client.get(url)
    except httpx.HTTPError as exc:
        return [_hit("btc", "Bitcoin", "wallet", "unresolved", url,
                     f"{type(exc).__name__}")]

    ms = int((time.perf_counter() - started) * 1000)
    if r.status_code != 200:
        return [_hit("btc", "Bitcoin", "wallet", "unresolved", url,
                     f"HTTP {r.status_code}", ms)]
    try:
        d = r.json()
    except ValueError:
        return [_hit("btc", "Bitcoin", "wallet", "unresolved", url,
                     "non-JSON response", ms)]

    chain_stats = d.get("chain_stats") or {}
    funded = chain_stats.get("funded_txo_sum") or 0
    spent = chain_stats.get("spent_txo_sum") or 0
    balance = (funded - spent) / 100_000_000
    tx_count = chain_stats.get("tx_count") or 0
    first_seen = ((chain_stats.get("first_seen") or {}).get("timestamp")) or None

    hits.append(_hit(
        "btc", "Bitcoin", "wallet", "hit",
        f"https://mempool.space/address/{addr}",
        f"{_fmt_amount(balance, 'BTC')} · {tx_count:,} transactions",
        ms,
        display=f"{balance:,.8f} BTC",
        avatar="https://blockstream.info/favicon.ico",
        meta=[
            ("Balance", _fmt_amount(balance, "BTC")),
            ("Received", _fmt_amount(funded / 100_000_000, "BTC")),
            ("Sent", _fmt_amount(spent / 100_000_000, "BTC")),
            ("Transactions", f"{tx_count:,}"),
            ("First seen", time.strftime("%Y-%m-%d", time.gmtime(first_seen))
             if first_seen else "—"),
        ],
    ))
    return hits


async def _wallet_eth(addr: str) -> list[Hit]:
    hits: list[Hit] = []
    started = time.perf_counter()
    url = f"https://api.blockchair.com/ethereum/dashboards/address/{addr}"
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(20.0),
                                     headers=JSON_HEADERS,
                                     follow_redirects=True) as client:
            r = await client.get(url)
    except httpx.HTTPError as exc:
        return [_hit("eth", "Ethereum", "wallet", "unresolved", url,
                     f"{type(exc).__name__}")]

    ms = int((time.perf_counter() - started) * 1000)
    if r.status_code != 200:
        return [_hit("eth", "Ethereum", "wallet", "unresolved", url,
                     f"HTTP {r.status_code}", ms)]
    try:
        d = r.json()
    except ValueError:
        return [_hit("eth", "Ethereum", "wallet", "unresolved", url,
                     "non-JSON response", ms)]

    row = (d.get("data") or {}).get(addr.lower())
    if not row:
        return [_hit("eth", "Ethereum", "wallet", "miss", url,
                     "no transactions on record for this address", ms)]
    a = row.get("address") or {}
    balance_wei = a.get("balance") or 0
    balance_eth = balance_wei / 1e18
    tx_count = a.get("transaction_count") or 0
    received = ((a.get("received") or 0) / 1e18)
    spent = ((a.get("spent") or 0) / 1e18)

    hits.append(_hit(
        "eth", "Ethereum", "wallet", "hit",
        f"https://www.oklink.com/eth/address/{addr}",
        f"{_fmt_amount(balance_eth, 'ETH')} · {tx_count:,} transactions",
        ms,
        display=f"{balance_eth:,.8f} ETH",
        avatar="https://www.ethereum.org/favicon.ico",
        meta=[
            ("Balance", _fmt_amount(balance_eth, "ETH")),
            ("Received", _fmt_amount(received, "ETH")),
            ("Sent", _fmt_amount(spent, "ETH")),
            ("Transactions", f"{tx_count:,}"),
            ("Balance (wei)", f"{balance_wei:,}"),
        ],
    ))
    return hits


async def _wallet_sol(addr: str) -> list[Hit]:
    started = time.perf_counter()
    rpc = "https://api.mainnet-beta.solana.com"
    url = f"https://solscan.io/account/{addr}"
    headers = {"User-Agent": UA, "Content-Type": "application/json"}

    async def call(method: str, params: list) -> Any:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0),
                                     headers=headers) as client:
            r = await client.post(rpc, json={
                "jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        r.raise_for_status()
        return r.json()

    try:
        bal_res, sig_res = await asyncio.gather(
            call("getBalance", [addr]),
            call("getSignaturesForAddress", [addr, {"limit": 1000}]),
            return_exceptions=True,
        )
    except httpx.HTTPError as exc:
        return [_hit("sol", "Solana", "wallet", "unresolved", url,
                     f"{type(exc).__name__}")]

    ms = int((time.perf_counter() - started) * 1000)
    if isinstance(bal_res, Exception):
        return [_hit("sol", "Solana", "wallet", "unresolved", url,
                     f"{type(bal_res).__name__}", ms)]
    if isinstance(sig_res, Exception):
        sig_res = None

    value = (bal_res.get("result") or {}).get("value")
    if value is None:
        return [_hit("sol", "Solana", "wallet", "unresolved", url,
                     "RPC returned no balance", ms)]
    balance = value / 1e9
    sigs = (sig_res.get("result") if isinstance(sig_res, dict) else None) or []

    first_block = sigs[-1].get("blockTime") if sigs else None
    last_block = sigs[0].get("blockTime") if sigs else None

    hits = [_hit(
        "sol", "Solana", "wallet", "hit", url,
        f"{_fmt_amount(balance, 'SOL')} · {len(sigs):,} signatures (last 1000)",
        ms,
        display=f"{balance:,.9f} SOL",
        avatar="https://solana.com/favicon.ico",
        meta=[
            ("Balance", _fmt_amount(balance, "SOL")),
            ("Lamports", f"{value:,}"),
            ("Recent signatures", f"{len(sigs):,}"),
            ("Latest activity", time.strftime("%Y-%m-%d %H:%M", time.gmtime(last_block))
             if last_block else "—"),
            ("Earliest in page", time.strftime("%Y-%m-%d %H:%M", time.gmtime(first_block))
             if first_block else "—"),
        ],
    )]
    return hits


async def _wallet_trx(addr: str) -> list[Hit]:
    started = time.perf_counter()
    url = f"https://api.trongrid.io/v1/accounts/{addr}"
    explorer = f"https://tronscan.org/#/account/{addr}"
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0),
                                     headers=JSON_HEADERS,
                                     follow_redirects=True) as client:
            r = await client.get(url)
    except httpx.HTTPError as exc:
        return [_hit("trx", "Tron", "wallet", "unresolved", explorer,
                     f"{type(exc).__name__}")]

    ms = int((time.perf_counter() - started) * 1000)
    if r.status_code != 200:
        return [_hit("trx", "Tron", "wallet", "unresolved", explorer,
                     f"HTTP {r.status_code}", ms)]
    try:
        d = r.json()
    except ValueError:
        return [_hit("trx", "Tron", "wallet", "unresolved", explorer,
                     "non-JSON response", ms)]

    data = d.get("data") or []
    if not data:
        return [_hit("trx", "Tron", "wallet", "miss", explorer,
                     "account not found on Tron", ms)]
    acc = data[0]
    balance_trx = (acc.get("balance") or 0) / 1_000_000
    created = acc.get("create_time")
    created_str = time.strftime("%Y-%m-%d %H:%M", time.gmtime(created / 1000)) \
        if created else "—"

    return [_hit(
        "trx", "Tron", "wallet", "hit", explorer,
        f"{_fmt_amount(balance_trx, 'TRX')}",
        ms,
        display=f"{balance_trx:,.6f} TRX",
        avatar="https://tron.network/favicon.ico",
        meta=[
            ("Balance", _fmt_amount(balance_trx, "TRX")),
            ("Bandwidth", f"{acc.get('net_usage', 0):,}"),
            ("Energy", f"{acc.get('energy_usage', 0):,}"),
            ("Created", created_str),
            ("Account type", "contract" if acc.get("type") == "Contract" else "wallet"),
        ],
    )]


# ==========================================================================
# names
# ==========================================================================

# Platforms worth checking for a real name. Chosen for reliable public
# profile URLs and low bot-blocking.
NAME_PLATFORMS: list[dict] = [
    {"name": "Instagram", "url": "https://www.instagram.com/{h}/"},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{h}"},
    {"name": "X (Twitter)", "url": "https://x.com/{h}"},
    {"name": "Facebook", "url": "https://www.facebook.com/{h}"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{h}/about.json"},
    {"name": "GitHub", "url": "https://github.com/{h}"},
    {"name": "GitLab", "url": "https://gitlab.com/{h}"},
    {"name": "Telegram", "url": "https://t.me/{h}"},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{h}"},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{h}/"},
    {"name": "Tumblr", "url": "https://{h}.tumblr.com"},
    {"name": "Medium", "url": "https://medium.com/@{h}"},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{h}"},
    {"name": "Spotify", "url": "https://open.spotify.com/user/{h}"},
    {"name": "Patreon", "url": "https://www.patreon.com/{h}"},
    {"name": "About.me", "url": "https://about.me/{h}"},
    {"name": "Linktree", "url": "https://linktr.ee/{h}"},
    {"name": "Keybase", "url": "https://keybase.io/{h}"},
    {"name": "Steam", "url": "https://steamcommunity.com/id/{h}"},
    {"name": "Twitch", "url": "https://m.twitch.tv/{h}"},
    {"name": "Vimeo", "url": "https://vimeo.com/{h}"},
    {"name": "Flickr", "url": "https://www.flickr.com/people/{h}"},
    {"name": "Letterboxd", "url": "https://letterboxd.com/{h}/"},
    {"name": "Goodreads", "url": "https://www.goodreads.com/{h}"},
    {"name": "Last.fm", "url": "https://www.last.fm/user/{h}"},
    {"name": "Bandcamp", "url": "https://{h}.bandcamp.com"},
    {"name": "500px", "url": "https://500px.com/p/{h}"},
    {"name": "DeviantArt", "url": "https://{h}.deviantart.com"},
    {"name": "Dribbble", "url": "https://dribbble.com/{h}"},
    {"name": "Behance", "url": "https://www.behance.net/{h}"},
    {"name": "Mastodon", "url": "https://mastodon.social/@{h}"},
    {"name": "Bluesky", "url": "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle={h}.bsky.social"},
]


def name_candidates(full_name: str) -> list[str]:
    """Handle candidates for a real name, most likely first."""
    parts = [p for p in re.split(r"[\s]+", full_name.strip()) if p]
    if not parts:
        return []
    first = re.sub(r"[^A-Za-z]", "", parts[0]).lower()
    last = re.sub(r"[^A-Za-z]", "", parts[-1]).lower() if len(parts) > 1 else ""
    middle = re.sub(r"[^A-Za-z]", "", parts[1]).lower() if len(parts) > 2 else ""

    out: list[str] = []

    def add(value: str) -> None:
        if value and 2 <= len(value) <= 40 and value not in out:
            out.append(value)

    if first and last:
        add(f"{first}.{last}")
        add(f"{first}{last}")
        add(f"{first}_{last}")
        add(f"{first[0]}{last}")
        add(f"{first}{last[0]}")
        add(f"{last}.{first}")
        add(f"{last}{first}")
        if middle:
            add(f"{first}.{middle}.{last}")
            add(f"{first[0]}{middle[0]}{last}")
    if first:
        add(first)
        add(f"{first}{len(last)}" if last else first)
    if last:
        add(last)

    return out[:10]


async def name_lookup(value: str, pro: bool = True) -> list[Hit]:
    """Find social profiles whose handle looks like the given name."""
    candidates = name_candidates(value)
    if not candidates:
        raise LookupError("Type a full name — at least a first and last name.")

    platforms = NAME_PLATFORMS
    if not pro:
        platforms = NAME_PLATFORMS[:12]

    started = time.perf_counter()
    sem = asyncio.Semaphore(24)
    found: list[Hit] = []
    checked = 0

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(8.0),
        headers=BROWSER_HEADERS,
        follow_redirects=True,
        limits=httpx.Limits(max_connections=32, max_keepalive_connections=16),
    ) as client:

        async def probe(platform: dict, handle: str) -> None:
            nonlocal checked
            url = platform["url"].replace("{h}", handle)
            async with sem:
                try:
                    r = await client.get(url)
                except httpx.HTTPError:
                    return
            checked += 1
            body = ""
            if "about.json" in url:
                body = r.text[:4000]
            ok = False
            if r.status_code in (200, 301, 302):
                if platform["name"] == "Reddit":
                    ok = '"name"' in body and '"id"' in body
                elif platform["name"] == "Bluesky":
                    ok = '"did"' in body
                elif platform["name"] == "Telegram":
                    ok = "tgme_page_title" in r.text
                else:
                    ok = True
            if not ok:
                return
            found.append(_hit(
                f"{platform['name'].lower().replace(' ', '-')}-{handle}",
                platform["name"], "name", "hit", url,
                f"handle candidate “{handle}”", 0,
                display=f"{handle}",
                avatar=f"https://{urllib.parse.urlsplit(url).hostname}/favicon.ico",
                meta=[("Candidate handle", handle),
                      ("Source", platform["name"])],
            ))

        tasks = [probe(p, h) for h in candidates for p in platforms]
        await asyncio.gather(*tasks, return_exceptions=True)

    ms = int((time.perf_counter() - started) * 1000)
    found.sort(key=lambda h: (h.display_name, h.name))

    if not found:
        return [_hit(
            "name-none", "Name search", "name", "miss",
            f"https://www.google.com/search?q={urllib.parse.quote('\"' + value + '\" social')}",
            f"no profile matched any of {len(candidates)} handle candidates "
            f"({checked} checks)",
            ms,
            display=f"{len(candidates)} candidates checked",
            meta=[("Candidates", ", ".join(candidates)),
                  ("Profiles found", "0"),
                  ("Checks run", f"{checked:,}")],
        )]

    return found


# ==========================================================================
# IP and domain
# ==========================================================================

async def ip_lookup(value: str) -> list[Hit]:
    """Geolocation, ASN and reverse DNS for an IP address."""
    started = time.perf_counter()
    ip = value.strip()
    fields = ("status,message,country,countryCode,regionName,city,zip,lat,lon,"
              "timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query")

    async with httpx.AsyncClient(timeout=httpx.Timeout(12.0),
                                 headers=JSON_HEADERS) as client:
        geo_task = client.get(
            f"http://ip-api.com/json/{urllib.parse.quote(ip)}",
            params={"fields": fields})
        rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa" \
            if ":" not in ip else None
        ptr_task = client.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": rev, "type": "PTR"},
            headers={"Accept": "application/dns-json"}) if rev else None

        gathered = await asyncio.gather(geo_task, ptr_task, return_exceptions=True)
        geo_resp, ptr_resp = gathered

    ms = int((time.perf_counter() - started) * 1000)
    hits: list[Hit] = []

    if isinstance(geo_resp, Exception) or geo_resp.status_code != 200:
        hits.append(_hit("ip-geo", "IP geolocation", "network", "unresolved",
                         f"http://ip-api.com/json/{ip}", "lookup failed", ms))
        return hits
    try:
        geo = geo_resp.json()
    except ValueError:
        hits.append(_hit("ip-geo", "IP geolocation", "network", "unresolved",
                         f"http://ip-api.com/json/{ip}", "non-JSON response", ms))
        return hits
    if geo.get("status") != "success":
        hits.append(_hit("ip-geo", "IP geolocation", "network", "unresolved",
                         f"http://ip-api.com/json/{ip}",
                         geo.get("message", "lookup failed"), ms))
        return hits

    flags = []
    if geo.get("proxy"):
        flags.append("proxy / anonymizer")
    if geo.get("mobile"):
        flags.append("mobile network")
    if geo.get("hosting"):
        flags.append("hosting / datacenter")

    ptr = ""
    if isinstance(ptr_resp, httpx.Response) and ptr_resp.status_code == 200:
        try:
            for a in (ptr_resp.json().get("Answer") or []):
                if a.get("type") == 12 and a.get("data"):
                    ptr = str(a["data"])
                    break
        except ValueError:
            ptr = ""

    hits.append(_hit(
        "ip-geo", "IP geolocation", "network", "hit",
        f"https://ipinfo.io/{ip}",
        f"{geo.get('city', '?')}, {geo.get('country', '?')} · "
        f"{geo.get('asname') or geo.get('as') or '—'}",
        ms,
        display=f"{ip}",
        avatar="https://ipinfo.io/favicon.ico",
        meta=[
            ("IP", geo.get("query", ip)),
            ("Country", f"{geo.get('country', '—')} ({geo.get('countryCode', '')})"),
            ("Region", geo.get("regionName", "—")),
            ("City", geo.get("city", "—")),
            ("Coordinates", f"{geo.get('lat', '')}, {geo.get('lon', '')}"),
            ("Timezone", geo.get("timezone", "—")),
            ("ISP", geo.get("isp", "—")),
            ("Organisation", geo.get("org", "—")),
            ("ASN", f"{geo.get('as', '')} {geo.get('asname', '')}".strip() or "—"),
            ("Reverse DNS", ptr or geo.get("reverse") or "—"),
            ("Flags", ", ".join(flags) or "none"),
        ],
    ))
    return hits


async def domain_lookup(value: str) -> list[Hit]:
    """RDAP registration data plus live DNS records for a domain."""
    started = time.perf_counter()
    host = value.strip().lower()
    hits: list[Hit] = []

    async with httpx.AsyncClient(timeout=httpx.Timeout(15.0),
                                 headers=BROWSER_HEADERS,
                                 follow_redirects=True) as client:
        rdap_task = client.get(f"https://rdap.org/domain/{host}")
        dns_tasks = {
            qtype: client.get("https://cloudflare-dns.com/dns-query",
                              params={"name": host, "type": qtype},
                              headers={"Accept": "application/dns-json"})
            for qtype in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA")
        }
        gathered = await asyncio.gather(
            rdap_task, *dns_tasks.values(), return_exceptions=True)

    ms = int((time.perf_counter() - started) * 1000)

    rdap = gathered[0]
    if not isinstance(rdap, Exception) and rdap.status_code == 200:
        try:
            data = rdap.json()
        except ValueError:
            data = {}
        events = {}
        for ev in data.get("events", []) or []:
            if ev.get("eventAction") and ev.get("eventDate"):
                events[ev["eventAction"]] = str(ev["eventDate"])[:10]
        registrar = ""
        for ent in data.get("entities", []) or []:
            if "registrar" in (ent.get("roles") or []):
                for v in (ent.get("vcardArray") or [None, []])[1]:
                    if v and v[0] == "fn":
                        registrar = str(v[3])
                break
        ns = ", ".join(str(n.get("ldhName", "")).lower()
                       for n in (data.get("nameservers") or [])) or "—"
        hits.append(_hit(
            "rdap", "RDAP registration", "domain", "hit",
            f"https://rdap.org/domain/{host}",
            f"{registrar or '—'} · created {events.get('registration', '—')}",
            ms,
            display=host,
            avatar=f"https://{host}/favicon.ico",
            meta=[
                ("Domain", host),
                ("Registrar", registrar or "—"),
                ("Registered", events.get("registration", "—")),
                ("Last changed", events.get("last changed", "—")),
                ("Expiry", events.get("expiration", "—")),
                ("Status", ", ".join(data.get("status", []) or []) or "—"),
                ("Nameservers", ns),
                ("DNSSEC", "signed" if (data.get("secureDNS") or {}).get(
                    "delegationSigned") else "not signed"),
            ],
        ))
    else:
        detail = "lookup failed" if isinstance(rdap, Exception) else f"HTTP {rdap.status_code}"
        hits.append(_hit("rdap", "RDAP registration", "domain", "unresolved",
                         f"https://rdap.org/domain/{host}", detail, ms))

    qtypes = list(dns_tasks.keys())
    for qtype, resp in zip(qtypes, gathered[1:]):
        if isinstance(resp, Exception) or resp.status_code != 200:
            hits.append(_hit(f"dns-{qtype.lower()}", f"DNS {qtype}", "domain",
                             "unresolved", f"https://{host}",
                             "lookup failed", ms))
            continue
        try:
            answers = resp.json().get("Answer") or []
        except ValueError:
            answers = []
        values = [str(a.get("data", "")) for a in answers if a.get("data")]
        if not values:
            hits.append(_hit(f"dns-{qtype.lower()}", f"DNS {qtype}", "domain",
                             "miss", f"https://{host}", f"no {qtype} record", ms))
        else:
            hits.append(_hit(
                f"dns-{qtype.lower()}", f"DNS {qtype}", "domain", "hit",
                f"https://{host}",
                "  ·  ".join(values[:6])[:220], ms,
                display=qtype,
                meta=[(qtype, "\n".join(values[:25]))],
            ))
    return hits


# ==========================================================================
# reverse image search
# ==========================================================================

def _host_of(url: str) -> str:
    try:
        return urllib.parse.urlsplit(url).hostname or ""
    except ValueError:
        return ""


async def image_lookup(value: str) -> list[Hit]:
    """Reverse-image search: every page that still hosts the picture."""
    img = value.strip()
    started = time.perf_counter()
    hits: list[Hit] = []

    async with httpx.AsyncClient(timeout=httpx.Timeout(20.0),
                                 headers=BROWSER_HEADERS,
                                 follow_redirects=True,
                                 limits=httpx.Limits(max_connections=3)) as client:
        results = await asyncio.gather(
            _reverse_yandex(client, img),
            _reverse_bing(client, img),
            _reverse_tineye(client, img),
            return_exceptions=True,
        )

    ms = int((time.perf_counter() - started) * 1000)
    engines = ("Yandex", "Bing", "TinEye")
    seen: set[str] = set()
    for engine, res in zip(engines, results):
        if isinstance(res, Exception):
            hits.append(_hit(f"rev-{engine.lower()}", f"{engine} reverse image",
                             "image", "unresolved", img,
                             f"{type(res).__name__}", ms))
            continue
        pages = res or []
        if not pages:
            hits.append(_hit(f"rev-{engine.lower()}", f"{engine} reverse image",
                             "image", "miss", img,
                             "no matching pages found", ms))
            continue
        for page in pages:
            url = page.get("url") or ""
            if not url or url in seen:
                continue
            seen.add(url)
            hits.append(_hit(
                f"rev-{engine.lower()}-{len(seen)}", f"{engine} reverse image",
                "image", "hit", url,
                page.get("title") or f"matching page on {urlparse_host(url)}",
                ms,
                display=page.get("title") or urlparse_host(url),
                avatar=page.get("image") or f"https://{urlparse_host(url)}/favicon.ico",
                meta=[("Found on", urlparse_host(url)),
                      ("Engine", engine),
                      ("Page", url)],
            ))
    return hits


def urlparse_host(url: str) -> str:
    try:
        return urllib.parse.urlsplit(url).hostname or url
    except ValueError:
        return url


async def _reverse_bing(client: httpx.AsyncClient, img: str) -> list[dict]:
    url = ("https://www.bing.com/images/search?q=imgurl:"
           + urllib.parse.quote(img, safe="")
           + "&view=detailv2&iss=sbi")
    r = await client.get(url)
    if r.status_code != 200:
        raise LookupError(f"HTTP {r.status_code}")
    out: list[dict] = []
    for m in re.finditer(r'class="iusc"[^>]*?\sm="([^"]+)"', r.text):
        raw = html.unescape(m.group(1))
        try:
            d = json.loads(raw)
        except ValueError:
            continue
        purl = d.get("purl") or ""
        if not purl:
            continue
        out.append({"url": purl, "title": d.get("t") or "", "image": d.get("murl") or ""})
    return out


async def _reverse_yandex(client: httpx.AsyncClient, img: str) -> list[dict]:
    cbir = "cbir_id=" + str(int(time.time() * 1000))
    r = await client.post(
        "https://yandex.com/images-apphost/image-download"
        + ("?" + cbir if False else ""),
        params={"cbir_id": str(int(time.time() * 1000)),
                "images_avatars_size": "preview",
                "images_avatars_namespace": "images-cbir"},
        json={"url": img},
    )
    if r.status_code != 200:
        raise LookupError(f"HTTP {r.status_code}")
    try:
        data = r.json()
    except ValueError:
        raise LookupError("non-JSON response") from None
    cbir_id = data.get("cbir_id") or ""
    if not cbir_id:
        raise LookupError("Yandex did not return a search id")

    page = await client.get(
        "https://yandex.com/images/search",
        params={"rpt": "imageview", "cbir_id": cbir_id, "source": "collections"},
    )
    if page.status_code != 200:
        raise LookupError(f"HTTP {page.status_code}")

    out: list[dict] = []
    for m in re.finditer(r'data-bem="([^"]+)"', page.text):
        raw = html.unescape(m.group(1))
        try:
            d = json.loads(raw)
        except ValueError:
            continue
        snippet = d.get("snippet") or {}
        url = snippet.get("url") or ""
        if not url:
            continue
        out.append({"url": url, "title": snippet.get("title") or "",
                    "image": snippet.get("image") or ""})
    return out


async def _reverse_tineye(client: httpx.AsyncClient, img: str) -> list[dict]:
    r = await client.get("https://tineye.com/search",
                         params={"url": img})
    if r.status_code != 200:
        raise LookupError(f"HTTP {r.status_code}")
    out: list[dict] = []
    seen: set[str] = set()
    for m in re.finditer(r'href="(https?://[^"]+)"[^>]*title="([^"]*)"', r.text):
        url = html.unescape(m.group(1))
        if "tineye.com" in url or url in seen:
            continue
        seen.add(url)
        out.append({"url": url, "title": html.unescape(m.group(2)), "image": ""})
    return out
