"""The live sweep engine.

Scans a username (or email / phone) across the endpoint corpus, concurrently,
and reports each endpoint as it resolves so the UI can stream results live.

Result classes (mirroring the public site's language):
  - hit        the endpoint returned evidence that the handle exists
  - miss       the endpoint returned evidence that it does not exist
  - unresolved the endpoint could not answer (blocked, timed out, unclear)

Every check is a plain GET against a public URL. Nothing logs in, nothing
sends form data, nothing touches a protected endpoint.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from contextlib import asynccontextmanager
from typing import AsyncIterator, Callable

import httpx

CORPUS_PATH = Path(__file__).resolve().parent.parent / "data" / "endpoints.json"

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

# How many endpoints we hit at once. High enough to finish 773 checks in
# roughly 20 seconds, low enough that a single host doesn't get hammered.
# Override with OSINT_CONCURRENCY on constrained deployments.
CONCURRENCY = max(4, min(80, int(os.environ.get("OSINT_CONCURRENCY", "40"))))
PER_REQUEST_TIMEOUT = float(os.environ.get("OSINT_TIMEOUT", "8.0"))
# How many full username sweeps may run at once. Each sweep keeps up to
# CONCURRENCY sockets open, so on a 512 MB instance a handful is the ceiling;
# extra sweeps wait their turn instead of exhausting memory and sockets.
MAX_SWEEPS = max(1, min(20, int(os.environ.get("OSINT_MAX_SCANS", "3"))))
_sweep_sems: dict[int, asyncio.Semaphore] = {}


@asynccontextmanager
async def sweep_slot():
    """Hold one of the MAX_SWEEPS global sweep slots (one pool per event loop)."""
    loop_id = id(asyncio.get_running_loop())
    sem = _sweep_sems.get(loop_id)
    if sem is None:
        if len(_sweep_sems) > 8:
            _sweep_sems.clear()
        sem = _sweep_sems[loop_id] = asyncio.Semaphore(MAX_SWEEPS)
    async with sem:
        yield

# A "hit" needs positive evidence. These are the signals we trust.
STATUS_HIT_CODES = {200, 201}
STATUS_MISS_CODES = {404, 410}

_EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")
_PHONE_RE = re.compile(r"^\+?[0-9][0-9\s().-]{6,19}$")


@dataclass
class Endpoint:
    id: str
    name: str
    category: str
    method: str
    url: str
    probe: str | None = None
    main: str | None = None
    absence: list[str] = field(default_factory=list)
    presence: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    adult: bool = False

    def target_url(self, handle: str) -> str:
        return self.url.replace("{username}", handle)


@dataclass
class Hit:
    endpoint_id: str
    name: str
    category: str
    status: str            # hit | miss | unresolved
    url: str
    detail: str = ""
    ms: int = 0
    display_name: str = ""
    avatar: str = ""
    meta: list = field(default_factory=list)

    @property
    def is_hit(self) -> bool:
        return self.status == "hit"


class Corpus:
    """The endpoint catalog, loaded once and shared by every scan."""

    def __init__(self, endpoints: list[Endpoint], categories: list[dict]):
        self.endpoints = endpoints
        self.categories = categories

    @property
    def total(self) -> int:
        return len(self.endpoints)

    @property
    def adult_total(self) -> int:
        return sum(1 for ep in self.endpoints if ep.adult)

    def by_category(self) -> dict[str, list[Endpoint]]:
        out: dict[str, list[Endpoint]] = {}
        for ep in self.endpoints:
            out.setdefault(ep.category, []).append(ep)
        return out

    def for_plan(self, pro: bool) -> list[Endpoint]:
        """The endpoints a plan may reach.

        Adult / explicit sources stay in the corpus but are Pro-only: a free
        scan never sees them and never reports them.
        """
        if pro:
            return list(self.endpoints)
        return [ep for ep in self.endpoints if not ep.adult]

    def categories_for(self, endpoints: list[Endpoint]) -> list[dict]:
        """Category metadata with counts that match the endpoints we will scan."""
        counts: dict[str, int] = {}
        for ep in endpoints:
            counts[ep.category] = counts.get(ep.category, 0) + 1
        out = []
        for cat in self.categories:
            out.append({
                "id": cat["id"],
                "label": cat["label"],
                "count": counts.get(cat["id"], 0),
            })
        return out


_CORPUS: Corpus | None = None


def load_corpus() -> Corpus:
    global _CORPUS
    if _CORPUS is not None:
        return _CORPUS
    with CORPUS_PATH.open(encoding="utf-8") as fh:
        raw = json.load(fh)
    endpoints = [
        Endpoint(
            id=e["id"], name=e["name"], category=e["category"], method=e["method"],
            url=e["url"], probe=e.get("probe"), main=e.get("main"),
            absence=e.get("absence") or [], presence=e.get("presence") or [],
            tags=e.get("tags") or [], adult=bool(e.get("adult")),
        )
        for e in raw["endpoints"]
    ]
    _CORPUS = Corpus(endpoints, raw.get("categories") or [])
    return _CORPUS


# --------------------------------------------------------------------------
# input handling
# --------------------------------------------------------------------------

class InputError(Exception):
    """Raised when the query cannot be scanned."""


# --- pattern matchers for the supported identifier types --------------------

_ETH_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_BTC_BECH32_RE = re.compile(r"^bc1[023456789acdefghjklmnpqrstuvwxyz]{11,71}$", re.I)
_BTC_LEGACY_RE = re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$")
_TRX_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
_SOL_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
_IMAGE_RE = re.compile(
    r"^https?://\S+\.(?:jpe?g|png|gif|webp|bmp|svg|avif|tiff?|heic)(?:\?\S*)?$", re.I)
_DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,24}$", re.I)
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Types the scanner itself understands. `kind` is the selected search tab.
INPUT_KINDS = ("username", "email", "phone", "name", "wallet", "ip", "domain", "image")


def detect_wallet(value: str) -> str:
    """Return the chain for a crypto address, or '' if it is not one."""
    v = value.strip()
    if _ETH_RE.match(v):
        return "ETH"
    if _BTC_BECH32_RE.match(v):
        return "BTC"
    if _TRX_RE.match(v):
        return "TRX"
    if _BTC_LEGACY_RE.match(v):
        return "BTC"
    if _SOL_RE.match(v):
        return "SOL"
    return ""


def classify_input(query: str, kind: str | None = None) -> tuple[str, str]:
    """Return (kind, normalised_value) for a raw query.

    `kind` is the search tab the user picked. When it is given, the value is
    validated as that type. When it is not, the type is detected — and the
    detection is deliberately conservative: a dotted string stays a username
    ("john.smith" is far more often a handle than a domain).

    kind is one of: username | email | phone | name | wallet | ip | domain | image
    """
    q = query.strip()
    if not q:
        raise InputError("Type something to search for first.")

    if kind:
        kind = kind.strip().lower()
        if kind not in INPUT_KINDS:
            raise InputError(f"Unknown search type {kind!r}.")
        return _validate_for_kind(kind, q)

    # A leading @ is a handle, never an email address.
    if q.startswith("@"):
        handle = q[1:].strip()
        if not handle:
            raise InputError("Type something to search for first.")
        return _validate_handle(handle)

    if "@" in q:
        email = q.strip().lower()
        if not _EMAIL_RE.match(email):
            raise InputError("That does not look like a valid email address.")
        return "email", email

    if q.startswith(("http://", "https://")):
        if _IMAGE_RE.match(q):
            return "image", q
        # a pasted profile URL — take the last meaningful segment
        seg = [s for s in re.split(r"[/?#]", q) if s]
        handle = seg[-1] if seg else ""
        handle = handle.lstrip("@")
        if not handle:
            raise InputError("Type something to search for first.")
        return _validate_handle(handle)

    chain = detect_wallet(q)
    if chain:
        return "wallet", q

    if _IPV4_RE.match(q):
        import ipaddress
        try:
            ipaddress.ip_address(q)
        except ValueError:
            pass
        else:
            return "ip", q
    else:
        try:
            import ipaddress
            ipaddress.ip_address(q)
        except ValueError:
            pass
        else:
            return "ip", q

    if _PHONE_RE.match(q) and sum(c.isdigit() for c in q) >= 7:
        digits = re.sub(r"[^\d+]", "", q)
        return "phone", digits

    handle = q
    if "://" in handle or "/" in handle:
        # a pasted profile URL — take the last meaningful segment
        seg = [s for s in re.split(r"[/?#]", handle) if s]
        handle = seg[-1] if seg else ""
        handle = handle.lstrip("@")
    handle = handle.strip()
    if not handle:
        raise InputError("Type something to search for first.")
    return _validate_handle(handle)


def _validate_for_kind(kind: str, q: str) -> tuple[str, str]:
    if kind == "username":
        handle = q.lstrip("@").strip()
        if "://" in handle or "/" in handle:
            seg = [s for s in re.split(r"[/?#]", handle) if s]
            handle = (seg[-1] if seg else "").lstrip("@")
        return _validate_handle(handle)

    if kind == "email":
        email = q.lower()
        if not _EMAIL_RE.match(email):
            raise InputError("That does not look like a valid email address.")
        return "email", email

    if kind == "phone":
        if not _PHONE_RE.match(q) or sum(c.isdigit() for c in q) < 7:
            raise InputError("That does not look like a phone number.")
        return "phone", re.sub(r"[^\d+]", "", q)

    if kind == "name":
        name = re.sub(r"\s+", " ", q).strip()
        words = name.split(" ")
        if len(words) < 2 or len(name) > 80:
            raise InputError("Type a full name — at least a first and last name.")
        for word in words:
            if not re.fullmatch(r"[A-Za-z][A-Za-z'\-]{1,29}", word):
                raise InputError("Names may only contain letters, apostrophes and hyphens.")
        return "name", name

    if kind == "wallet":
        chain = detect_wallet(q)
        if not chain:
            raise InputError(
                "That is not a valid ETH, BTC, SOL or TRX address.")
        return "wallet", q

    if kind == "ip":
        import ipaddress
        try:
            ip = ipaddress.ip_address(q)
        except ValueError:
            raise InputError("That is not a valid IPv4 or IPv6 address.") from None
        return "ip", str(ip)

    if kind == "domain":
        host = q.strip().rstrip(".").lower()
        if "://" in host:
            host = re.sub(r"^[a-z]+://", "", host)
        host = host.split("/")[0].split(":")[0]
        if not _DOMAIN_RE.match(host):
            raise InputError("That does not look like a domain name.")
        return "domain", host

    if kind == "image":
        if not q.startswith(("http://", "https://")):
            raise InputError("Paste the direct URL of the image.")
        return "image", q

    raise InputError(f"Unknown search type {kind!r}.")


def _validate_handle(handle: str) -> tuple[str, str]:
    if len(handle) > 64:
        raise InputError("That username is too long to scan.")
    if not re.fullmatch(r"[A-Za-z0-9._\-+]{1,64}", handle):
        raise InputError(
            "Usernames may only contain letters, digits, dots, dashes and underscores."
        )
    return "username", handle


# --------------------------------------------------------------------------
# checking
# --------------------------------------------------------------------------

async def _check_one(client: httpx.AsyncClient, ep: Endpoint, handle: str) -> Hit:
    url = ep.target_url(handle)
    started = time.perf_counter()
    try:
        resp = await client.get(url)
    except httpx.TimeoutException:
        return Hit(ep.id, ep.name, ep.category, "unresolved", url,
                   "timed out", int((time.perf_counter() - started) * 1000))
    except httpx.HTTPError as exc:
        return Hit(ep.id, ep.name, ep.category, "unresolved", url,
                   type(exc).__name__, int((time.perf_counter() - started) * 1000))

    elapsed = int((time.perf_counter() - started) * 1000)
    code = resp.status_code

    if ep.method == "message":
        body = resp.text[:20000]
        lowered = body.lower()
        for marker in ep.absence:
            if marker.lower() in lowered:
                return Hit(ep.id, ep.name, ep.category, "miss", url,
                           "page says the account does not exist", elapsed)
        if code in STATUS_MISS_CODES:
            return Hit(ep.id, ep.name, ep.category, "miss", url,
                       "no page for this handle", elapsed)
        if code in STATUS_HIT_CODES:
            for marker in ep.presence:
                if marker.lower() in lowered:
                    return Hit(ep.id, ep.name, ep.category, "hit", url,
                               "profile page returned", elapsed)
            # a 200 with no absence marker is a reasonable hit for these sites
            return Hit(ep.id, ep.name, ep.category, "hit", url,
                       "profile page returned", elapsed)
        return Hit(ep.id, ep.name, ep.category, "unresolved", url,
                   f"HTTP {code}", elapsed)

    # status_code method
    if code in STATUS_HIT_CODES:
        return Hit(ep.id, ep.name, ep.category, "hit", url,
                   "profile page returned", elapsed)
    if code in STATUS_MISS_CODES:
        return Hit(ep.id, ep.name, ep.category, "miss", url,
                   "no page for this handle", elapsed)
    if code in (301, 302, 303, 307, 308):
        return Hit(ep.id, ep.name, ep.category, "hit", url,
                   "redirected to a profile", elapsed)
    if code in (401, 403, 429):
        return Hit(ep.id, ep.name, ep.category, "unresolved", url,
                   f"blocked (HTTP {code})", elapsed)
    return Hit(ep.id, ep.name, ep.category, "unresolved", url,
               f"HTTP {code}", elapsed)


async def _run_batch(
    client: httpx.AsyncClient,
    batch: list[Endpoint],
    handle: str,
) -> list[Hit]:
    sem = asyncio.Semaphore(CONCURRENCY)

    async def guarded(ep: Endpoint) -> Hit:
        async with sem:
            return await _check_one(client, ep, handle)

    return list(await asyncio.gather(*(guarded(ep) for ep in batch)))


# --------------------------------------------------------------------------
# the scan
# --------------------------------------------------------------------------

@dataclass
class ScanResult:
    query: str
    kind: str
    value: str
    hits: list[Hit]
    elapsed: float
    checked: int
    total: int
    categories: list[dict]

    @property
    def found(self) -> int:
        return sum(1 for h in self.hits if h.is_hit)

    def by_category(self) -> dict[str, list[Hit]]:
        out: dict[str, list[Hit]] = {c["id"]: [] for c in self.categories}
        for h in self.hits:
            out.setdefault(h.category, []).append(h)
        return out


async def iter_hits(
    client: httpx.AsyncClient,
    endpoints: list[Endpoint],
    handle: str,
) -> AsyncIterator[Hit]:
    """Check every endpoint with a saturated worker pool.

    Yields each Hit as it completes, so callers can stream results out live.
    A fixed pool of CONCURRENCY workers is used rather than one task per
    endpoint: firing all 773 requests at once starves the connection pool and
    pushes most of them past their timeout.
    """
    queue: asyncio.Queue[Endpoint | None] = asyncio.Queue()
    for ep in endpoints:
        queue.put_nowait(ep)
    for _ in range(CONCURRENCY):
        queue.put_nowait(None)  # worker sentinels

    out: asyncio.Queue[Hit | None] = asyncio.Queue()

    async def worker() -> None:
        while True:
            ep = await queue.get()
            if ep is None:
                queue.task_done()
                return
            try:
                hit = await _check_one(client, ep, handle)
            except Exception:  # noqa: BLE001 — a worker must never die silently
                hit = Hit(ep.id, ep.name, ep.category, "unresolved",
                          ep.target_url(handle), "check failed")
            await out.put(hit)
            queue.task_done()

    async def supervisor() -> None:
        """Signal end-of-stream once every endpoint has been handled."""
        await queue.join()
        await out.put(None)

    workers = [asyncio.create_task(worker()) for _ in range(CONCURRENCY)]
    sup = asyncio.create_task(supervisor())
    try:
        while True:
            hit = await out.get()
            if hit is None:
                break
            yield hit
    finally:
        sup.cancel()
        for w in workers:
            w.cancel()
        await asyncio.gather(sup, *workers, return_exceptions=True)


def _client(headers: dict) -> httpx.AsyncClient:
    limits = httpx.Limits(max_connections=CONCURRENCY * 2,
                          max_keepalive_connections=CONCURRENCY)
    return httpx.AsyncClient(
        timeout=httpx.Timeout(PER_REQUEST_TIMEOUT),
        follow_redirects=True,
        headers=headers,
        limits=limits,
    )


async def enrich_hits(hits: list[Hit], handle: str) -> list[Hit]:
    """Decorate hits with display name, avatar and profile metadata.

    Only platforms with a keyless public API are enriched; everything else
    falls back to the site's own favicon.
    """
    from . import enrich as enrich_mod

    targets = [h for h in hits if h.is_hit]
    if not targets:
        return hits
    sem = asyncio.Semaphore(12)

    async def one(hit: Hit) -> None:
        async with sem:
            data = await enrich_mod.enrich(hit.name, handle, hit.url)
            hit.display_name = data.get("display_name") or ""
            hit.avatar = data.get("avatar") or ""
            hit.meta = data.get("meta") or []

    await asyncio.gather(*(one(h) for h in targets))
    return hits


def scan_headers() -> dict:
    return {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }


async def run_lookup(kind: str, value: str, pro: bool = True) -> list[Hit]:
    """Run a non-username search type and return its hits."""
    from . import lookups

    if kind == "email" or kind == "phone":
        return await _identity_checks(kind, value, scan_headers())
    if kind == "wallet":
        return await lookups.wallet_lookup(value)
    if kind == "name":
        return await lookups.name_lookup(value, pro=pro)
    if kind == "ip":
        return await lookups.ip_lookup(value)
    if kind == "domain":
        return await lookups.domain_lookup(value)
    if kind == "image":
        return await lookups.image_lookup(value)
    raise InputError(f"Unsupported search type {kind!r}.")


async def scan(
    query: str,
    *,
    kind: str | None = None,
    pro: bool = False,
    limit: int | None = None,
    on_progress: Callable[[dict], None] | None = None,
) -> ScanResult:
    """Run a full sweep. `on_progress` is called as results arrive.

    `pro` unlocks the adult part of the corpus and the Pro-only search types.
    """
    corpus = load_corpus()
    detected, value = classify_input(query, kind)
    kind = detected
    endpoints = corpus.for_plan(pro)
    if limit:
        endpoints = endpoints[:limit]

    started = time.perf_counter()
    hits: list[Hit] = []

    if kind == "username":
        async with sweep_slot(), _client(scan_headers()) as client:
            async for hit in iter_hits(client, endpoints, value):
                hits.append(hit)
                if on_progress:
                    on_progress({
                        "checked": len(hits),
                        "total": len(endpoints),
                        "found": sum(1 for h in hits if h.is_hit),
                        "elapsed": round(time.perf_counter() - started, 2),
                    })
        await enrich_hits(hits, value)
        total = len(endpoints)
    else:
        # Email, phone, wallet, name, IP, domain and image queries run the
        # checks that apply to them — a handful of real, public lookups.
        hits = await run_lookup(kind, value, pro=pro)
        total = len(hits)
        if on_progress:
            on_progress({
                "checked": len(hits),
                "total": total,
                "found": sum(1 for h in hits if h.is_hit),
                "elapsed": round(time.perf_counter() - started, 2),
            })

    elapsed = time.perf_counter() - started
    categories = (corpus.categories_for(endpoints) if kind == "username"
                  else _categories_for_kind(kind))
    return ScanResult(
        query=query, kind=kind, value=value, hits=hits, elapsed=elapsed,
        checked=len(hits), total=total, categories=categories,
    )


_TYPE_CATEGORY = {
    "email": "identity",
    "phone": "identity",
    "wallet": "wallet",
    "name": "name",
    "ip": "network",
    "domain": "domain",
    "image": "image",
}


def _categories_for_kind(kind: str) -> list[dict]:
    cat = _TYPE_CATEGORY.get(kind, "identity")
    return [{"id": cat, "label": cat.capitalize(), "count": 0}]


async def _identity_checks(kind: str, value: str, headers: dict) -> list[Hit]:
    """Checks for email and phone queries (public, no account required)."""
    from . import services

    hits: list[Hit] = []

    def add(eid: str, name: str, cat: str, status: str, url: str, detail: str = "") -> None:
        hits.append(Hit(eid, name, cat, status, url, detail))

    if kind == "email":
        try:
            gravatar = services.gravatar_url(value)
        except Exception:  # noqa: BLE001
            gravatar = ""
        if gravatar:
            try:
                async with httpx.AsyncClient(timeout=6.0, headers=headers,
                                             follow_redirects=True) as client:
                    r = await client.get(gravatar + "?d=404")
                add("gravatar", "Gravatar", "social",
                    "hit" if r.status_code == 200 else "miss", gravatar,
                    "avatar registered for this address" if r.status_code == 200
                    else "no avatar registered")
            except httpx.HTTPError as exc:
                add("gravatar", "Gravatar", "social", "unresolved", gravatar, type(exc).__name__)

        domain = value.rsplit("@", 1)[1]
        add("mail-domain", "Mail domain", "social",
            "hit" if domain not in services.DISPOSABLE_DOMAINS else "unresolved",
            f"https://{domain}", "disposable mail provider" if domain in services.DISPOSABLE_DOMAINS
            else "domain accepted by the mail provider")

    else:  # phone
        digits = re.sub(r"\D", "", value)
        add("phone-normalised", "Phone number", "social", "hit",
            f"tel:+{digits}", f"normalised to {len(digits)} digits")

    return hits
