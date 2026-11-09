# OSINT Hub

A self-hosted open-source-intelligence (OSINT) toolbox: seven lookup tools over
**free public sources**, a curated resource library, local query history, and a
case-note pad. Built with FastAPI + SQLite + Jinja2. No API keys, no accounts,
no telemetry.

## The rules

This toolbox is for **lawful, authorized research** — your own infrastructure,
consensual subjects, or engagements where you have permission. It deliberately
ships nothing that would dox a person: no people-search brokers, no address
aggregation, no location tracking, no logins into any platform. Every data
source used is public and free.

## Tools

| Route | Tool | What it does | Source |
|---|---|---|---|
| `/tool/whois` | Domain ownership (RDAP) | Registrar, creation/expiry, nameservers, status, DNSSEC | rdap.org |
| `/tool/dns` | DNS records | A/AAAA/CNAME/MX/NS/TXT/SOA | Cloudflare DoH JSON API |
| `/tool/ip` | IP & network intelligence | Host resolution, geolocation, ISP/ASN, reverse DNS, hosting/proxy flags | ip-api.com + DoH |
| `/tool/headers` | HTTP headers & redirect chain | Follows redirects manually, inspects final headers, lists missing security headers | live fetch (headers only) |
| `/tool/username` | Username presence check | Public profile existence on 19 platforms: 3 result classes (found? / gone / inconclusive) | public profile URLs & official JSON APIs |
| `/tool/email` | Email checks | Syntax, MX, disposable-domain flag, Gravatar existence | DoH, gravatar |
| `/tool/url` | URL analysis | URL anatomy, structural red flags (IP hosts, punycode, shorteners, userinfo, HTTP), redirect resolution | local parsing + live fetch |

Also: `/resources` (curated methodology links: OSINT Framework, Bellingcat,
Shodan, VirusTotal, HIBP…), `/notes` (pinned findings), `/history` (re-run past
queries).

## Run it

```powershell
cd osint-hub
python -m pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Open http://127.0.0.1:8000

## Tests (offline, no network needed)

```powershell
python -m pytest tests -q
```

Tests mock all outbound calls; they cover routing, DB history/notes, error
rendering, and pure logic (domain cleaning, status interpretation, TLD
handling, disposable lists).

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `OSINT_DB` | `data/osint.db` | Where the SQLite file (history + notes) lives |
| `ADMIN_TOKEN` | `admin12345` | Token for `/admin` (hashed into an HttpOnly session cookie) |
| `SECRET_KEY` | `osint-hub-local-secret` | Cookie-signing secret; rotate together with the token |
| `HIBP_API_KEY` | *(none)* | Unlocks email-breach lookups on `/hibp` (see below) |

History is bounded to the 2000 most recent queries. Delete `data/osint.db` to
reset everything.

## Pwned checks (`/hibp`)

Not affiliated with Have I Been Pwned — data from their official API. Three tiers:

1. **Breach catalog** (free, no key): every breach HIBP has indexed, searchable,
   with per-breach detail (accounts pwned, data classes, description). Cached 10 min.
2. **Pwned-password check** (free, no key): k-anonymity against 600M+ leaked
   passwords via `api.pwnedpasswords.com/range`. Only the first 5 characters of
   the SHA-1 hash leave the machine; passwords are never stored or logged.
3. **Email breach lookup** (optional): requires an HIBP API key from
   haveibeenpwned.com/API/Key (email search tier, ≈$3.50/mo). Set `HIBP_API_KEY`
   and restart; the form unlocks automatically.

## Admin panel (`/admin`)

Token-gated local console for the database: usage stats (lookups, unique
targets, notes, tools used), per-row delete, clear history / clear notes, and
integration status. Change the token with `ADMIN_TOKEN`; the UI warns while the
default is in place. Login is HMAC-verified with a 0.6 s delay on bad attempts.

## Honest limits (also shown in the UI)

- **Username checks** check public *existence* only; `found?` means a page
  exists — open the URL and verify. Platforms that hide results behind login
  walls or bot defenses return `inconclusive`, never false negatives.
- **Email MX** proves the domain can receive mail, not that your exact mailbox
  does. SMTP probing is deliberately not implemented. For breach data use the
  official [haveibeenpwned.com](https://haveibeenpwned.com) check.
- **IP geolocation** is city/country-level approximate, sourced from ip-api.com's
  free tier (45 req/min), and its hosting/proxy flags are heuristics.
- **RDAP** coverage depends on each registry; some ccTLDs have no RDAP service.

## Outbound calls the app can make

- `cloudflare-dns.com/dns-query` (DNS over HTTPS)
- `rdap.org/domain/…` (WHOIS over RDAP)
- `ip-api.com/json/…` (IP data)
- `haveibeenpwned.com/api/v3/…` + `api.pwnedpasswords.com/range/…` (pwned checks)
- `public.api.bsky.app` (Bluesky handle resolution — official API)
- `gravatar.com` (avatar existence)
- Public profile URLs on the 19 username-check platforms (GET only)

Everything else stays on your machine.

## Legal note

Running lookups about third parties can still be unlawful depending on your
jurisdiction and purpose (harassment, discrimination, surveillance). This tool
provides access to public data; you are responsible for how you use it.
