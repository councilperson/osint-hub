# OSINT Hub

A self-hosted, **live** open-source-intelligence search engine: type a username
(or an email or phone number) and the app sweeps **773 public endpoints across
6 categories**, streaming each result back to the browser as the source
answers. Built with FastAPI + SQLite + Jinja2. No API keys, no accounts, no
telemetry, no platform logins.

## The rules

This toolbox is for **lawful, authorized research** — your own infrastructure,
consensual subjects, or engagements where you have permission. It deliberately
ships nothing that would dox a person: no people-search brokers, no address
aggregation, no location tracking, no logins into any platform. Every data
source used is public and free.

## The search engine

| Route | What it does |
|---|---|
| `/` | The live search console: dot-matrix hero, scan form, streaming sweep panel |
| `/api/scan/stream?q=<handle>` | Server-Sent Events stream: `start` → `result` × N → `done` |
| `/api/scan?q=<handle>` | The same sweep as a single JSON response |
| `/tools` | The seven focused lookup tools (see below) |

Every endpoint returns one of three honest answers:

| Class | Meaning |
|---|---|
| `hit` | the endpoint returned evidence that the handle exists |
| `miss` | the endpoint returned evidence that it does not exist |
| `unresolved` | the endpoint could not answer (bot-blocked, timed out, unclear) |

A site that hides its results behind a login wall or bot defense is **never**
reported as a false negative — it is marked `unresolved`, so the count of
"sites found" only ever means "sites that positively answered".

### Endpoint corpus

`data/endpoints.json` holds all 773 endpoints: name, category, URL template,
check method (`status_code` or `message`), the exact strings a source uses to
say *"no such account"*, and an optional API probe URL.

The catalogue is generated from [Maigret](https://github.com/soxoj/maigret)'s
community-maintained site list so that every URL and every absence marker is a
real, working definition rather than a guess:

```powershell
python scripts\build_corpus.py            # downloads the source list, rebuilds
python scripts\build_corpus.py --offline  # reuse scripts\maigret_data.json
```

The builder filters out adult, piracy and gambling destinations, prefers
sources with explicit absence markers, and pins well-known platforms to the
category people expect them in. Category sizes are fixed:

| Category | Endpoints |
|---|---|
| Social and messaging | 46 |
| Creator and media | 29 |
| Developer and tech | 31 |
| Gaming | 14 |
| Commerce and links | 33 |
| Long tail | 620 |
| **Total** | **773** |

## Tools

| Route | Tool | What it does | Source |
|---|---|---|---|
| `/tool/whois` | Domain ownership (RDAP) | Registrar, creation/expiry, nameservers, status, DNSSEC | rdap.org |
| `/tool/dns` | DNS records | A/AAAA/CNAME/MX/NS/TXT/SOA | Cloudflare DoH JSON API |
| `/tool/ip` | IP & network intelligence | Host resolution, geolocation, ISP/ASN, reverse DNS, hosting/proxy flags | ip-api.com + DoH |
| `/tool/headers` | HTTP headers & redirect chain | Follows redirects manually, inspects final headers, lists missing security headers | live fetch (headers only) |
| `/tool/username` | Username presence check | Public profile existence on 19 platforms: 3 result classes | public profile URLs & official JSON APIs |
| `/tool/email` | Email checks | Syntax, MX, disposable-domain flag, Gravatar existence | DoH, gravatar |
| `/tool/url` | URL analysis | URL anatomy, structural red flags (IP hosts, punycode, shorteners, userinfo, HTTP), redirect resolution | local parsing + live fetch |

Also: `/resources` (curated methodology links), `/notes` (pinned findings),
`/history` (re-run past queries), `/hibp` (breach checks).

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

43 tests covering routing, the DB layer, error rendering, pure logic, the
corpus shape, query normalisation, endpoint classification (hit / miss /
unresolved, timeouts, message markers), and the SSE event sequence. Every
outbound call is mocked.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `OSINT_DB` | `data/osint.db` | Where the SQLite file (history + notes) lives |
| `ADMIN_TOKEN` | `admin12345` | Token for `/admin` (hashed into an HttpOnly session cookie) |
| `SECRET_KEY` | `osint-hub-local-secret` | Cookie-signing secret; rotate together with the token |
| `HIBP_API_KEY` | *(none)* | Unlocks email-breach lookups on `/hibp` |
| `OSINT_CONCURRENCY` | `40` | Parallel endpoint checks (lower it on small hosts) |
| `OSINT_TIMEOUT` | `8.0` | Per-request timeout in seconds |

History is bounded to the 2000 most recent queries. Delete `data/osint.db` to
reset everything.

## Architecture

```
app/
  main.py       routes: landing page, /api/scan*, the toolbox, admin, notes
  scanner.py    the sweep engine — corpus, input parsing, worker pool
  stream.py     Server-Sent Events wrapper around the sweep
  services.py   the seven toolbox lookups (RDAP, DoH, ip-api, HIBP, …)
  db.py         SQLite: history, notes, licenses
  templates/    Jinja2 pages
  static/       style.css (design tokens) + app.js (dot matrix + live sweep)
data/
  endpoints.json  the 773-endpoint corpus
scripts/
  build_corpus.py  regenerates endpoints.json from the Maigret site list
```

The sweep uses a fixed pool of `OSINT_CONCURRENCY` workers feeding a queue.
Firing all 773 requests at once would starve the HTTP connection pool and
push most of them past their timeout; the pool keeps every slot busy and
finishes the full sweep in roughly 20 seconds.

## Honest limits

- **Username checks** verify public *existence* only. `hit` means a page
  exists — open the URL and confirm it. Many large platforms block automated
  requests and return `unresolved`; that is a true unknown, not a negative.
- **Email and phone** queries run the identity checks that apply to them
  (Gravatar, disposable-domain flags, number normalisation) rather than the
  full username sweep.
- **Email MX** proves the domain can receive mail, not that your exact mailbox
  does. SMTP probing is deliberately not implemented.
- **IP geolocation** is city/country-level approximate, sourced from
  ip-api.com's free tier, and its hosting/proxy flags are heuristics.
- **RDAP** coverage depends on each registry; some ccTLDs have no RDAP service.
- Results are **leads to verify**, not findings of fact.

## Outbound calls the app can make

- Every public profile URL in `data/endpoints.json` (GET only)
- `cloudflare-dns.com/dns-query` (DNS over HTTPS)
- `rdap.org/domain/…` (WHOIS over RDAP)
- `ip-api.com/json/…` (IP data)
- `haveibeenpwned.com/api/v3/…` + `api.pwnedpasswords.com/range/…`
- `public.api.bsky.app` (Bluesky handle resolution)
- `gravatar.com` (avatar existence)

Everything else stays on your machine.

## Legal note

Running lookups about third parties can still be unlawful depending on your
jurisdiction and purpose (harassment, discrimination, surveillance). This tool
provides access to public data; you are responsible for how you use it.

## Deploying on Render (free tier)

The repo ships a `Dockerfile` and `render.yaml` (`runtime: docker`, `plan: free`).
Render injects `$PORT`; the container binds `0.0.0.0:${PORT:-8077}` and HTTPS is
provided by Render, so no nginx/certbot is needed.

Env vars: `ADMIN_TOKEN`, `SECRET_KEY`, `OWNER_EMAIL`, `OWNER_PASSWORD`,
optional `HIBP_API_KEY`. The admin console lives at
`/hq-<first 10 hex of sha256(ADMIN_TOKEN)>` unless `ADMIN_PATH` is set.

### Keeping the database across redeploys

Render's free disk is wiped on every deploy/restart. `app/backup.py` keeps the
SQLite DB off-box on GitHub, for free:

* on startup, if the local DB is missing it is restored from GitHub;
* every `BACKUP_INTERVAL` seconds (default 300) a consistent snapshot
  (sqlite3 backup API, gzip + base64) is pushed if anything changed;
* one final push runs on shutdown (Render sends SIGTERM before a redeploy).

Set `BACKUP_GITHUB_TOKEN` plus one of:

* `BACKUP_GITHUB_REPO=owner/name` - a **private** repo (recommended). Token:
  fine-grained, that repo only, *Contents: Read and write*.
* `BACKUP_GIST_ID=<id>` - a secret gist. Token: fine-grained with
  *Gists: Read and write* (or classic with `gist` scope). Secret gists are
  unlisted, not private: anyone with the URL can read them.

With none set, backup is a silent no-op. Data written in the last few minutes
before a hard crash can be lost; normal redeploys are covered by the shutdown push.
