# OSINT Hub: review and fix pass (12 Nov 2026)

A backup of the folder from before these changes is at
`..\osint-hub-backup-20261112-1758.zip`. Tests: 82 before, 120 after
(82 original + 7 backup + 31 new regression tests). All of them pass.

## Security
- **Anyone could turn on Pro for the whole site.** `POST /pro/purchase` and
  `/pro/deactivate` had no login check. Only the admin can use them now.
- **Anyone could take over the owner account.** If `OWNER_PASSWORD` wasn't set,
  signing up with the owner email gave you the owner panel. Now there is no
  owner panel without `OWNER_PASSWORD`, and at boot the env password replaces
  any password someone else set on that account.
- **Order pages could be read by changing the number in the URL.** Each order
  link now carries a signed key (`?k=`). The buyer, the owner and the admin
  can still open it.
- **A TXID could overwrite an order that was already approved or rejected.**
  You can only submit a TXID while the order is pending.
- **Approving an order twice granted credits twice.** It now applies once.
- **Reseller sub-accounts printed free credits.** Their scans are now paid from
  the owner's balance, with the sub-account limit as a cap. Their per-minute
  rate limit is enforced, and the owner must still be on a paid plan.
- **Free users could run Pro search types.** If you left the type out (an IP
  address, for example), the type was auto-detected and skipped the Pro
  check. The check now runs after detection.
- **SSRF.** The headers/redirect tool and monitor webhooks could be pointed at
  internal addresses (127.0.0.1, 169.254.169.254 and so on). Every hop is now
  checked. Webhooks must be https, and Discord webhooks must be real
  discord.com webhook URLs.
- **CSRF.** Form posts from another site are refused (Origin/Referer check).
  Cookies are HttpOnly and SameSite=Lax, plus Secure when served over HTTPS.
- **Brute force.** Login, signup, admin login, checkout, the tools and the API
  now have rate limits. The admin login delay no longer blocks the server.
- **Default secrets on Render.** On Render, the admin console stays off until
  `ADMIN_TOKEN` is set to 12 or more characters. The log warns about any
  secret left on its default.
- **XSS.** Links and images that come from scan results go through a
  safe-URL filter (no `javascript:` links), both in the templates and in
  app.js.
- Notes and search history were shared by every visitor. They now belong to
  each account.
- Safer redirects after login (no `//evil.com` or backslash tricks).
- Security headers (nosniff, frame deny, referrer policy, HSTS on HTTPS). The
  public `/openapi.json` is turned off.
- Password hashes are upgraded automatically on login, and absurd hash
  parameters are rejected. Changing your password signs out your other
  sessions.

## Bugs
- The owner got another 2,000 credits on every restart or redeploy. The grant
  now happens only once (tracked in the ledger).
- Credits were checked first and taken later, so two quick requests could
  overspend. Spending is now one atomic step, and the balance never goes
  below 0. A search that fails refunds its credits. Bulk runs charge up front
  and refund the items that fail.
- `type(exc)` crashed because a route parameter called `type` replaced the
  built-in (scan, API and reseller routes).
- `HTTPException` wasn't imported in main.py.
- The owner panel forms posted to `/admin/...` routes that don't exist (404).
  They now post to `/account/owner/...`.
- Admin form actions were relative and broke after the first click. Every
  admin action now redirects back to the console.
- Monitors: the webhook config key didn't match (alerts never fired), the
  config was JSON-parsed twice (crash), "last run" was always blank, and
  hits weren't stored properly. Email alerts are escaped and sent off the
  event loop.
- pro_reports.py was missing an import (crash on custom templates), had dead
  duplicate routes, and used the raw query as the download filename (header
  injection risk).
- The reseller pages read `.key`, which doesn't exist (it's `api_key`).
- The case limit for each plan wasn't enforced. Users are capped at 10 API
  keys and 25 monitors.
- Bad JSON in a database column no longer crashes a page.

## Reliability (512 MB free instance)
- SQLite runs in WAL mode with a busy timeout. Connections always close and
  roll back on errors. Indexes were added for the hot queries.
- At most `OSINT_MAX_SCANS` (default 3) full sweeps run at once. The rest
  wait instead of exhausting memory.
- Blocking lookups (tools, HIBP, crypto rates, SMTP) run in a thread pool, so
  one slow site can't freeze the server.
- `last_seen` is written at most once a minute per user, not on every request.
- Static files skip the session and database lookup.
- Off-box backups of the database to GitHub (`app/backup.py`), because
  Render's free disk is wiped on every deploy. Restore runs at boot, then a
  push every `BACKUP_INTERVAL` seconds.
- Added a Dockerfile, a .dockerignore and a .gitignore. render.yaml uses the
  Docker runtime.

## Quality / UX
- Friendlier error messages. Internal errors aren't shown to users.
- Notes and history ask visitors to sign in instead of showing other people's
  data.
- Accessibility: form labels, focus outlines, screen-reader text, and tables
  that scroll on mobile.
- Cache-busted `app.js` / `style.css` (`?v=11`).
- Removed unused imports. Updated the README (configuration, Render deploy).

## New env vars
- `OSINT_MAX_SCANS` (default 3)
- `MONITOR_RUNNER_SECRET` (optional, for an external cron)
- `OSINT_PUBLIC` (optional)
- `BACKUP_*` (optional)

All the existing names are unchanged.

## UI
- Account page: Scan history and the Owner console (all accounts, crypto
  orders, and all scans) now use card boxes instead of wide table rows.
  API keys, the credit ledger, cloud cases, and the password form are
  unchanged.

## Bugs (follow-up)
- Crypto payment QR codes were often unscannable. The format-information
  copy beside the top-right finder was shifted by one module and overwrote
  the mandatory dark module, so wallet apps could not read them. The QR now
  also encodes a BIP-21 / EIP-681 payment URI with the amount when the rate
  is known (BTC, ETH, SOL, TRX). Payout addresses are unchanged.

## Known, not changed
- API keys are stored in plain text, so existing keys keep working. Hashing
  them would mean reissuing every key.
- The SSRF check resolves DNS before the request is made, so a DNS-rebinding
  race is still possible in theory. Low risk on Render.
- Rate limits are in memory and reset on restart. That's fine for a single
  instance.
- `scripts/_*.py` are one-off probe scripts. They're unused by the app but
  were left in place.

## Fixes, round 3 (Nov 12, 2026, evening)

### Monitors and Reports showed "Internal Server Error"
- The cause was the upload to GitHub, not the code. GitHub main (the commit
  Render deploys) was missing four page templates: `monitors.html`,
  `monitor_detail.html`, `reports.html` and `reseller_account_detail.html`.
  When the server couldn't find the page file it crashed with a 500. GitHub
  also had old copies of `bulk.html`, `order.html` (missing the order-key field
  on the "I have sent the payment" form) and `pro.html` (the old "Checkout,
  honestly" demo text).
- The code on this PC was already correct. The fix is to upload the whole
  folder so GitHub matches it.
- New `scripts/verify_deploy.py` compares this folder with GitHub file by
  file and lists anything missing or different. Run
  `python scripts/verify_deploy.py councilperson/osint-hub main` after an
  upload. It should print `OK`.
- New `tests/test_pages.py`:
  - checks that every template the app uses exists, so a missing page file
    now fails the tests;
  - opens every page in the app as a free user, a Pro user, a Team user, the
    owner and the admin console, with sample data (scans, cases, monitors
    with runs and hits, report templates, orders, reseller sub-accounts)
    loaded, and fails if any page gives a server error;
  - creates a monitor and generates a PDF report.

### Crypto QR codes still didn't scan
- The QR encoder we wrote ourselves was still broken. Its own self-test
  could read its codes back, but real scanners (zxing and OpenCV) couldn't
  read any of them. It has been replaced with `segno`, a standard,
  pure-Python QR library (added to `requirements.txt`; no system packages
  needed, so the Docker build is unchanged).
- The QR now holds only the plain wallet address, like the receive screen in
  Exodus. Payment links (`bitcoin:…?amount=`, `ethereum:…@1?value=`) are
  gone, because many wallets and exchanges reject them. The amount to send is
  still shown in large text above the code, and there's a short note under
  the code.
- The code is black on white with the standard 4-module white border. It's
  slightly bigger (260 px) and scales cleanly (the SVG now has a viewBox),
  with no filters or recolouring. The stylesheet version was bumped
  (`style.css?v=12`) so browsers load the new CSS.
- Checked by decoding the real order page in headless Chrome (desktop and a
  phone-sized screen, dark mode) with two different decoders. BTC, ETH, SOL
  and TRX each decode to exactly the payout address. Payout addresses are
  unchanged.
- New tests decode the QR on the order page for every coin with a real
  decoder (zxing-cpp, listed in `requirements-dev.txt`). They're skipped
  automatically if it isn't installed. `scripts/_probe_qr.py` does the same
  check from the command line.
