"""Monitoring & Alerts runner.

Triggered by an external scheduler (cron job, GitHub Action, uptime pinger)
calling ``POST /internal/run-monitors`` with the ``X-Internal-Secret`` header.
For each enabled monitor that is due according to its frequency:

  1. checks the owner still has a paid plan and charges the search's credits
  2. runs the scan for the monitor's search type
  3. diffs the hits against the previous successful run
  4. notifies about NEW hits on the configured channel
  5. records the run and the new hits

Channels:
  - email:   SMTP (SMTP_HOST / SMTP_PORT / SMTP_USER / SMTP_PASS / SMTP_FROM)
  - webhook: POSTs JSON to a public http(s) URL
  - discord: posts to a discord.com webhook URL
"""
from __future__ import annotations

import asyncio
import html
import logging
import os
import smtplib
import time
import urllib.parse
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import httpx

from . import auth, db, plans, scanner, services

log = logging.getLogger("osint.monitor")

FREQUENCIES = {"hourly": 3600, "daily": 86400, "weekly": 7 * 86400}
CHANNELS = ("email", "webhook", "discord")
MAX_MONITORS_PER_USER = 25
# A little slack so a daily cron that fires a few minutes early still runs.
_DUE_SLACK = 300


def webhook_url(channel: str, config: dict) -> str:
    """The configured destination URL (accepts both key spellings)."""
    if channel == "webhook":
        return str(config.get("webhook_url") or config.get("url") or "").strip()
    if channel == "discord":
        return str(config.get("discord_webhook_url") or config.get("webhook_url") or "").strip()
    return ""


def validate_destination(channel: str, config: dict) -> str | None:
    """Return an error message when the channel config is unusable or unsafe."""
    if channel not in CHANNELS:
        return "Pick email, webhook or Discord as the notification channel."
    if channel == "email":
        return None
    url = webhook_url(channel, config)
    if not url:
        return ("Add a webhook URL in the channel config, e.g. "
                '{"webhook_url": "https://example.com/hook"}.' if channel == "webhook" else
                "Add your Discord webhook in the channel config, e.g. "
                '{"discord_webhook_url": "https://discord.com/api/webhooks/..."}.')
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https":
        return "Webhook URLs must start with https://."
    if channel == "discord":
        host = (parts.hostname or "").lower()
        if host not in ("discord.com", "discordapp.com", "ptb.discord.com",
                        "canary.discord.com") or not parts.path.startswith("/api/webhooks/"):
            return "That is not a Discord webhook URL (https://discord.com/api/webhooks/...)."
    try:
        services.assert_public_url(url)
    except services.LookupError as exc:
        return f"Webhook URL rejected: {exc}"
    return None


def is_due(monitor: dict, now: float | None = None) -> bool:
    now = now or time.time()
    last = monitor.get("last_run") or 0
    period = FREQUENCIES.get(monitor.get("frequency") or "daily", 86400)
    return now - float(last) >= period - _DUE_SLACK


async def run_all_monitors(force: bool = False) -> dict:
    """Run every enabled monitor that is due. Returns summary stats."""
    results = {"checked": 0, "skipped": 0, "triggered": 0, "notifications": 0, "errors": 0}
    for m in db.list_enabled_monitors():
        if not force and not is_due(m):
            results["skipped"] += 1
            continue
        try:
            result = await run_monitor(m)
            if result.get("skipped"):
                results["skipped"] += 1
                continue
            results["checked"] += 1
            if result["new_hits"] > 0:
                results["triggered"] += 1
                results["notifications"] += result["notifications_sent"]
        except Exception as e:  # noqa: BLE001 — one bad monitor must not stop the rest
            results["errors"] += 1
            log.warning("monitor %s failed: %s", m.get("id"), e)
    return results


def _skip(monitor_id: int, reason: str) -> dict:
    db.create_monitor_run(monitor_id, 0, 0, 0.0, reason)
    db.mark_monitor_run(monitor_id, 0)
    return {"monitor_id": monitor_id, "skipped": True, "reason": reason}


async def run_monitor(monitor: dict) -> dict:
    """Run a single monitor. Returns run results."""
    monitor_id = monitor["id"]
    kind = monitor["kind"]
    target = monitor["target"]
    channel = monitor["channel"]
    channel_config = db._json_obj(monitor.get("channel_config"))

    owner = db.get_user(monitor["user_id"])
    if not owner or not auth.is_pro(owner):
        return _skip(monitor_id, "skipped: monitors need an active Pro or Team plan")
    cost = plans.type_cost(kind)
    if db.try_spend_credits(owner["id"], cost, f"monitor {kind} run",
                            f"monitor:{monitor_id}") is None:
        return _skip(monitor_id, f"skipped: not enough credits ({cost} needed)")

    started = time.perf_counter()
    previous_hits = _get_previous_hits(monitor_id)
    new_hits: list[dict] = []

    try:
        if kind == "username":
            result = await scanner.scan(target, kind="username", pro=True)
            hits = [h for h in result.hits if h.is_hit]
            total_checked = result.checked
        else:
            _, value = scanner.classify_input(target, kind)
            all_hits = await scanner.run_lookup(kind, value, pro=True)
            hits = [h for h in all_hits if h.is_hit]
            total_checked = len(all_hits)
    except Exception as e:  # noqa: BLE001
        elapsed = time.perf_counter() - started
        db.adjust_credits(owner["id"], cost, "monitor run refund (failed)",
                          f"monitor:{monitor_id}")
        db.create_monitor_run(monitor_id, 0, 0, elapsed, f"{type(e).__name__}: {e}"[:500])
        db.mark_monitor_run(monitor_id, 0)
        raise

    prev_set = {(h["endpoint_id"], h["url"]) for h in previous_hits}
    for h in hits:
        if (h.endpoint_id, h.url) not in prev_set:
            new_hits.append({
                "id": h.endpoint_id,
                "endpoint_id": h.endpoint_id,
                "name": h.name,
                "category": h.category,
                "url": h.url,
                "detail": h.detail,
                "display_name": h.display_name,
                "avatar": h.avatar,
                "meta": h.meta,
            })

    elapsed = time.perf_counter() - started
    run_id = db.create_monitor_run(monitor_id, len(hits), total_checked, elapsed, "")
    # store every current hit so the next run diffs against the full picture
    db.add_monitor_hits(run_id, monitor_id, [
        {"id": h.endpoint_id, "name": h.name, "category": h.category, "url": h.url,
         "detail": h.detail, "display_name": h.display_name, "avatar": h.avatar,
         "meta": h.meta}
        for h in hits])
    db.mark_monitor_run(monitor_id, len(hits))

    notifications_sent = 0
    if new_hits:
        notifications_sent = await _send_notifications(
            monitor, owner, new_hits, channel, channel_config)

    return {
        "monitor_id": monitor_id,
        "total_checked": total_checked,
        "hits_found": len(hits),
        "new_hits": len(new_hits),
        "notifications_sent": notifications_sent,
        "elapsed": round(elapsed, 2),
    }


def _get_previous_hits(monitor_id: int) -> list[dict]:
    """Hits from the most recent successful run."""
    with db._conn() as conn:
        run_row = conn.execute(
            "SELECT id FROM monitor_runs WHERE monitor_id = ? AND (error = '' OR error IS NULL) "
            "ORDER BY created_at DESC LIMIT 1", (monitor_id,)).fetchone()
        if not run_row:
            return []
        rows = conn.execute(
            "SELECT endpoint_id, url FROM monitor_hits WHERE run_id = ?",
            (run_row["id"],)).fetchall()
    return [dict(r) for r in rows]


async def _send_notifications(monitor: dict, owner: dict, new_hits: list[dict],
                              channel: str, config: dict) -> int:
    if channel == "email":
        return await asyncio.to_thread(_send_email, owner["email"], monitor, new_hits)
    if channel in ("webhook", "discord"):
        url = webhook_url(channel, config)
        if validate_destination(channel, config):
            return 0
        if channel == "webhook":
            payload = {
                "monitor": {"id": monitor["id"], "kind": monitor["kind"],
                            "target": monitor["target"]},
                "hits": new_hits,
                "count": len(new_hits),
                "timestamp": time.time(),
            }
        else:
            payload = {"username": "OSINT Hub Alerts", "embeds": [
                {
                    "title": str(h["name"])[:250],
                    "url": h["url"] if str(h["url"]).startswith(("http://", "https://")) else None,
                    "color": 5814783,
                    "fields": [
                        {"name": "Category", "value": str(h["category"])[:1000] or "—", "inline": True},
                        {"name": "Detail", "value": str(h["detail"] or "—")[:1000], "inline": True},
                    ],
                    "footer": {"text": f"OSINT Hub • {monitor['kind']} monitor"},
                }
                for h in new_hits[:10]  # Discord allows 10 embeds per message
            ]}
        return await _post_json(url, payload)
    return 0


async def _post_json(url: str, payload: dict) -> int:
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            r = await client.post(url, json=payload)
            r.raise_for_status()
        return 1
    except httpx.HTTPError as exc:
        log.warning("webhook delivery failed: %s", exc)
        return 0


def _send_email(to_email: str, monitor: dict, hits: list[dict]) -> int:
    """Blocking SMTP send — always called in a worker thread."""
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = int(os.environ.get("SMTP_PORT", "587") or 587)
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")
    from_email = os.environ.get("SMTP_FROM", "alerts@osint-hub.local")
    if not all([smtp_host, smtp_user, smtp_pass]):
        return 0

    e = html.escape
    rows = "".join(
        f'<tr><td style="padding:8px;border-bottom:1px solid #eee;"><strong>{e(str(h["name"]))}</strong></td>'
        f'<td style="padding:8px;border-bottom:1px solid #eee;">{e(str(h["category"]))}</td>'
        f'<td style="padding:8px;border-bottom:1px solid #eee;">'
        + (f'<a href="{e(str(h["url"]))}">View</a>' if str(h["url"]).startswith(("http://", "https://")) else "")
        + f'</td><td style="padding:8px;border-bottom:1px solid #eee;">{e(str(h["detail"] or ""))}</td></tr>'
        for h in hits)
    body = f"""<html><body style="font-family:Arial,sans-serif;color:#333;">
<h2>New OSINT matches found</h2>
<p><strong>Monitor:</strong> {e(monitor['kind'])} — {e(monitor['target'])}</p>
<p><strong>Frequency:</strong> {e(monitor['frequency'])}</p>
<p><strong>New matches:</strong> {len(hits)}</p>
<table style="border-collapse:collapse;width:100%;max-width:800px;">
<thead><tr style="background:#f5f5f5;"><th align="left">Name</th><th align="left">Category</th>
<th align="left">Profile</th><th align="left">Detail</th></tr></thead>{rows}</table>
<p style="margin-top:20px;color:#888;font-size:12px;">You received this because you set up a monitor at OSINT Hub.</p>
</body></html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"OSINT alert: {len(hits)} new match(es) for {monitor['target']}"[:200]
    msg["From"] = from_email
    msg["To"] = to_email
    msg.attach(MIMEText(body, "html"))
    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        return 1
    except (OSError, smtplib.SMTPException) as exc:
        log.warning("alert email failed: %s", exc)
        return 0
