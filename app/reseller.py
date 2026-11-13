"""White-Label API Reseller endpoints.

Pro/Team users create sub-accounts with their own API keys. Every scan a
sub-account runs is paid from the owner's credit balance; the sub-account's
``credits_limit`` is a spending cap on top of that, never a source of free
credits. ``rate_limit`` (requests per minute) is enforced per sub-account.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from . import auth, db, plans, scanner, security

router = APIRouter(prefix="/reseller", tags=["reseller"])

# set by main.py so this module never imports main (no circular import)
templates = None
_admin_ctx_fn = None
_is_admin_fn = None

MAX_CREDITS_LIMIT = 100_000
MAX_RATE_LIMIT = 1_000
_rate = security.RateLimiter(limit=60, window=60.0)


def set_templates(t, admin_ctx=None, is_admin=None) -> None:
    global templates, _admin_ctx_fn, _is_admin_fn
    templates = t
    _admin_ctx_fn = admin_ctx
    _is_admin_fn = is_admin


def _clamp(value: int, low: int, high: int) -> int:
    try:
        return max(low, min(high, int(value)))
    except (TypeError, ValueError):
        return low


def _wants_json(request: Request) -> bool:
    return "application/json" in request.headers.get("accept", "")


def _owner_or_redirect(request: Request):
    """The signed-in Pro/Team user, or a redirect for the browser."""
    user = request.state.user
    if not user:
        target = request.url.path
        return None, RedirectResponse(f"/login?next={target}", status_code=303)
    if not auth.is_pro(user):
        return None, RedirectResponse("/pricing", status_code=303)
    return user, None


def _auth_ctx(request: Request, **extra) -> dict:
    user = request.state.user
    ctx = {
        "user": user,
        "plan": auth.effective_plan(user),
        "plan_info": auth.plan_of(user),
        "credits": auth.credits_of(user),
        "pro": auth.is_pro(user),
    }
    ctx.update(extra)
    return ctx


def _branding_from_form(form) -> dict:
    out = {}
    for key in ("logo_url", "primary_color", "company_name", "footer_text"):
        val = form.get(f"branding[{key}]")
        if val is not None:
            out[key] = str(val).strip()[:300]
    if out.get("logo_url") and not out["logo_url"].startswith("https://"):
        out["logo_url"] = ""
    return out


# --- Sub-account management (browser) ---

@router.get("/accounts", response_class=HTMLResponse)
async def reseller_accounts_page(request: Request):
    user, redirect = _owner_or_redirect(request)
    if redirect:
        return redirect
    return templates.TemplateResponse(request, "reseller_accounts.html", _auth_ctx(
        request, accounts=db.list_sub_accounts(user["id"])))


@router.post("/accounts")
async def reseller_create_account(request: Request,
                                  name: str = Form(""),
                                  credits_limit: int = Form(1000),
                                  rate_limit: int = Form(60)):
    user, redirect = _owner_or_redirect(request)
    if redirect:
        return redirect
    name = name.strip()
    if not name:
        if _wants_json(request):
            raise HTTPException(400, "Name required")
        return templates.TemplateResponse(request, "reseller_accounts.html", _auth_ctx(
            request, accounts=db.list_sub_accounts(user["id"]),
            error="Give the sub-account a name."), status_code=400)
    account = db.create_sub_account(
        user["id"], name,
        credits_limit=_clamp(credits_limit, 0, MAX_CREDITS_LIMIT),
        rate_limit=_clamp(rate_limit, 1, MAX_RATE_LIMIT))
    if _wants_json(request):
        return JSONResponse({"id": account["id"], "key": account["key"], "name": account["name"]})
    return RedirectResponse(f"/reseller/accounts/{account['id']}", status_code=303)


@router.get("/accounts/{sub_id}", response_class=HTMLResponse)
async def reseller_account_detail(request: Request, sub_id: int):
    user, redirect = _owner_or_redirect(request)
    if redirect:
        return redirect
    account = db.get_sub_account(sub_id, user["id"])
    if not account:
        raise HTTPException(404, "Sub-account not found")
    return templates.TemplateResponse(request, "reseller_account_detail.html", _auth_ctx(
        request, account=account, usage=db.get_sub_account_usage(sub_id)))


@router.post("/accounts/{sub_id}")
async def reseller_update_account(request: Request, sub_id: int,
                                  name: str = Form(...),
                                  credits_limit: int = Form(...),
                                  rate_limit: int = Form(...),
                                  active: int = Form(...)):
    user, redirect = _owner_or_redirect(request)
    if redirect:
        return redirect
    account = db.get_sub_account(sub_id, user["id"])
    if not account:
        raise HTTPException(404, "Sub-account not found")
    fields = dict(name=(name.strip() or account["name"])[:100],
                  credits_limit=_clamp(credits_limit, 0, MAX_CREDITS_LIMIT),
                  rate_limit=_clamp(rate_limit, 1, MAX_RATE_LIMIT),
                  active=1 if active else 0)
    branding = _branding_from_form(await request.form())
    if branding:
        fields["branding"] = {**(account.get("branding") or {}), **branding}
    db.update_sub_account(sub_id, user["id"], **fields)
    if _wants_json(request):
        return JSONResponse({"ok": True})
    return RedirectResponse(f"/reseller/accounts/{sub_id}", status_code=303)


@router.post("/accounts/{sub_id}/delete")
async def reseller_delete_account(request: Request, sub_id: int):
    user, redirect = _owner_or_redirect(request)
    if redirect:
        return redirect
    db.delete_sub_account(sub_id, user["id"])
    if _wants_json(request):
        return JSONResponse({"ok": True})
    return RedirectResponse("/reseller/accounts", status_code=303)


# --- Sub-account API (for the white-label consumers) ---

def _sub_account_user(request: Request) -> dict:
    """Authenticate a sub-account via X-API-Key."""
    key = request.headers.get("x-api-key", "").strip()
    if not key or not key.startswith("osh_") or len(key) > 128:
        raise HTTPException(401, "Invalid API key")
    row = db.get_sub_account_by_key(key)
    if not row:
        raise HTTPException(401, "Invalid or disabled API key")
    return row


@router.get("/api/v1/me")
async def reseller_api_me(sub_acc: dict = Depends(_sub_account_user)):
    return {
        "name": sub_acc["name"],
        "credits_limit": sub_acc["credits_limit"],
        "credits_used": sub_acc["credits_used"],
        "credits_remaining": max(0, sub_acc["credits_limit"] - sub_acc["credits_used"]),
        "rate_limit": sub_acc["rate_limit"],
    }


@router.get("/api/v1/scan")
async def reseller_api_scan(request: Request, q: str = "", type: str = "",
                            sub_acc: dict = Depends(_sub_account_user)):
    """White-label scan endpoint for sub-accounts (paid from the owner's credits)."""
    if not _rate.hit(f"sub:{sub_acc['id']}", limit=int(sub_acc["rate_limit"] or 60)):
        raise HTTPException(429, "Rate limit exceeded — slow down and retry in a minute")
    query = q.strip()
    if not query:
        raise HTTPException(400, "Missing query parameter 'q'")
    kind = (type or "").strip().lower() or None
    if kind and kind not in plans.SEARCH_TYPE_IDS:
        raise HTTPException(400, f"Unknown search type {kind!r}")
    try:
        kind, _ = scanner.classify_input(query, kind)
    except scanner.InputError as e:
        raise HTTPException(400, str(e)) from None

    owner = db.get_user(sub_acc["owner_id"])
    if not owner or not auth.is_pro(owner):
        raise HTTPException(403, "The account that issued this key no longer has a paid plan")

    cost = plans.type_cost(kind)
    if not db.try_use_sub_account_credits(sub_acc["id"], cost):
        remaining = max(0, sub_acc["credits_limit"] - sub_acc["credits_used"])
        raise HTTPException(402, f"Insufficient credits: {cost} required, {remaining} available")
    ref = f"sub:{sub_acc['id']}"
    if db.try_spend_credits(owner["id"], cost, f"reseller {kind} search", ref) is None:
        db.release_sub_account_credits(sub_acc["id"], cost)
        raise HTTPException(402, "The issuing account is out of credits")

    try:
        result = await scanner.scan(query, kind=kind, pro=True)
    except Exception as e:  # noqa: BLE001
        db.release_sub_account_credits(sub_acc["id"], cost)
        db.adjust_credits(owner["id"], cost, "reseller search refund (failed)", ref)
        status = 400 if isinstance(e, scanner.InputError) else 502
        detail = str(e) if status == 400 else "The search failed upstream — no credits were charged."
        raise HTTPException(status, detail) from None

    import time as _time
    now = _time.time()
    db.record_sub_account_usage(sub_acc["id"], cost, 1, now - 86400, now)
    fresh = db.get_sub_account(sub_acc["id"], owner["id"]) or sub_acc
    return {
        "query": result.query,
        "kind": result.kind,
        "value": result.value,
        "found": result.found,
        "checked": result.checked,
        "total": result.total,
        "elapsed": round(result.elapsed, 2),
        "credits_remaining": max(0, fresh["credits_limit"] - fresh["credits_used"]),
        "results": [
            {
                "id": h.endpoint_id, "name": h.name, "category": h.category,
                "status": h.status, "url": h.url, "detail": h.detail, "ms": h.ms,
                "display_name": h.display_name, "avatar": h.avatar, "meta": h.meta,
            }
            for h in result.hits
        ],
    }


# --- Admin: every sub-account ---

@router.get("/admin/accounts")
async def admin_all_sub_accounts(request: Request):
    if not (_is_admin_fn and _is_admin_fn(request)):
        return templates.TemplateResponse(request, "admin.html",
                                          _admin_ctx_fn(request, login_error=True))
    return templates.TemplateResponse(request, "reseller_admin_accounts.html", _admin_ctx_fn(
        request, accounts=db.list_all_sub_accounts()))


reseller_router = router
