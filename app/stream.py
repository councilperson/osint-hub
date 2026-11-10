"""Server-Sent Events endpoint for live scans.

The browser opens `/api/scan/stream?q=<query>&type=<kind>` and receives:
  event: start    -> the scan began, with the endpoint total
  event: result   -> one check resolved (hit / miss / unresolved)
  event: enrich   -> a hit gained a display name, avatar and metadata
  event: done     -> the sweep finished, with totals

Keeping the stream on the server (rather than polling) is what makes the
results appear live, exactly as they resolve.
"""
from __future__ import annotations

import json
import time
from typing import AsyncIterator

from fastapi import Request
from fastapi.responses import StreamingResponse

from . import auth, db, scanner


def _sse(event: str, data: dict) -> str:
    payload = json.dumps(data, ensure_ascii=False)
    return f"event: {event}\ndata: {payload}\n\n"


async def _event_stream(
    request: Request,
    query: str,
    kind: str | None = None,
    pro: bool = False,
) -> AsyncIterator[str]:
    corpus = scanner.load_corpus()

    try:
        detected, value = scanner.classify_input(query, kind)
    except scanner.InputError as exc:
        yield _sse("error", {"message": str(exc)})
        return

    kind = detected
    endpoints = corpus.for_plan(pro)

    started = time.perf_counter()
    yield _sse("start", {
        "kind": kind,
        "value": value,
        "total": len(endpoints) if kind == "username" else 0,
        "categories": (corpus.categories_for(endpoints) if kind == "username"
                       else scanner._categories_for_kind(kind)),
    })

    hits: list[scanner.Hit] = []

    try:
        if kind == "username":
            async with scanner._client(scanner.scan_headers()) as client:
                async for hit in scanner.iter_hits(client, endpoints, value):
                    hits.append(hit)
                    yield _sse("result", {
                        "id": hit.endpoint_id,
                        "name": hit.name,
                        "category": hit.category,
                        "status": hit.status,
                        "url": hit.url,
                        "detail": hit.detail,
                        "ms": hit.ms,
                        "checked": len(hits),
                        "total": len(endpoints),
                        "found": sum(1 for h in hits if h.is_hit),
                        "elapsed": round(time.perf_counter() - started, 2),
                    })
        else:
            for hit in await scanner.run_lookup(kind, value, pro=pro):
                hits.append(hit)
                yield _sse("result", {
                    "id": hit.endpoint_id,
                    "name": hit.name,
                    "category": hit.category,
                    "status": hit.status,
                    "url": hit.url,
                    "detail": hit.detail,
                    "ms": hit.ms,
                    "display_name": hit.display_name,
                    "avatar": hit.avatar,
                    "meta": hit.meta,
                    "checked": len(hits),
                    "total": len(hits),
                    "found": sum(1 for h in hits if h.is_hit),
                    "elapsed": round(time.perf_counter() - started, 2),
                })
    except Exception as exc:  # noqa: BLE001
        yield _sse("error", {"message": f"{type(exc).__name__}: {exc}"})
        return

    # Enrich the hits with display names, avatars and profile metadata.
    # This runs after the sweep so it never slows the live results down.
    if kind == "username":
        await scanner.enrich_hits(hits, value)
        for hit in hits:
            if not hit.is_hit:
                continue
            yield _sse("enrich", {
                "id": hit.endpoint_id,
                "display_name": hit.display_name,
                "avatar": hit.avatar,
                "meta": hit.meta,
            })

    elapsed = time.perf_counter() - started
    yield _sse("done", {
        "kind": kind,
        "value": value,
        "checked": len(hits),
        "total": len(endpoints) if kind == "username" else len(hits),
        "found": sum(1 for h in hits if h.is_hit),
        "elapsed": round(elapsed, 2),
        "misses": sum(1 for h in hits if h.status == "miss"),
        "unresolved": sum(1 for h in hits if h.status == "unresolved"),
    })

    # Persist the scan for the signed-in user.
    user = request.state.user
    if user:
        payload = [
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
            for h in hits
        ]
        db.insert_scan(
            user["id"], kind, query, value,
            sum(1 for h in hits if h.is_hit),
            len(hits),
            len(endpoints) if kind == "username" else len(hits),
            elapsed,
            payload,
        )


def stream_response(
    request: Request,
    query: str,
    kind: str | None = None,
    pro: bool = False,
) -> StreamingResponse:
    return StreamingResponse(
        _event_stream(request, query, kind, pro),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
