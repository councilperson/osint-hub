import asyncio
import io
import sys

import httpx

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")


async def main():
    q = sys.argv[1] if len(sys.argv) > 1 else "mrbeast"
    kinds = {}
    enrich_names = []
    async with httpx.AsyncClient(timeout=120) as client:
        async with client.stream(
            "GET", "http://127.0.0.1:8077/api/scan/stream",
            params={"q": q}, headers={"Accept": "text/event-stream"},
        ) as resp:
            name = None
            data = ""
            async for line in resp.aiter_lines():
                if line.startswith("event: "):
                    name = line[7:]
                elif line.startswith("data: "):
                    data = line[6:]
                    kinds[name] = kinds.get(name, 0) + 1
                    if name == "enrich":
                        import json
                        d = json.loads(data)
                        enrich_names.append((d.get("id"), d.get("display_name")))
    print("event counts:", kinds)
    print("enriched:", len(enrich_names))
    for n in enrich_names[:12]:
        print("   ", n)


asyncio.run(main())
