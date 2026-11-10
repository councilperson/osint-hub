import asyncio
import io
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
from app import enrich


async def main():
    for plat in ["GitHub", "Reddit", "Bluesky", "GitLab", "Telegram", "Mastodon", "Gravatar"]:
        d = await enrich.enrich(plat, "mrbeast", "https://example.com/x")
        name = str(d.get("display_name"))[:30]
        avatar = str(d.get("avatar"))[:70]
        print("%-10s name=%-32s avatar=%s" % (plat, name, avatar))


asyncio.run(main())
