"""Build the endpoint corpus (data/endpoints.json) from Maigret's site list.

Maigret (github.com/soxoj/maigret) ships a community-maintained list of sites
with a username URL template and, for most of them, the exact strings that
appear when a handle does NOT exist. We use that list as the source of truth
for *real, working* endpoints instead of hand-writing hundreds of guesses.

Output: data/endpoints.json — exactly 773 endpoints in 6 categories, with the
per-category counts the UI advertises.

Usage:
    python scripts/build_corpus.py            # downloads the source if missing
    python scripts/build_corpus.py --offline  # use a local maigret_data.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "endpoints.json"
SOURCE_URL = (
    "https://raw.githubusercontent.com/soxoj/maigret/master/maigret/resources/data.json"
)
LOCAL_SOURCE = ROOT / "scripts" / "maigret_data.json"

# The UI advertises these numbers; the corpus must match them exactly.
CATEGORY_TARGETS = {
    "social": 46,
    "creator": 29,
    "developer": 31,
    "gaming": 14,
    "commerce": 33,
    "longtail": 620,
}

CATEGORY_LABELS = {
    "social": "Social and messaging",
    "creator": "Creator and media",
    "developer": "Developer and tech",
    "gaming": "Gaming",
    "commerce": "Commerce and links",
    "longtail": "Long tail",
}

# Marquee platforms that must be present regardless of their Maigret tags.
CORE = {
    "social": [
        "GitHub", "Reddit", "Twitter", "Instagram", "TikTok", "YouTube",
        "Twitch", "Telegram", "Discord", "Facebook", "Pinterest", "Medium",
        "Mastodon", "Bluesky", "VK", "Snapchat", "Threads", "Tumblr",
        "Flickr", "SoundCloud", "LinkedIn", "About.me", "Linktree",
        "Gravatar", "Keybase", "500px", "Quora", "Vimeo", "Mixcloud",
        "Imgur", "Giphy", "Patreon", "Ko-fi", "BuyMeACoffee", "Behance",
        "Dribbble", "DeviantArt", "Fandom", "Wikipedia", "Bandcamp",
        "Last.fm", "MyAnimeList", "Goodreads", "Letterboxd", "Untappd",
    ],
    "creator": [
        "YouTube", "Twitch", "Vimeo", "Dailymotion", "SoundCloud", "Mixcloud",
        "Bandcamp", "Beatport", "Discogs", "Spotify", "ReverbNation", "Flickr",
        "500px", "DeviantArt", "Behance", "Dribbble", "ArtStation", "Pixiv",
        "Imgur", "Giphy", "Foursquare", "Goodreads", "Letterboxd", "Untappd",
        "MyAnimeList", "Trakt", "Patreon", "OnlyFans", "BuyMeACoffee",
        "Ko-fi", "Chaturbe",
    ],
    "developer": [
        "GitHub", "GitLab", "Bitbucket", "StackOverflow", "PyPI", "npm",
        "Docker Hub", "HuggingFace", "Kaggle", "Replit", "Codepen",
        "CodePen", "Codeberg", "SourceForge", "Launchpad", "Dev.to",
        "Hashnode", "Medium", "HackerRank", "LeetCode", "Codeforces",
        "Kaggle", "Replit", "Trello", "Airtable", "Notion", "Obsidian",
        "GitBook", "Readthedocs", "npmjs", "NuGet", "RubyGems", "Packagist",
        "Crates.io", "Maven", "Gradle", "Jira", "Confluence",
    ],
    "gaming": [
        "Steam", "SteamCommunity", "Roblox", "Xbox Gamertag", "PSNProfiles",
        "itch.io", "Chess.com", "Lichess", "Duolingo", "osu!", "Speedrun",
        "Speedrun.com", "Kongregate", "Newgrounds", "ArmorGames",
        "Habbo", "Miiverse",
    ],
    "commerce": [
        "Patreon", "Etsy", "eBay", "Fiverr", "Freelancer", "Upwork",
        "BuyMeACoffee", "Ko-fi", "Gumroad", "PayPal", "Cash.app", "Wise",
        "Shopify", "Walmart", "Target", "Etsy", "Fiverr", "Ko-fi",
        "BuyMeACoffee", "Patreon", "Gumroad", "Etsy", "Goodreads",
        "Untappd", "Letterboxd", "Trakt", "Paypal", "Cashme", "Bountysource",
    ],
}

# Platforms whose home is unambiguous. Without this, a site tagged both
# "music" and "social" lands in whichever category the tag sorter happens to
# favour first — the marquee platforms should always be where people expect.
PRIMARY_CATEGORY = {
    # social and messaging
    "Reddit": "social", "Twitter": "social", "Instagram": "social",
    "TikTok": "social", "Telegram": "social", "Discord": "social",
    "Facebook": "social", "Mastodon": "social", "Bluesky": "social",
    "Snapchat": "social", "Threads": "social", "VK": "social",
    "Tumblr": "social", "Linktree": "social", "About.me": "social",
    "Gravatar": "social", "Keybase": "social", "Quora": "social",
    "LinkedIn": "social", "Pinterest": "social", "Medium": "social",
    # creator and media
    "YouTube": "creator", "Twitch": "creator", "Vimeo": "creator",
    "Dailymotion": "creator", "SoundCloud": "creator", "Mixcloud": "creator",
    "Bandcamp": "creator", "Beatport": "creator", "Discogs": "creator",
    "ReverbNation": "creator", "Flickr": "creator", "500px": "creator",
    "DeviantArt": "creator", "Behance": "creator", "Dribbble": "creator",
    "ArtStation": "creator", "Pixiv": "creator", "Giphy": "creator",
    "Foursquare": "creator", "Goodreads": "creator", "Letterboxd": "creator",
    "Untappd": "creator", "MyAnimeList": "creator", "Trakt": "creator",
    "Imgur": "creator", "Spotify": "creator", "Last.fm": "creator",
    # developer and tech
    "GitHub": "developer", "GitLab": "developer", "Bitbucket": "developer",
    "StackOverflow": "developer", "PyPI": "developer", "npm": "developer",
    "Docker Hub": "developer", "HuggingFace": "developer", "Kaggle": "developer",
    "Replit": "developer", "CodePen": "developer", "Codeberg": "developer",
    "SourceForge": "developer", "Launchpad": "developer", "Dev.to": "developer",
    "Hashnode": "developer", "HackerRank": "developer", "LeetCode": "developer",
    "Codeforces": "developer", "Trello": "developer", "Airtable": "developer",
    "Notion": "developer", "GitBook": "developer", "Readthedocs": "developer",
    "NuGet": "developer", "RubyGems": "developer", "Packagist": "developer",
    "Crates.io": "developer", "Jira": "developer", "Confluence": "developer",
    "npmjs": "developer", "Maven": "developer", "Gradle": "developer",
    # gaming
    "Steam": "gaming", "SteamCommunity": "gaming", "Roblox": "gaming",
    "Xbox Gamertag": "gaming", "PSNProfiles": "gaming", "itch.io": "gaming",
    "Chess.com": "gaming", "Lichess": "gaming", "osu!": "gaming",
    "Speedrun.com": "gaming", "Kongregate": "gaming", "Newgrounds": "gaming",
    "ArmorGames": "gaming", "Habbo": "gaming", "Duolingo": "gaming",
    # commerce and links
    "Etsy": "commerce", "eBay": "commerce", "Fiverr": "commerce",
    "Freelancer": "commerce", "Upwork": "commerce", "Gumroad": "commerce",
    "PayPal": "commerce", "Shopify": "commerce", "Walmart": "commerce",
    "Target": "commerce", "Wise": "commerce", "Bountysource": "commerce",
}

# Tags that steer a site into a category.
TAG_CATEGORY = [
    ("social", {
        "social", "messaging", "forum", "discussion", "chat", "mail", "email",
        "news", "professional", "networking", "dating", "contact",
    }),
    ("creator", {
        "music", "video", "streaming", "photo", "art", "design", "blog",
        "writing", "podcast", "film", "movies", "tv", "book", "books",
        "anime", "manga", "comics", "fashion", "food", "travel", "hobby",
        "sports", "sport", "science", "education", "dance", "theater",
    }),
    ("developer", {
        "coding", "tech", "technology", "programming", "software", "developer",
        "dev", "code", "open-source", "opensource", "linux", "security",
        "sysadmin", "data", "science-tech", "hacking", "cloud",
    }),
    ("gaming", {"gaming", "game", "games", "gamers", "speedrun", "chess", "puzzle"}),
    ("commerce", {
        "shopping", "business", "finance", "money", "crypto", "banking",
        "ecommerce", "freelance", "jobs", "career", "company", "brand",
        "investment", "insurance", "selling", "marketplace",
    }),
]

# --------------------------------------------------------------------------
# content classification
# --------------------------------------------------------------------------
# Adult / explicit platforms are NOT deleted. They stay in the corpus and are
# tagged `adult: true`, so a Pro plan can reach them while the free tier
# never sees them. Piracy and gambling have no research value and are the
# kind of source that blocks automated checks, so those are excluded outright.

ADULT_TAGS = {
    "nsfw", "porn", "porno", "adult", "xxx", "hentai", "camgirl", "escort",
    "milf", "blowjob", "onlyfans", "onlyfans-leak", "fansly", "pornhub",
    "cams", "webcam", "stripchat", "chaturbate", "patreon-leak", "erotic",
    "erotica", "fetish", "bdsm", "shemale", "voyeur", "sex", "sexy",
    "nudity", "nude", "hookup", "swinger", "lingerie", "sexdolls",
}

BLOCK_TAGS = {
    "gambling", "casino", "poker", "betting", "bets", "sportsbook",
    "piracy", "torrent", "warez", "crack", "keygen",
}

# Domains that are unambiguously adult / 18+. Matching on the host is far
# more precise than matching the whole URL.
ADULT_DOMAINS = {
    "pornhub.com", "xvideos.com", "xhamster.com", "xnxx.com", "redtube.com",
    "youporn.com", "tube8.com", "spankbang.com", "motherless.com",
    "indiaporn.com", "bongacams.com", "cam4.com", "chaturbate.com",
    "stripchat.com", "camsoda.com", "myfreecams.com", "flirt4free.com",
    "livejasmin.com", "royalcam.com", "cams.com", "camwhores.tv",
    "adultfriendfinder.com", "friendfinder.com", "friendfinder-x.com",
    "allthingsworn.com", "furaffinity.net", "inkbunny.net", "justfor.fans",
    "admire.me", "onlyfans.com", "fansly.com", "erome.com", "e621.net",
    "rule34.xxx", "furryfandom.com", "catboy.baby", "cute.aam.pics",
    "gays.com", "gays.ru", "badoo.com", "dating.ru", "letschatlove.com",
    "chaturbe.com", "hot-xxx.com", "sexcam.com", "hookup.dating",
    "sexhub.com", "fetlife.com", "literotica.com", "domywife.com",
    "sugardaddy.com", "wifelounge.com", "seek.com",
    "lewd.com", "nasty.com", "onlybabes.com",
}

ADULT_NAME_RE = re.compile(
    r"porn|xxx|hentai|escort|camgirl|milf|nsfw|adult|blowjob|hotgirls|"
    r"nude|naked|bonga|royalcam|stripchat|chaturbe|onlyfans|fansly|"
    r"myfreecams|flirt4free|islandmania|livejasmin|camsoda|xhamster|"
    r"redtube|youporn|tube8|spankbang|motherless|indiaporn|erotic|"
    r"erotica|fetish|bdsm|shemale|sexcam|sexdoll|lingerie|hookup|"
    r"swinger|e621|rule34|webcam|cams\.com|sexy\.com|friendfinder|"
    r"allthingsworn|all things worn|furaffinity|fur affinity|inkbunny|"
    r"justfor\.fans|justforfans|admire me|badoo|dating\.ru|"
    r"letschatlove|chatujme|personals|casual-dating|dating-singles",
    re.I,
)

BLOCK_NAME_RE = re.compile(
    r"1337x|rarbg|limextorrents|eztv|nyaa\.si|rutracker|shadowban|"
    r"gamblejoe|casino|poker|sportsbook|jackpot|slots\b|"
    r"torrent|warez|crack|keygen",
    re.I,
)

BLOCK_URL_RE = re.compile(
    r"1337x|rarbg|torrents|nyaa|rutracker|shadowban|"
    r"casino|poker|betting|gambling|sportsbook|jackpot",
    re.I,
)


def _host_of(url: str) -> str:
    m = re.match(r"https?://([^/?#]+)", url or "", re.I)
    if not m:
        return ""
    host = m.group(1).split("@")[-1].split(":")[0].lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def _host_is_adult(host: str) -> bool:
    """True when the host is a known adult platform (exact or subdomain)."""
    if not host:
        return False
    if host in ADULT_DOMAINS:
        return True
    for dom in ADULT_DOMAINS:
        if host.endswith("." + dom):
            return True
    return False


def is_adult(site: dict) -> bool:
    """Adult / explicit sources are kept in the corpus but Pro-only."""
    tags = {t.lower() for t in (site.get("tags") or [])}
    if tags & ADULT_TAGS:
        return True
    name = site.get("name", "") or ""
    if ADULT_NAME_RE.search(name):
        return True
    for url in (site.get("url") or "", site.get("urlMain") or ""):
        if _host_is_adult(_host_of(url)):
            return True
        if ADULT_NAME_RE.search(url):
            return True
    return False


def download_source(dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"downloading source list from {SOURCE_URL}")
    with urllib.request.urlopen(SOURCE_URL, timeout=120) as r:
        data = r.read()
    dest.write_bytes(data)
    print(f"  saved {len(data):,} bytes -> {dest}")
    return dest


def load_source(offline: bool) -> dict:
    path = LOCAL_SOURCE
    if not path.exists():
        if offline:
            sys.exit("offline mode requested but scripts/maigret_data.json is missing")
        path = download_source(path)
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def blocked(site: dict) -> bool:
    """True for content we refuse to index at all (piracy, gambling)."""
    tags = {t.lower() for t in (site.get("tags") or [])}
    if tags & BLOCK_TAGS:
        return True
    name = site.get("name", "")
    if BLOCK_NAME_RE.search(name):
        return True
    if BLOCK_URL_RE.search(site.get("url") or "") or BLOCK_URL_RE.search(site.get("urlMain") or ""):
        return True
    return False


def score(site: dict) -> int:
    """Higher is more likely to behave well in an automated check."""
    s = 0
    method = site.get("checkType", "status_code")
    if method == "status_code":
        s += 3
    if site.get("absenceStrs"):
        s += 3
    if site.get("presenseStrs"):
        s += 1
    if site.get("urlProbe"):
        s += 1
    if site.get("urlMain"):
        s += 1
    # prefer sites with a sane, short URL
    url = site.get("url") or ""
    s -= len(url) // 60
    # penalise heavy engines that need special handling
    engine = (site.get("engine") or "").lower()
    if engine in {"phpbb", "phpbb2", "vbulletin", "xenforo", "discourse",
                  "flarum", "vanilla", "ucoz", "mediawiki"}:
        s -= 2
    return s


def classify(tags: set[str]) -> str:
    best, best_hits = "longtail", 0
    for cat, cat_tags in TAG_CATEGORY:
        hits = len(tags & cat_tags)
        if hits > best_hits:
            best, best_hits = cat, hits
    return best


def normalise(name: str, site: dict) -> dict | None:
    url = (site.get("url") or "").strip()
    if not url or "{username}" not in url:
        return None
    main = (site.get("urlMain") or "").strip()
    url = url.replace("{urlMain}", main.rstrip("/"))
    if not url.startswith(("http://", "https://")):
        return None
    if site.get("regexCheck"):
        return None  # numeric-only handles are not what we scan for
    method = site.get("checkType", "status_code")
    if method not in ("status_code", "message"):
        return None
    absence = [a for a in (site.get("absenceStrs") or []) if isinstance(a, str) and a]
    if method == "message" and not absence:
        return None
    probe = (site.get("urlProbe") or "").strip() or None
    if probe:
        probe = probe.replace("{urlMain}", main.rstrip("/"))
        if "{username}" not in probe:
            probe = None
    return {
        "id": re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:64],
        "name": name,
        "category": "",
        "method": method,
        "url": url,
        "probe": probe,
        "main": main or None,
        "absence": absence[:4],
        "presence": [p for p in (site.get("presenseStrs") or []) if isinstance(p, str)][:3],
        "tags": sorted({t.lower() for t in (site.get("tags") or [])})[:8],
        "adult": is_adult(site),
    }


def build() -> dict:
    data = load_source("--offline" in sys.argv)
    sites = data.get("sites", {})
    print(f"source has {len(sites):,} sites")

    candidates: list[dict] = []
    seen_urls: set[str] = set()
    for name, site in sites.items():
        if not isinstance(site, dict) or blocked(site):
            continue
        entry = normalise(name, site)
        if not entry:
            continue
        key = entry["url"].lower()
        if key in seen_urls:
            continue
        seen_urls.add(key)
        entry["_score"] = score(site)
        candidates.append(entry)

    print(f"{len(candidates):,} usable endpoints after filtering")

    by_name = {c["name"]: c for c in candidates}
    # category -> ordered list of picked entries
    picked: dict[str, list[dict]] = {k: [] for k in CATEGORY_TARGETS}
    taken_names: set[str] = set()

    def take(cat: str, entry: dict) -> bool:
        """Add an endpoint to a category if it fits the target and is new."""
        if entry["name"] in taken_names:
            return False
        if len(picked[cat]) >= CATEGORY_TARGETS[cat]:
            return False
        entry["category"] = cat
        picked[cat].append(entry)
        taken_names.add(entry["name"])
        return True

    # 1) marquee platforms first, in their primary category
    for cat, names in CORE.items():
        for n in names:
            entry = by_name.get(n)
            if entry:
                take(cat, entry)

    # 1b) well-known platforms whose primary category is fixed
    for name, cat in PRIMARY_CATEGORY.items():
        entry = by_name.get(name)
        if entry:
            take(cat, entry)

    # 2) fill each named category with the best-scoring tag matches
    buckets: dict[str, list[dict]] = {k: [] for k in CATEGORY_TARGETS}
    for c in candidates:
        if c["name"] in taken_names:
            continue
        buckets[classify(set(c["tags"]))].append(c)

    for cat in ("social", "creator", "developer", "gaming", "commerce"):
        pool = sorted(buckets[cat], key=lambda e: (-e["_score"], e["name"]))
        for entry in pool:
            take(cat, entry)
            if len(picked[cat]) >= CATEGORY_TARGETS[cat]:
                break

    # 3) long tail: the best remaining endpoints
    rest = [c for c in candidates if c["name"] not in taken_names]
    rest.sort(key=lambda e: (-e["_score"], e["name"]))
    for entry in rest:
        take("longtail", entry)
        if len(picked["longtail"]) >= CATEGORY_TARGETS["longtail"]:
            break

    # 4) finalise
    endpoints: list[dict] = []
    for cat, target in CATEGORY_TARGETS.items():
        items = sorted(picked[cat], key=lambda e: (-e["_score"], e["name"]))[:target]
        if len(items) < target:
            print(f"  ! {cat}: only {len(items)}/{target} available", file=sys.stderr)
        for e in items:
            e.pop("_score", None)
            endpoints.append(e)

    total = len(endpoints)
    print(f"built {total} endpoints")
    for cat, target in CATEGORY_TARGETS.items():
        n = sum(1 for e in endpoints if e["category"] == cat)
        print(f"  {CATEGORY_LABELS[cat]:24s} {n:3d} / {target}")

    return {
        "version": 1,
        "source": "Maigret site list (github.com/soxoj/maigret)",
        "total": total,
        "categories": [
            {
                "id": cat,
                "label": CATEGORY_LABELS[cat],
                "count": sum(1 for e in endpoints if e["category"] == cat),
            }
            for cat in CATEGORY_TARGETS
        ],
        "endpoints": endpoints,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true", help="don't download the source list")
    args = ap.parse_args()

    if args.offline and not LOCAL_SOURCE.exists():
        sys.exit("offline mode requested but scripts/maigret_data.json is missing")

    corpus = build()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8") as fh:
        json.dump(corpus, fh, ensure_ascii=False, indent=1)
    print(f"wrote {OUT} ({OUT.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
