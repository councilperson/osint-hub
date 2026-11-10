import io
import json
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
sys.path.insert(0, "scripts")
import build_corpus as bc  # noqa: E402

src = json.load(open("scripts/maigret_data.json", encoding="utf-8"))
sites = src.get("sites", {})
for want in ("APClips", "Eporner", "Gam1ng", "Gays", "Badoo"):
    site = sites.get(want)
    if not site:
        print(want, "-> NOT IN SOURCE")
        continue
    print(want)
    print("   tags   :", site.get("tags"))
    print("   name   :", bc.ADULT_NAME_RE.findall(site.get("name", "")))
    print("   url    :", site.get("url"))
    print("   urlMain:", site.get("urlMain"))
    print("   host   :", bc._host_of(site.get("url") or ""), bc._host_of(site.get("urlMain") or ""))
    print("   adult  :", bc.is_adult(site))
