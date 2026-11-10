import io
import json
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
d = json.load(open("data/endpoints.json", encoding="utf-8"))
eps = d["endpoints"]
adult = [e for e in eps if e.get("adult")]
print("total endpoints: %d" % len(eps))
print("adult-tagged   : %d" % len(adult))
print("free-tier set  : %d" % (len(eps) - len(adult)))
print()
for cat in [c["id"] for c in d["categories"]]:
    n = sum(1 for e in eps if e["category"] == cat)
    a = sum(1 for e in adult if e["category"] == cat)
    print("  %-10s %3d total  %3d adult  %3d free" % (cat, n, a, n - a))
print()
print("adult entries:")
for e in adult:
    print("  [%-9s] %-28s %s" % (e["category"], e["name"], e["url"][:78]))
