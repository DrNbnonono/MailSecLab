import json
import urllib.request

targets = {
    "v03-nocolon__postfix__capture",
    "v04-8bit-name__postfix__capture",
    "v03-nocolon__exim__capture",
}
found = {}
total = None
for off in range(0, 200, 25):
    r = urllib.request.urlopen(
        "http://msl-mailpit:8025/api/v1/messages?limit=25&start=%d" % off, timeout=5)
    d = json.loads(r.read())
    total = d.get("total")
    for m in d.get("messages", []):
        s = m.get("Subject") or ""
        if s in targets and s not in found:
            found[s] = (m.get("Created"), m["ID"])
    if not d.get("messages"):
        break
print("total:", total)
for k, v in sorted(found.items()):
    print(k, "->", v)
for t in sorted(targets - set(found)):
    print(t, "-> NOT FOUND in full scan")
