import json
import urllib.request

CASE_IDS = [
    "v03-nocolon__postfix__threshold", "v03-nocolon__postfix__capture",
    "v04-8bit-name__postfix__threshold", "v04-8bit-name__postfix__capture",
    "v03-nocolon__exim__threshold", "v03-nocolon__exim__capture",
    "v03-nocolon__osmtpd__threshold", "v03-nocolon__osmtpd__capture",
    "v04-8bit-name__osmtpd__threshold", "v04-8bit-name__osmtpd__capture",
    "v04-8bit-name__exim__threshold", "v04-8bit-name__exim__capture",
]
found = {}
for off in range(0, 200, 25):
    r = urllib.request.urlopen(
        "http://msl-mailpit:8025/api/v1/messages?limit=25&start=%d" % off, timeout=5)
    d = json.loads(r.read())
    msgs = d.get("messages", [])
    if not msgs:
        break
    for m in msgs:
        subj = m.get("Subject") or ""
        if subj:
            continue  # 有主题的已被主题扫描覆盖
        raw = urllib.request.urlopen(
            "http://msl-mailpit:8025/api/v1/message/%s/raw" % m["ID"], timeout=5).read()
        for cid in CASE_IDS:
            if cid.encode() in raw and cid not in found:
                out = "/evidence/w3-20261003a/diffrun/%s.stored.raw" % cid
                open(out, "wb").write(raw)
                found[cid] = (m.get("Created"), len(raw))
for cid in CASE_IDS:
    print(cid, "->", found.get(cid, "STILL NOT FOUND"))
