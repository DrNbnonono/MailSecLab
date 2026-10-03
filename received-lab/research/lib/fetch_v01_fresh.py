import json
import urllib.request

r = urllib.request.urlopen("http://msl-mailpit:8025/api/v1/messages?limit=30", timeout=5)
msgs = json.loads(r.read())["messages"]
print("listed", len(msgs))
for m in msgs:
    if (m.get("Subject") or "") == "v01-obs-colon__osmtpd__capture":
        raw = urllib.request.urlopen(
            "http://msl-mailpit:8025/api/v1/message/%s/raw" % m["ID"], timeout=5).read()
        open("/evidence/w3-20261003a/diffrun/v01-fresh.raw", "wb").write(raw)
        print("fetched", m["Created"], len(raw))
        break
