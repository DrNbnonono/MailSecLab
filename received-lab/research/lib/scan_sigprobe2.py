import json
import urllib.request

for off in range(0, 250, 25):
    r = urllib.request.urlopen(
        "http://msl-mailpit:8025/api/v1/messages?limit=25&start=%d" % off, timeout=5)
    d = json.loads(r.read())
    if not d.get("messages"):
        break
    for m in d["messages"]:
        s = m.get("Subject") or "(no subject)"
        if "sigprobe2" in s or "sp2-" in s:
            # 取首条 Received 判定经手 MTA
            raw = urllib.request.urlopen(
                "http://msl-mailpit:8025/api/v1/message/%s/raw" % m["ID"], timeout=5).read()
            first = raw[raw.find(b"Received"):raw.find(b"Received") + 60].decode("utf-8", "replace")
            via = "postfix" if b"auth-postfix" in raw[:600] else ("osmtpd" if b"opensmtpd" in raw[:600] else "?")
            print(f"{s:<34} {m.get('Created')} via={via} first={first[:48]!r}")
