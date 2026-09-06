#!/usr/bin/env python3
import json, urllib.request, sys
api = "http://mailpit:8025/api/v1"
ms = json.load(urllib.request.urlopen(f"{api}/messages?limit=3"))
for m in ms["messages"]:
    print("ID:", m["ID"], "|", m.get("Subject","")[:40])
mid = ms["messages"][0]["ID"]
for ep in (f"/api/v1/message/{mid}", f"/api/v1/view/{mid}"):
    try:
        r = urllib.request.urlopen(api + ep)
        print(ep, "->", r.status, len(r.read()), "bytes")
    except Exception as e:
        print(ep, "->", e)
