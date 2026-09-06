#!/usr/bin/env python3
"""Fetch the latest mailpit message whose raw contains a marker string.
usage: mailpit_dump.py MARKER OUT_FILE"""
import json, sys, urllib.request

marker, out = sys.argv[1], sys.argv[2]
api = "http://mailpit:8025/api/v1"
ids = json.load(urllib.request.urlopen(f"{api}/messages?limit=20"))["messages"]
for m in ids:
    raw = urllib.request.urlopen(f"{api}/message/{m['ID']}/raw").read()
    if marker.encode() in raw:
        open(out, "wb").write(raw)
        print(f"found {m['ID']} ({len(raw)} bytes) -> {out}")
        sys.exit(0)
print("NOT_FOUND")
sys.exit(1)
