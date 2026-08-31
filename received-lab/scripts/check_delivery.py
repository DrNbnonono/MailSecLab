#!/usr/bin/env python3
"""Check Mailpit for delivery of a case message and for its bounce; count final Received headers."""
import argparse
import json
import sys
import time
import urllib.request

MP = "http://mailpit:8025"


def http(path, method="GET", body=None):
    req = urllib.request.Request(
        MP + path, method=method, data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=8) as r:
        return r.read().decode(errors="replace")


def get_json(path):
    return json.loads(http(path))


def list_messages(limit=300):
    return get_json(f"/api/v1/messages?limit={limit}").get("messages", [])


def get_raw(mid):
    return http(f"/api/v1/message/{mid}/raw")


def count_received(raw):
    n = 0
    in_headers = True
    for line in raw.split("\r\n"):
        if not in_headers:
            break
        if line == "":
            in_headers = False
            continue
        if line.startswith("Received:"):
            n += 1
    return n


def clear_all():
    ids = [m["ID"] for m in list_messages(10000)]
    if ids:
        http("/api/v1/messages", method="DELETE",
             body=json.dumps({"ids": ids}).encode())
    print(f"CLEAR: {len(ids)}")


def find_message(sub):
    for m in list_messages():
        if sub in (m.get("Subject") or ""):
            return m
    return None


def bounce_for_case(case):
    marker = f"X-Case-ID: {case}"
    for m in list_messages():
        if "Undelivered Mail Returned to Sender" in (m.get("Subject") or ""):
            if marker in get_raw(m["ID"]):
                return True
    return False


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--case-id", default=None)
    p.add_argument("--timeout", type=float, default=15)
    p.add_argument("--clear", action="store_true")
    p.add_argument("--dump-subject", default=None,
                   help="print raw source of first message whose subject contains this string")
    a = p.parse_args()

    if a.clear:
        clear_all()
        return

    if a.dump_subject:
        m = find_message(a.dump_subject)
        if m is None:
            print("NOT_FOUND")
            sys.exit(1)
        print(get_raw(m["ID"]))
        return

    case = a.case_id
    deadline = time.time() + a.timeout
    msg = None
    while time.time() < deadline and msg is None:
        msg = find_message(f"[{case}]")
        if msg is None:
            time.sleep(0.4)

    if msg is not None:
        raw = get_raw(msg["ID"])
        print(f"DELIVERED: yes received_count={count_received(raw)}")
        print(f"BOUNCE: {'yes' if bounce_for_case(case) else 'no'}")
    else:
        print("DELIVERED: no")
        print(f"BOUNCE: {'yes' if bounce_for_case(case) else 'no'}")


if __name__ == "__main__":
    main()
