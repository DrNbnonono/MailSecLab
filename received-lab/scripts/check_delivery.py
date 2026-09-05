#!/usr/bin/env python3
"""Check Mailpit for delivery of a case message and its bounce.

The message is located by its X-Case-ID header in the stored raw bytes — never
by Subject, which can be demoted into the body by malformed-header cases
(the ET050 lesson). Subject-based dump is kept only as a display helper.

Output for the default mode (machine-readable, used by scan.sh / phase2.sh):
  DELIVERED: yes received_count=N      (N = exact "Received:" line count)
  DELIVERED: no
  BOUNCE: yes|no                       (DSN containing this case's X-Case-ID)
"""
import argparse
import json
import sys
import time
import urllib.request

MP = "http://mailpit:8025"


def http(path, method="GET", body=None, raw=False):
    req = urllib.request.Request(
        MP + path, method=method, data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=8) as r:
        data = r.read()
    return data if raw else json.loads(data.decode())


def get_json(path):
    return http(path)


def list_messages(limit=300):
    return get_json(f"/api/v1/messages?limit={limit}").get("messages", [])


def get_raw(mid):
    return http(f"/api/v1/message/{mid}/raw", raw=True)


def find_raw_by_case(case, limit=80):
    marker = b"X-Case-ID: " + case.encode()
    for m in list_messages(limit):
        raw = get_raw(m["ID"])
        if marker in raw.split(b"\r\n\r\n", 1)[0]:
            return raw
    return None


def count_received_exact(raw: bytes):
    header = raw.split(b"\r\n\r\n", 1)[0]
    return sum(1 for l in header.split(b"\r\n") if l.startswith(b"Received:"))


def bounce_for_case(case):
    """A DSN contains the original X-Case-ID in its attached headers/body but
    NOT in its own header section (that is the case message itself). Detect
    the marker anywhere in messages that are not the case message, regardless
    of DSN subject wording (Postfix/Exim/OpenSMTPD differ)."""
    marker = b"X-Case-ID: " + case.encode()
    for m in list_messages():
        raw = get_raw(m["ID"])
        if marker in raw.split(b"\r\n\r\n", 1)[0]:
            continue  # this is the case message itself
        if marker in raw:
            return True
    return False


def clear_all():
    ids = [m["ID"] for m in list_messages(10000)]
    if ids:
        http("/api/v1/messages", method="DELETE",
             body=json.dumps({"ids": ids}).encode())
    print(f"CLEAR: {len(ids)}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--case-id", default=None)
    p.add_argument("--timeout", type=float, default=15)
    p.add_argument("--clear", action="store_true")
    p.add_argument("--dump-subject", default=None,
                   help="[display helper] print raw of first message whose Subject contains this")
    p.add_argument("--dump-case", default=None,
                   help="print raw bytes of the message with this X-Case-ID")
    a = p.parse_args()

    if a.clear:
        clear_all()
        return

    if a.dump_case:
        raw = find_raw_by_case(a.dump_case)
        if raw is None:
            print("NOT_FOUND")
            sys.exit(1)
        sys.stdout.buffer.write(raw)
        return

    if a.dump_subject:
        for m in list_messages():
            if a.dump_subject in (m.get("Subject") or ""):
                sys.stdout.buffer.write(get_raw(m["ID"]))
                return
        print("NOT_FOUND")
        sys.exit(1)

    case = a.case_id
    deadline = time.time() + a.timeout
    raw = None
    while time.time() < deadline and raw is None:
        raw = find_raw_by_case(case)
        if raw is None:
            time.sleep(0.4)

    if raw is not None:
        print(f"DELIVERED: yes received_count={count_received_exact(raw)}")
        print(f"BOUNCE: {'yes' if bounce_for_case(case) else 'no'}")
    else:
        print("DELIVERED: no")
        print(f"BOUNCE: {'yes' if bounce_for_case(case) else 'no'}")


if __name__ == "__main__":
    main()
