#!/usr/bin/env python3
"""Phase 3C parser: Python stdlib email (policy=default). Reports the
structure as *this parser* sees the byte stream."""
import json
import sys
import email
from email import policy

raw = open(sys.argv[1], "rb").read()
out = {"parser": "python-email", "version": sys.version.split()[0]}
try:
    msg = email.message_from_bytes(raw, policy=policy.default)
    out["parse_error"] = None
    out["defects"] = [type(d).__name__ for d in msg.defects]
    items = msg.items()
    out["header_entries"] = len(items)
    out["received_count"] = sum(1 for k, _ in items if k.lower() == "received")
    out["from_present"] = msg["From"] is not None
    out["subject_present"] = msg["Subject"] is not None
    out["message_id_present"] = msg["Message-ID"] is not None
    try:
        body = msg.get_content()
    except Exception:
        body = msg.get_payload() or ""
    if not isinstance(body, str):
        body = str(body)
    out["from_in_body"] = "From: Alice" in body
    out["subject_in_body"] = "Subject: [" in body
except Exception as e:
    out["parse_error"] = repr(e)
    out["defects"] = []
    out["header_entries"] = 0
    out["received_count"] = 0
    out["from_present"] = False
    out["subject_present"] = False
    out["message_id_present"] = False
    out["from_in_body"] = False
    out["subject_in_body"] = False
print(json.dumps(out))
