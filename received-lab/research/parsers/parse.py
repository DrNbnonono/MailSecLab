import email, json, sys
raw = sys.stdin.buffer.read()
msg = email.message_from_bytes(raw)  # compat32 默认策略
print(json.dumps({
    "received_count": len(msg.get_all("Received") or []),
    "from_in_headers": msg.get("From") is not None,
    "defects": [type(d).__name__ for d in msg.defects],
}))
