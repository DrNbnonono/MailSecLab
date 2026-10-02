#!/usr/bin/env python3
"""Build an I2 message from the IP observed on this socket, then send it."""
from __future__ import annotations

import argparse
import json
import socket
import sys
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path


def local_ip(server: str, port: int) -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((server, port))
        return probe.getsockname()[0]
    finally:
        probe.close()


def stamp(when: datetime) -> str:
    text = format_datetime(when, usegmt=False)
    return text[:-6] + "+0000" if text.endswith(" -0000") else text


def received(from_host, from_ip, by_host, by_ip, protocol, ident, when) -> str:
    return (
        f"Received: from {from_host} ({from_host} [{from_ip}])\r\n"
        f"\tby {by_host} ({by_host} [{by_ip}]) with {protocol} id {ident}\r\n"
        f"\tfor <bob@lab.test>; {stamp(when)}"
    )


def message(case: str, mode: str, client_ip: str, observed: dict | None) -> bytes:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    headers = []
    if mode != "plain":
        if not observed:
            raise SystemExit("observed Received template is required")
        protocol = observed.get("protocol") or "ESMTP"
        client_host = observed.get("from_host") or "client.lab.test"
        t0 = now - timedelta(seconds=180)
        t1 = now - timedelta(seconds=60)
        older = received(
            "origin.example", "203.0.113.10",
            "relay.example", "203.0.113.11",
            protocol, "forged0001", t0,
        )
        if mode == "consistent":
            newer = received(
                "relay.example", "203.0.113.11",
                client_host, client_ip,
                protocol, "forged0002", t1,
            )
        elif mode == "inconsistent":
            newer = received(
                "relay.example", "203.0.113.11",
                "forged.example", "203.0.113.99",
                protocol, "forged0002", t1,
            )
        else:
            raise SystemExit(f"unknown mode {mode}")
        # Trace is newest-first. The hop that must meet Postfix's client
        # header is the newer forged hop, so it is written first.
        headers.extend([newer, older])
    headers.append(f"X-Case-ID: {case}")
    headers.extend([
        "From: Alice <alice@lab.test>",
        "To: Bob <bob@lab.test>",
        f"Subject: {case}",
        f"Message-ID: <{case}@lab.test>",
        "Date: Thu, 01 Oct 2026 12:00:00 +0000",
    ])
    return ("\r\n".join(headers) + "\r\n\r\n" + f"i2-body {case}\r\n").encode("ascii")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=["plain", "consistent", "inconsistent"])
    ap.add_argument("--case", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--observed", default="")
    ap.add_argument("--server", default="postfix1")
    ap.add_argument("--port", type=int, default=25)
    args = ap.parse_args()
    ip = local_ip(args.server, args.port)
    observed = None
    if args.observed:
        observed = json.loads(Path(args.observed).read_text(encoding="utf-8"))
    raw = message(args.case, args.mode, ip, observed)
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    meta = {
        "case": args.case,
        "mode": args.mode,
        "client_ip_at_build": ip,
        "bytes": len(raw),
        "forged_addresses": ["203.0.113.10", "203.0.113.11"] + (
            [] if args.mode == "plain" else (
                [ip] if args.mode == "consistent" else ["203.0.113.99"]
            )
        ),
        "address_policy": "RFC 5737 TEST-NET-3 plus the client IP read on this socket",
    }
    path.with_suffix(".build.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(meta))
    return 0


if __name__ == "__main__":
    sys.exit(main())
