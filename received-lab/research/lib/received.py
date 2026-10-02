"""Parse Received headers and compare a forged hop with the hop Postfix added."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime


def _split_header(raw: bytes) -> list[str]:
    sep = raw.find(b"\r\n\r\n")
    if sep >= 0:
        lines = raw[:sep].decode("latin1").split("\r\n")
    else:
        sep = raw.find(b"\n\n")
        if sep < 0:
            return []
        lines = raw[:sep].decode("latin1").split("\n")
    fields = []
    current = None
    for line in lines:
        if line.startswith(" ") or line.startswith("\t"):
            if current is not None:
                current.append(line)
            continue
        if current is not None:
            fields.append("\r\n".join(current))
        current = [line]
    if current is not None:
        fields.append("\r\n".join(current))
    return fields


def parse_received(field: str) -> dict:
    unfolded = re.sub(r"[\r\n]+[ \t]+", " ", field).strip()
    from_m = re.search(r"\bfrom\s+(\S+)", unfolded, re.I)
    by_m = re.search(r"\bby\s+(\S+)", unfolded, re.I)
    with_m = re.search(r"\bwith\s+(\S+)", unfolded, re.I)
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", unfolded)
    date = unfolded.split(";", 1)[1].strip() if ";" in unfolded else ""
    parsed = None
    if date:
        try:
            parsed = parsedate_to_datetime(date)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError, IndexError):
            parsed = None
    return {
        "raw": field,
        "unfolded": unfolded,
        "from_host": (from_m.group(1).strip(";") if from_m else ""),
        "by_host": (by_m.group(1).strip(";") if by_m else ""),
        "protocol": (with_m.group(1).strip(";") if with_m else ""),
        "ips": ips,
        "date": date,
        "date_iso": parsed.isoformat() if parsed else "",
    }


def received_headers(raw: bytes) -> list[dict]:
    out = []
    for field in _split_header(raw):
        name = field.split(":", 1)[0].strip().lower()
        if name == "received":
            out.append(parse_received(field))
    return out


def _time(item: dict):
    if not item.get("date_iso"):
        return None
    return datetime.fromisoformat(item["date_iso"])


def assess_join(stored: bytes, mode: str, client_ip: str) -> dict:
    headers = received_headers(stored)
    genuine = next((h for h in headers if client_ip in h["ips"] and "postfix1" in h["by_host"]), None)
    if genuine is None:
        genuine = next((h for h in headers if client_ip in h["ips"]), None)
    reasons = []
    forged = None
    if genuine is None:
        reasons.append("no Received header contains the client IP read before send")
    else:
        if genuine["ips"][0] != client_ip and client_ip not in genuine["ips"]:
            reasons.append("genuine header IP differs from the pre-send client IP")
        idx = headers.index(genuine)
        if idx + 1 < len(headers):
            forged = headers[idx + 1]
    if mode == "plain":
        ok = genuine is not None and client_ip in genuine["ips"] and not reasons
        return {"join_ok": ok, "reasons": reasons, "genuine": genuine, "forged_below": forged, "received": headers}
    if forged is None:
        reasons.append("no forged Received immediately below the genuine client hop")
        return {"join_ok": False, "reasons": reasons, "genuine": genuine, "forged_below": None, "received": headers}
    if genuine and forged["by_host"] != genuine["from_host"]:
        reasons.append(f"by-host {forged['by_host']} != from-host {genuine['from_host']}")
    if client_ip not in forged["ips"]:
        reasons.append("forged by-clause does not contain the client IP")
    elif forged["ips"][-1] != client_ip:
        reasons.append("client IP is not the by-address of the forged hop")
    if genuine and forged["protocol"] != genuine["protocol"]:
        reasons.append(f"protocol {forged['protocol']} != {genuine['protocol']}")
    gt = _time(genuine) if genuine else None
    ft = _time(forged)
    if gt is None or ft is None:
        reasons.append("could not parse Received dates")
    elif not ft < gt:
        reasons.append("forged hop is not earlier than the genuine hop")
    earlier = None
    idx = headers.index(genuine) if genuine in headers else -1
    if idx >= 0 and idx + 2 < len(headers):
        earlier = headers[idx + 2]
        et = _time(earlier)
        if et is None or ft is None or not et < ft:
            reasons.append("forged hops are not strictly increasing in time")
        if earlier["ips"][:2] != ["203.0.113.10", "203.0.113.11"] and "203.0.113.10" not in earlier["ips"]:
            reasons.append("earlier forged hop is not in RFC 5737 TEST-NET-3")
    else:
        reasons.append("missing the earlier forged hop")
    forbidden = [ip for ip in sum((h["ips"] for h in headers), []) if ip.startswith("192.0.113.")]
    if forbidden:
        reasons.append("non-RFC5737 192.0.113 address present")
    return {
        "join_ok": not reasons,
        "reasons": reasons,
        "genuine": genuine,
        "forged_below": forged,
        "earlier_forged": earlier,
        "received": headers,
    }
