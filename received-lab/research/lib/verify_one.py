#!/usr/bin/env python3
"""Run one verifier on one file and print a JSON verdict."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def perl_feed(raw: bytes) -> bytes:
    if raw == b"":
        return b""
    text = raw.decode("latin1")
    parts = []
    buf = ""
    for ch in text:
        buf += ch
        if ch == "\n":
            parts.append(buf)
            buf = ""
    if buf:
        parts.append(buf)
    fed = []
    for line in parts:
        if line.endswith("\r\n"):
            line = line[:-2]
        elif line.endswith("\n") or line.endswith("\r"):
            line = line[:-1]
        fed.append(line + "\r\n")
    return "".join(fed).encode("latin1")


def classify_text(kind: str, text: str, rc: int) -> str:
    low = text.lower()
    if "timed out" in low or "timeout" in low:
        return "timeout"
    if kind == "perl":
        for line in text.splitlines():
            if line.startswith("result:"):
                raw = line.split(":", 1)[1].strip().lower()
                return {
                    "pass": "pass",
                    "fail": "fail",
                    "none": "none",
                    "invalid": "parse-error",
                    "temperror": "temp-error",
                    "permerror": "fail",
                }.get(raw, "tool-error")
        return "tool-error"
    if kind == "dkimpy":
        if "status: pass" in low:
            return "pass"
        if "status: fail" in low:
            return "fail"
        if "status: none" in low:
            return "none"
        if "status: temp-error" in low:
            return "temp-error"
        if "status: parse-error" in low:
            return "parse-error"
        return "tool-error"
    if "invalid signature" in low or "did not verify" in low:
        return "fail"
    if "valid signature" in low:
        return "pass"
    if "no signature" in low or "no signatures" in low:
        return "none"
    if "temperror" in low or "temporary" in low:
        return "temp-error"
    if "permerror" in low:
        return "fail"
    if "syntax" in low or "parse error" in low:
        return "parse-error"
    lines = [ln.strip().lower() for ln in text.splitlines() if ln.strip()]
    if any(ln == "pass" or ln.startswith("pass ") for ln in lines):
        return "pass"
    if any(ln.startswith("fail") or "bad signature" in ln or "verification failed" in ln for ln in lines):
        return "fail"
    if rc != 0:
        return "tool-error"
    if not text.strip():
        return "none"
    return "tool-error"


def run_dkimpy(raw: bytes) -> tuple[str, str]:
    import dns.resolver
    import dkim
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    resolver.timeout = 3
    dns.resolver.default_resolver = resolver
    if b"dkim-signature:" not in raw.lower():
        return "status: none\nno DKIM-Signature header\n", ""
    try:
        ok = dkim.verify(raw)
        if ok:
            return "status: pass\n", ""
        return "status: fail\n", ""
    except Exception as exc:
        msg = f"{type(exc).__name__}: {exc}"
        low = msg.lower()
        if "no signature" in low or "no signatures" in low:
            return "status: none\n" + msg + "\n", ""
        if "servfail" in low or "timeout" in low or "temp" in low or "try again" in low:
            return "status: temp-error\n" + msg + "\n", ""
        if "syntax" in low or "format" in low or "header" in low and "parse" in low:
            return "status: parse-error\n" + msg + "\n", ""
        if "fail" in low or "signature" in low or "key" in low or "body" in low or "hash" in low or "public" in low:
            return "status: fail\n" + msg + "\n", ""
        return "status: tool-error\n" + msg + "\n", ""


def main() -> int:
    kind, path = sys.argv[1], sys.argv[2]
    raw = open(path, "rb").read()
    fed = perl_feed(raw)
    record = {
        "tool": kind,
        "input_sha256": sha256(raw),
        "input_len": len(raw),
        "perl_feed_sha256": sha256(fed),
        "perl_normalization": "identity" if fed == raw else "newline-rewritten",
    }
    if kind == "dkimpy":
        out, err = run_dkimpy(raw)
        rc = 0
    elif kind == "perl":
        proc = subprocess.run(
            ["perl", "/usr/local/bin/verify_perl.pl"],
            input=raw,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        out = proc.stdout.decode("utf-8", "replace")
        err = proc.stderr.decode("utf-8", "replace")
        rc = proc.returncode
        for line in out.splitlines():
            if line.startswith("fed_sha256:"):
                record["library_fed_sha256"] = line.split(":", 1)[1].strip()
            if line.startswith("normalization:"):
                record["library_normalization"] = line.split(":", 1)[1].strip()
    elif kind == "go":
        proc = subprocess.run(
            ["dkim-verify"],
            input=raw,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        out = proc.stdout.decode("utf-8", "replace")
        err = proc.stderr.decode("utf-8", "replace")
        rc = proc.returncode
    else:
        raise SystemExit(f"unknown tool {kind}")
    record["stdout"] = out
    record["stderr"] = err
    record["exit_code"] = rc
    record["status"] = classify_text(kind, out + "\n" + err, rc)
    print(json.dumps(record))
    return 0


if __name__ == "__main__":
    sys.exit(main())
