#!/usr/bin/env python3
"""Collect results/phase3c/*.json into results/phase3c/parser_matrix.csv."""
import csv
import glob
import json
import os

BASE = os.path.join(os.path.dirname(__file__), "..", "results", "phase3c")
OUT = os.path.join(BASE, "parser_matrix.csv")
FIELDS = ["case_id", "parser", "version", "parse_error", "defects", "header_entries",
          "received_count", "from_present", "subject_present", "message_id_present",
          "from_in_body", "subject_in_body"]

rows = []
for path in sorted(glob.glob(os.path.join(BASE, "V*.json"))):
    try:
        with open(path) as f:
            d = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"warning: skipping {path}: {e}")
        continue
    rows.append({
        "case_id": d.get("_case"),
        "parser": d.get("parser"),
        "version": d.get("version"),
        "parse_error": d.get("parse_error") or "",
        "defects": ";".join(d.get("defects") or []),
        "header_entries": d.get("header_entries"),
        "received_count": d.get("received_count"),
        "from_present": d.get("from_present"),
        "subject_present": d.get("subject_present"),
        "message_id_present": d.get("message_id_present"),
        "from_in_body": d.get("from_in_body"),
        "subject_in_body": d.get("subject_in_body"),
    })

with open(OUT, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=FIELDS)
    w.writeheader()
    w.writerows(rows)
print(f"parser_matrix.csv: {len(rows)} rows -> {OUT}")
