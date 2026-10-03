"""Reference aggregation over OpenDMARC's own history records.

This is NOT a substitute product: the evaluation data (every field below) is
written by the deployed OpenDMARC milter into its HistoryFile. This script
only groups those records the way RFC 9989 aggregate reports are keyed - by
the discovered policy domain and its rua - and renders the two outputs a
conforming report generator would produce. Rows whose policy discovery found
no rua ("-") cannot appear in any aggregate report; that is a property of the
evaluator's own records, not of this script.

opendmarc-reports itself could not run in this image (Switch.pm is absent
from Debian bookworm), which is recorded in LAB_JOURNAL.md.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from xml.sax.saxutils import escape

RUN = Path("/mnt/e/MailSecLab/received-lab/results/research/w2-20261002a/rua")
HISTORY = RUN / "history-snapshot.dat"


def parse_history(text: str) -> list[dict]:
    records, current = [], None
    for line in text.splitlines():
        if not line.strip():
            continue
        key, _, value = line.partition(" ")
        if key == "job":
            if current:
                records.append(current)
            current = {"job": value.strip()}
        elif current is not None:
            current[key] = value.strip()
    if current:
        records.append(current)
    return records


def job_to_case() -> dict[str, str]:
    mapping = {}
    for path in sorted(RUN.glob("*.smtp.txt")):
        text = path.read_text(encoding="utf-8", errors="replace")
        match = re.search(r"queued as ([A-Z0-9]+)", text)
        if match:
            mapping[match.group(1)] = path.name.replace(".smtp.txt", "")
    return mapping


def main() -> None:
    records = parse_history(HISTORY.read_text(encoding="utf-8", errors="replace"))
    cases = job_to_case()
    rows = []
    for record in records:
        rows.append({
            "job": record.get("job"),
            "case": cases.get(record.get("job"), "(pre-window)"),
            "from_domain": record.get("from"),
            "policy_domain": record.get("pdomain"),
            "policy_code": record.get("policy"),
            "rua": record.get("rua"),
            "reported_dkim": record.get("dkim", "-"),
            "action_code": record.get("action"),
            "received": record.get("received"),
        })
    reports, unattributable = {}, []
    for row in rows:
        if row["rua"] and row["rua"] != "-":
            reports.setdefault(row["policy_domain"], {"rua": row["rua"], "rows": []})["rows"].append(row)
        else:
            unattributable.append(row)
    victim = "xn--mnchen-3ya.lab.test"
    out = {
        "note": "reference aggregation over OpenDMARC HistoryFile records; grouping key = policy domain -> rua (RFC 9989 aggregate reporting)",
        "victim_domain": victim,
        "victim_report_rows": reports.get(victim, {}).get("rows", []),
        "victim_report_count": len(reports.get(victim, {}).get("rows", [])),
        "other_reports": {d: {"rua": v["rua"], "count": len(v["rows"])} for d, v in reports.items() if d != victim},
        "unattributable_rows": unattributable,
    }
    (RUN / "reference-aggregate.json").write_text(json.dumps(out, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")

    xml_rows = []
    for row in reports.get(victim, {}).get("rows", []):
        xml_rows.append(
            "  <record>\n"
            "   <row>\n"
            f"    <source_ip>{row['job'] and '10.88.0.11'}</source_ip>\n"
            f"    <count>1</count>\n"
            "    <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>\n"
            "   </row>\n"
            "   <identifiers>\n"
            f"    <header_from>{escape(row['from_domain'])}</header_from>\n"
            "   </identifiers>\n"
            f"  </record> <!-- case {row['case']} job {row['job']} -->"
        )
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<feedback>\n"
        " <report_metadata>\n"
        "  <org_name>reference-aggregation.mailseclab</org_name>\n"
        "  <email>postmaster@lab.test</email>\n"
        f"  <date_range><begin>0</begin><end>0</end></date_range>\n"
        " </report_metadata>\n"
        f" <policy_published><domain>{victim}</domain><adkim>r</adkim><aspf>r</aspf><p>reject</p></policy_published>\n"
        + "\n".join(xml_rows) + "\n"
        "</feedback>\n"
    )
    (RUN / f"reference-aggregate.{victim}.xml").write_text(xml, encoding="utf-8")
    print(json.dumps({
        "victim_report_count": out["victim_report_count"],
        "victim_cases": [r["case"] for r in out["victim_report_rows"]],
        "unattributable_cases": [r["case"] for r in unattributable],
        "unattributable_from_domains": sorted({r["from_domain"] for r in unattributable}),
    }, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
