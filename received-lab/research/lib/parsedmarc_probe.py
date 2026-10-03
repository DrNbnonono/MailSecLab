"""Task 9c: DMARC aggregate-report consumer probe (parsedmarc 11.0.3).

Three XML reports fed to the de-facto consumer library:
  legit    well-formed report about the lab victim domain, from a plausible
           receiver org, rows matching real lab observations
  forged   attacker-crafted: impersonated reporter org (Google), fabricated
           rows (spoofed source IP, inflated count, fake policy_published),
           never sent by any real receiver
  broken   w2 hand-built reference XML (date_range=0 placeholders)

Question: does the consumer verify report ORIGIN at all? RFC 7489/9989
aggregate reports carry no authentication; measurement anchors the
poisoning primitive at the consumer level.
"""
import json
import sys
from pathlib import Path

OUT = Path("/evidence/w3-20261003a/parsedmarc-probe")
OUT.mkdir(parents=True, exist_ok=True)

LEGIT = """<?xml version="1.0" encoding="UTF-8"?>
<feedback>
 <report_metadata>
  <org_name>receiver.example</org_name>
  <email>dmarc@receiver.example</email>
  <extra_contact_info>dmarc-help@receiver.example</extra_contact_info>
  <report_id>legit-20261003-001</report_id>
  <date_range><begin>1790900000</begin><end>1790986400</end></date_range>
 </report_metadata>
 <policy_published>
  <domain>xn--mnchen-3ya.bank.test</domain><adkim>r</adkim><aspf>r</aspf>
  <p>reject</p><sp>reject</sp><pct>100</pct>
 </policy_published>
 <record>
  <row>
   <source_ip>10.88.0.11</source_ip><count>3</count>
   <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
  </row>
  <identifiers><header_from>xn--mnchen-3ya.bank.test</header_from></identifiers>
  <auth_results>
   <dkim><domain>xn--mnchen-3ya.bank.test</domain><result>fail</result></dkim>
   <spf><domain>lab.test</domain><result>fail</result></spf>
  </auth_results>
 </record>
</feedback>"""

FORGED = """<?xml version="1.0" encoding="UTF-8"?>
<feedback>
 <report_metadata>
  <org_name>Google, Inc.</org_name>
  <email>noreply-dmarc-support@google.com</email>
  <report_id>9764825170338712501</report_id>
  <date_range><begin>1790900000</begin><end>1790986400</end></date_range>
 </report_metadata>
 <policy_published>
  <domain>xn--mnchen-3ya.bank.test</domain><adkim>r</adkim><aspf>r</aspf>
  <p>reject</p><sp>reject</sp><pct>100</pct>
 </policy_published>
 <record>
  <row>
   <source_ip>198.51.100.66</source_ip><count>5000</count>
   <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
  </row>
  <identifiers><header_from>xn--mnchen-3ya.bank.test</header_from></identifiers>
  <auth_results>
   <dkim><domain>xn--mnchen-3ya.bank.test</domain><result>fail</result></dkim>
   <spf><domain>xn--mnchen-3ya.bank.test</domain><result>fail</result></spf>
  </auth_results>
 </record>
</feedback>"""


def main() -> None:
    import parsedmarc

    cases = {}
    broken_path = Path("/evidence/w2-20261002a/rua/reference-aggregate.xn--mnchen-3ya.lab.test.xml")
    bodies = {"legit": LEGIT.encode(), "forged": FORGED.encode()}
    if broken_path.exists():
        bodies["broken"] = broken_path.read_bytes()

    results = {}
    for name, xml_bytes in bodies.items():
        (OUT / f"{name}.xml").write_bytes(xml_bytes)
        try:
            report = parsedmarc.parse_aggregate_report_xml(xml_bytes, offline=True)
            d = report.model_dump() if hasattr(report, "model_dump") else report
            results[name] = {
                "accepted": True,
                "org_name": d["report_metadata"]["org_name"],
                "org_email": d["report_metadata"]["org_email"],
                "domain": d["policy_published"]["domain"],
                "rows": [
                    {
                        "source_ip": r["source"]["ip_address"],
                        "count": r["count"],
                        "disposition": r["policy_evaluated"]["disposition"],
                    }
                    for r in d.get("records", [])
                ],
            }
        except Exception as exc:
            results[name] = {"accepted": False, "error": f"{type(exc).__name__}: {exc}"[:200]}
        print(json.dumps({"case": name, "result": results[name]}, ensure_ascii=False), flush=True)

    (OUT / "probe.json").write_text(
        json.dumps({"parsedmarc_version": parsedmarc.__version__, "results": results},
                   ensure_ascii=False, indent=1), encoding="utf-8")
    verdict = {
        "legit": results["legit"]["accepted"],
        "forged": results["forged"]["accepted"],
        "origin_verification_seen": any(
            "auth" in k.lower() or "verify" in k.lower()
            for r in [results["forged"]] if r.get("accepted")
            for k in r
        ),
    }
    (OUT / "verdict.json").write_text(json.dumps(verdict, indent=1), encoding="utf-8")
    print(json.dumps(verdict))


if __name__ == "__main__":
    main()
