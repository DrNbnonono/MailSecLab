import json
from pathlib import Path
rows = json.loads(Path("/mnt/e/MailSecLab/received-lab/results/research/w1-20261001a/fuzz/minimized/report.json").read_text())
print("classes", len(rows))
for row in rows:
    c = row["candidates"]
    print(row["statuses"], "n", len(c),
          "minimal", sum(1 for x in c if x.get("minimal")),
          "sig", sum(1 for x in c if x.get("signature_matches_parent")),
          "repro", sum(1 for x in c if x.get("split_reproduced")))
