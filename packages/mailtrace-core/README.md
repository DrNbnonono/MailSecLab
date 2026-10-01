# mailtrace-core

Offline email header investigation library and CLI, with byte-preserving
header evidence, Received route/timing analysis and reported authentication
results. Requires Python 3.11+ and Pydantic 2.

```python
from mailtrace import analyze

report = analyze(raw_email_bytes)
print(report.route)
print(report.model_dump_json(by_alias=True, indent=2))
```

```text
mailtrace analyze sample.eml
mailtrace analyze sample.eml --json
mailtrace analyze sample.eml --chain-limit 50
```

Header assertions are not actively verified. The library performs no DNS
queries, sends no mail, and writes no input files. CLI input is limited to
10 MiB; the library does not silently truncate input. The full repository
contains synthetic samples, tests, and the versioned report contract.
