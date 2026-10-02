# research

Approved eight-week line, executed from an isolated Compose project. Historical `received-lab` containers, Mailpit volume, RECORD files and DKIM keys are not inputs to this stack and are not overwritten.

Week 1 entry, from WSL:

```text
cd /mnt/e/MailSecLab/received-lab
python3 research/run.py --stage bootstrap --run-id <id>
```

Artifacts go to `received-lab/results/research/<id>/`. The web port is `127.0.0.1:18025`. Container CPU and memory limits sum to 3.3 CPUs and 3840 MiB.

`causal`, `e2e`, `fuzz`, `defense` and `report` refuse to start until the previous stage has a `gate.json`.
