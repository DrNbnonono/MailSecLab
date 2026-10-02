"""Docker wrappers that refuse to touch the historical stack."""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

RESEARCH = Path(__file__).resolve().parents[1]
LAB = RESEARCH.parent
COMPOSE = RESEARCH / "docker-compose.yml"
PROJECT = "mailseclab-research"
ALLOWED = ("msl-",)


class DockerError(RuntimeError):
    pass


def _run(args: list[str], timeout: int = 120, check: bool = True, env: dict | None = None) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        args,
        cwd=str(RESEARCH),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        env=env,
        check=False,
    )
    if check and proc.returncode != 0:
        raise DockerError(
            f"command failed ({proc.returncode}): {' '.join(args)}\n"
            f"stdout:\n{proc.stdout[-4000:]}\nstderr:\n{proc.stderr[-4000:]}"
        )
    return proc


def compose_env(run_id: str) -> dict:
    import os
    env = os.environ.copy()
    env["RUN_ID"] = run_id
    env["COMPOSE_PROJECT_NAME"] = PROJECT
    return env


def compose(run_id: str, args: list[str], timeout: int = 1800) -> subprocess.CompletedProcess:
    cmd = [
        "docker", "compose",
        "-p", PROJECT,
        "-f", str(COMPOSE),
        *args,
    ]
    return _run(cmd, timeout=timeout, env=compose_env(run_id))


def assert_research_name(name: str) -> None:
    if not name.startswith(ALLOWED):
        raise DockerError(f"refusing to touch non-research container {name}")


def inspect_states() -> dict[str, str]:
    proc = _run(["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Status}}"], check=True)
    out = {}
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        name, status = line.split("\t", 1)
        out[name] = status
    return out


def legacy_is_running() -> list[str]:
    bad = []
    for name, status in inspect_states().items():
        if name.startswith(ALLOWED):
            continue
        if status.startswith("Up"):
            if name in {"postfix1", "postfix2", "postfix3", "mailpit", "mail-client", "rspamd", "dns", "exim", "opensmtpd"} or name.startswith("postfix"):
                bad.append(f"{name} {status}")
    return bad


def docker_exec(name: str, args: list[str], timeout: int = 120, stdin: bytes | None = None) -> subprocess.CompletedProcess:
    assert_research_name(name)
    cmd = ["docker", "exec"]
    if stdin is not None:
        cmd.append("-i")
    cmd.extend([name, *args])
    proc = subprocess.run(
        cmd,
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    proc.stdout_text = proc.stdout.decode("utf-8", "replace") if isinstance(proc.stdout, bytes) else (proc.stdout or "")
    proc.stderr_text = proc.stderr.decode("utf-8", "replace") if isinstance(proc.stderr, bytes) else (proc.stderr or "")
    return proc


def docker_logs(name: str, since: int | None = None) -> str:
    assert_research_name(name)
    cmd = ["docker", "logs"]
    if since is not None:
        cmd.extend(["--since", str(since)])
    cmd.append(name)
    proc = _run(cmd, timeout=60, check=False)
    return (proc.stdout or "") + (proc.stderr or "")


def wait_healthy(run_id: str, timeout: int = 90) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        proc = compose(run_id, ["ps", "--format", "json"], timeout=30)
        if proc.returncode == 0 and "healthy" in proc.stdout:
            return
        time.sleep(2)
    raise DockerError("dns did not become healthy")


def image_inspect(ref: str) -> dict:
    proc = _run(["docker", "image", "inspect", ref], check=False)
    if proc.returncode != 0:
        return {"error": proc.stderr.strip()}
    data = json.loads(proc.stdout)[0]
    return {
        "id": data.get("Id"),
        "repo_digests": data.get("RepoDigests"),
        "repo_tags": data.get("RepoTags"),
        "created": data.get("Created"),
    }
