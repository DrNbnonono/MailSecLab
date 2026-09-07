#!/usr/bin/env python3
"""Fetch a docker image by digest WITHOUT daemon network access, in two phases.

  download (Windows side): python pull_image.py download <repo> <digest> <tag>
      fetches root manifest (verifies digest), resolves linux/amd64 child,
      downloads config + layers (verifies every sha256) into ./imgpull/<name>/
  load (WSL side):         python pull_image.py load <repo> <digest> <tag>
      assembles a docker-archive with RepoTags [<tag>] and runs docker load.

repo example: library/debian   digest example: sha256:abcd...   tag: debian:sid
"""
import hashlib, io, json, os, subprocess, sys, tarfile, urllib.request, urllib.parse

REG = "https://docker.m.daocloud.io"
UA = {"User-Agent": "docker/28.5.1 python-puller"}
ACCEPT = ", ".join([
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
])

def req(url, headers=None, data=None):
    h = dict(UA); h.update(headers or {})
    return urllib.request.urlopen(urllib.request.Request(url, headers=h, data=data), timeout=180)

def sha(b): return "sha256:" + hashlib.sha256(b).hexdigest()

def get_token(repo):
    realm, service, wa = None, None, ""
    try:
        req(f"{REG}/v2/")
    except urllib.error.HTTPError as e:
        wa = e.headers.get("WWW-Authenticate", "")
        parts = dict(p.strip().split("=", 1) for p in wa.split(",") if "=" in p)
        realm = parts.get("Bearer realm", "").strip('"')
        service = parts.get("service", "").strip('"')
    assert realm, f"no WWW-Authenticate realm in {wa!r}"
    url = f"{realm}?service={urllib.parse.quote(service)}&scope=repository:{repo}:pull"
    for attempt in range(5):
        try:
            with req(url) as r:
                d = json.load(r)
                return d.get("token") or d.get("access_token")
        except Exception as e:
            print(f"  token retry {attempt+1}: {e}")
    raise SystemExit("token failed")

def fetch(url, headers, dest=None):
    for attempt in range(5):
        try:
            with req(url, headers) as r:
                b = r.read()
            if dest:
                open(dest, "wb").write(b)
            return b
        except Exception as e:
            print(f"  retry {attempt+1}: {e}")
    raise SystemExit(f"fetch failed: {url}")

def workdir(name):
    d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "imgpull", name)
    os.makedirs(d, exist_ok=True)
    return d

def download(repo, digest, tag):
    name = repo.split("/")[-1] + "_" + digest.split(":")[1][:10]
    w = workdir(name)
    tok = get_token(repo)
    auth = {"Authorization": f"Bearer {tok}"}
    print(f"[*] {repo}@{digest} -> {w}")
    mb = fetch(f"{REG}/v2/{repo}/manifests/{digest}", {**auth, "Accept": ACCEPT}, os.path.join(w, "root_manifest.json"))
    assert sha(mb) == digest, "root manifest digest mismatch"
    m = json.loads(mb)
    if "manifests" in m:
        c = next(x for x in m["manifests"] if x.get("platform", {}).get("architecture") == "amd64" and x.get("platform", {}).get("os") == "linux")
        print(f"[*] list -> linux/amd64 {c['digest']}")
        mb = fetch(f"{REG}/v2/{repo}/manifests/{c['digest']}", {**auth, "Accept": ACCEPT}, os.path.join(w, "amd64_manifest.json"))
        assert sha(mb) == c["digest"]
        m = json.loads(mb)
    assert "layers" in m, f"unexpected: {list(m)}"
    cfg_d = m["config"]["digest"]
    print(f"[*] config {cfg_d[:24]}, {len(m['layers'])} layers")
    fetch(f"{REG}/v2/{repo}/blobs/{cfg_d}", auth, os.path.join(w, "config.json"))
    assert sha(open(os.path.join(w, "config.json"), "rb").read()) == cfg_d
    for i, l in enumerate(m["layers"]):
        d = l["digest"]; fn = os.path.join(w, f"layer_{i}.tar")
        if os.path.exists(fn) and sha(open(fn, "rb").read()) == d:
            print(f"  layer {i} cached"); continue
        print(f"  layer {i}: {l['size']/1e6:.1f} MB ...")
        fetch(f"{REG}/v2/{repo}/blobs/{d}", auth, fn)
        assert sha(open(fn, "rb").read()) == d, f"layer {i} mismatch"
    json.dump({"repo": repo, "digest": digest, "tag": tag, "manifest": m}, open(os.path.join(w, "meta.json"), "w"))
    print("[*] download complete")

def load(repo, digest, tag):
    name = repo.split("/")[-1] + "_" + digest.split(":")[1][:10]
    w = workdir(name)
    meta = json.load(open(os.path.join(w, "meta.json")))
    m = meta["manifest"]
    cfg_name = m["config"]["digest"].split(":")[1] + ".json"
    layers = [f"layer_{i}.tar" for i in range(len(m["layers"]))]
    out = os.path.join(w, "image.tar")
    with tarfile.open(out, "w") as tf:
        tf.add(os.path.join(w, "config.json"), arcname=cfg_name)
        for lf in layers:
            tf.add(os.path.join(w, lf), arcname=lf)
        mj = json.dumps([{"Config": cfg_name, "RepoTags": [tag], "Layers": layers}]).encode()
        ti = tarfile.TarInfo("manifest.json"); ti.size = len(mj)
        tf.addfile(ti, io.BytesIO(mj))
    print(f"[*] docker load {tag} ...")
    subprocess.run(["docker", "load", "-i", out], check=True)
    subprocess.run(["docker", "images", tag.split(":")[0]], check=True)

if __name__ == "__main__":
    mode, repo, digest, tag = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    {"download": download, "load": load}[mode](repo, digest, tag)
