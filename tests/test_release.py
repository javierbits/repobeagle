#!/usr/bin/env python3
"""release: semantic artifact-vs-repo drift, provenance evidence, offline overrides (no network)."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures" / "release"
fail = 0


def check(name, ok, detail=""):
    global fail
    print(("PASS " if ok else "FAIL ") + name + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        fail = 1


def run(tarball, registry, out=None):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        js = Path(fh.name)
    argv = [sys.executable, "repobeagle.py", "release", "acme/demo", "--tag", "v1.0.0",
            "--repo", str(FIX / "repo"), "--tarball", str(tarball),
            "--registry-json", str(registry), "--json", str(js)]
    r = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=120)
    doc = json.loads(js.read_text(encoding="utf-8")) if js.exists() else {}
    js.unlink(missing_ok=True)
    return r, doc


r, doc = run(FIX / "drift.tgz", FIX / "registry-npm.json")
titles = [f["title"] for f in doc.get("findings") or []]
check("an artifact with an injected postinstall is DRIFT", r.returncode == 1 and doc.get("verdict") == "DRIFT",
      (r.stderr or r.stdout)[-400:])
check("the drift finding names the added hook and dependency",
      any(t.startswith("release-drift: artifact adds install hook postinstall") for t in titles)
      and any(t.startswith("release-drift: artifact adds dependency evil-dep") for t in titles),
      str(titles))
check("drift findings are high severity",
      {f["severity"] for f in doc["findings"] if f["title"].startswith("release-drift")} == {"high"})
check("the semantic summary keeps repo and artifact manifests",
      doc["repo"]["deps"] == {"left-pad": "^1.0.0"} and doc["artifact"]["deps"].get("evil-dep") == "^2.0.0",
      json.dumps({"repo": doc["repo"]["deps"], "artifact": doc["artifact"]["deps"]})[:300])

r, doc = run(FIX / "clean.tgz", FIX / "registry-npm.json")
titles = [f["title"] for f in doc.get("findings") or []]
check("an identical artifact produces no release-drift", r.returncode == 0 and doc.get("verdict") == "CONSISTENT"
      and not any(t.startswith("release-drift") for t in titles), str(titles))
check("registry attestations are reported as provenance evidence",
      any(t.startswith("release-provenance:") for t in titles), str(titles))

r, doc = run(FIX / "clean.tgz", FIX / "registry-npm-unsigned.json")
check("missing attestations produce a low no-provenance finding",
      r.returncode == 0 and any(f["title"].startswith("no-provenance") and f["severity"] == "low"
                                for f in doc.get("findings") or []),
      json.dumps(doc.get("findings"))[:300])

# A mismatched registry version (tarball says 1.0.0, registry says 0.9.9) must be explicit.
registry = json.loads((FIX / "registry-npm.json").read_text(encoding="utf-8"))
registry["dist-tags"]["latest"] = "0.9.9"
registry["versions"]["0.9.9"] = {"name": "acme-demo", "version": "0.9.9", "dist": {"tarball": "https://example.invalid/x.tgz"}}
with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as fh:
    json.dump(registry, fh)
    alt = Path(fh.name)
try:
    r, doc = run(FIX / "clean.tgz", alt)
finally:
    alt.unlink(missing_ok=True)
check("a version mismatch is a high release-drift",
      r.returncode == 1 and any(f["title"].startswith("release-drift: registry lists 0.9.9")
                                for f in doc.get("findings") or []),
      json.dumps(doc.get("findings"))[:300])

sys.exit(fail)
