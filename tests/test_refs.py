#!/usr/bin/env python3
"""Ref pinning tests: tag, branch, commit, unknown ref, ref+since, map --ref, and the rescan image choice.

Hermetic: builds a local repository and scans it through a file:// git URL, so no network is used.
"""
import json, subprocess, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import repobeagle as rb

fail = 0
def check(name, ok):
    global fail
    print(("PASS " if ok else "FAIL ") + name)
    if not ok:
        fail = 1

def git(cwd, *args, ok=True):
    r = subprocess.run(["git", "-C", str(cwd)] + list(args), capture_output=True, text=True, timeout=120)
    if ok and r.returncode != 0:
        raise RuntimeError(r.stderr)
    return r.stdout.strip()

def scan(url, *extra):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        out = Path(fh.name)
    try:
        r = subprocess.run([sys.executable, str(ROOT / "repobeagle.py"), "scan", url, "--no-docker",
                            "--no-osv", "--no-trust", "--no-color", "--json", str(out)] + list(extra),
                           capture_output=True, text=True, timeout=900)
        try:
            return json.loads(out.read_text(encoding="utf-8")), r
        except ValueError:
            return {}, r
    finally:
        out.unlink(missing_ok=True)

with tempfile.TemporaryDirectory() as td:
    repo = Path(td) / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.email", "test@example.invalid")
    git(repo, "config", "user.name", "test")
    (repo / "old.py").write_text('OLD = "https://old.example.org"\n')
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "v0")
    git(repo, "tag", "-a", "v0", "-m", "v0")
    (repo / "new.py").write_text('NEW = "https://new.example.org"\n')
    git(repo, "add", "new.py")
    git(repo, "commit", "-qm", "v1")
    git(repo, "tag", "-a", "v1", "-m", "v1")
    git(repo, "checkout", "-qb", "feature", "HEAD~1")
    (repo / "feat.py").write_text('FEATURE = "https://feature.example.org"\n')
    git(repo, "add", "feat.py")
    git(repo, "commit", "-qm", "feature")
    git(repo, "checkout", "-q", "main")
    c0 = git(repo, "rev-parse", "v0^{commit}")
    c1 = git(repo, "rev-parse", "v1^{commit}")
    cf = git(repo, "rev-parse", "feature^{commit}")
    url = f"file://{repo}"

    report, r = scan(url, "--ref", "v1")
    check("tag ref pins the tag's commit",
          r.returncode == 0 and report["meta"]["ref"] == "v1" and report["meta"]["commit"] == c1)
    report, r = scan(url, "--ref", "feature")
    check("branch ref pins the branch tip",
          r.returncode == 0 and report["meta"]["ref"] == "feature" and report["meta"]["commit"] == cf)
    report, r = scan(url, "--ref", c0)
    check("commit ref pins exactly that commit",
          r.returncode == 0 and report["meta"]["ref"] == c0 and report["meta"]["commit"] == c0)
    report, r = scan(url, "--ref", "does-not-exist")
    check("unknown ref fails loudly", r.returncode != 0 and "couldn't find remote ref" in r.stderr + r.stdout)

    report, r = scan(url, "--ref", "v1", "--since", "v0")
    scope = report["meta"].get("scope") or {}
    check("ref+since pins the commit and scopes the diff",
          r.returncode == 0 and report["meta"]["commit"] == c1 and scope.get("scope") == "changed"
          and scope.get("since") == "v0" and scope.get("changed_files", 0) >= 1
          and 0 < scope.get("checked_out", 0) < scope.get("listed_files", 0))

    def mapped(*extra):
        r = subprocess.run([sys.executable, str(ROOT / "repobeagle.py"), "map", url, "--no-docker"] + list(extra),
                           capture_output=True, text=True, timeout=900)
        return r.stdout
    v0map, v1map = mapped("--ref", "v0"), mapped("--ref", "v1")
    # v0 contains only old.py; v1 adds new.py but keeps old.py
    check("map --ref renders the requested revision",
          "old.example.org" in v0map and "new.example.org" not in v0map
          and "new.example.org" in v1map)
    if "new.example.org" in v0map:
        print("  v0 map:", v0map.replace("\n", " | ")[:300])

    check("local directories still reject --ref",
          scan(str(repo), "--ref", "v0")[1].returncode != 0)

# web has no git ref: a single URL, and its report says so
with tempfile.TemporaryDirectory() as td:
    page = Path(td) / "page.html"
    page.write_text("<html><body>hello</body></html>")
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        out = Path(fh.name)
    try:
        r = subprocess.run([sys.executable, str(ROOT / "repobeagle.py"), "web", f"file://{page}",
                            "--json", str(out), "--no-color"], capture_output=True, text=True, timeout=600)
        meta = (json.loads(out.read_text()) or {}).get("meta") or {}
        check("web reports carry no git ref", r.returncode in (0, 1) and meta.get("ref") is None)
        bad = subprocess.run([sys.executable, str(ROOT / "repobeagle.py"), "web", f"file://{page}", "--ref", "v1"],
                              capture_output=True, text=True, timeout=60)
        check("web does not accept --ref", bad.returncode == 2)
    finally:
        out.unlink(missing_ok=True)

# the rescan image choice: the report's image when recorded, this install's otherwise (with a caveat)
img, note = rb.rescan_image({"image_ref": "ghcr.io/example/repobeagle:v1.2.3"})
check("rescan prefers the report's image", img == "ghcr.io/example/repobeagle:v1.2.3" and "report's image" in note)
img, note = rb.rescan_image({})
check("rescan falls back to the current image with a caveat", img == rb.IMAGE and "may differ" in note)
check("local image digest helper normalizes or skips",
      rb._local_image_digest("ghcr.io/javierbits/repobeagle:does-not-exist") in (None,)
      or rb._local_image_digest("ghcr.io/javierbits/repobeagle:does-not-exist").startswith("sha256:"))

sys.exit(fail)
