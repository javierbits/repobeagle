#!/usr/bin/env python3
"""`repobeagle fix` tests: dry-run immutability, pinning, write-all rewrite, idempotence, re-scan improvement."""
import hashlib, json, os, shutil, subprocess, sys, tempfile
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

PINS = {"actions/checkout@v4": "0123456789abcdef0123456789abcdef01234567",
        "actions/github-script@v7": "89abcdef0123456789abcdef0123456789abcdef"}

def run(args, timeout=900):
    return subprocess.run([sys.executable, str(ROOT / "repobeagle.py")] + args,
                           capture_output=True, text=True, timeout=timeout)

def snapshot(repo):
    return {p.relative_to(repo).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted((repo / ".github" / "workflows").glob("*.yml"))}

def scan(repo):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        out = Path(fh.name)
    try:
        subprocess.run([sys.executable, str(ROOT / "repobeagle.py"), "scan", str(repo), "--no-docker",
                        "--no-osv", "--no-trust", "--no-color", "--json", str(out)],
                       capture_output=True, text=True, timeout=900)
        return json.loads(out.read_text(encoding="utf-8"))
    finally:
        out.unlink(missing_ok=True)

with tempfile.TemporaryDirectory() as td:
    repo = Path(td) / "trap-gha"
    shutil.copytree(ROOT / "tests" / "fixtures" / "trap-gha", repo)
    (repo / ".github" / "workflows" / "release.yml").write_text(
        "name: release\non: push\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n    steps:\n      - run: echo ok\n")
    pins = Path(td) / "pins.json"
    pins.write_text(json.dumps(PINS))
    before = snapshot(repo)
    before_scan = scan(repo)
    before_rules = {f["title"].split(":")[0] for f in before_scan["findings"]}

    # dry-run must print the diff and mutate nothing
    out = Path(td) / "dry.json"
    dry = run(["fix", str(repo), "--dry-run", "--pins", str(pins), "--json", str(out)])
    dry_report = json.loads(out.read_text())
    check("dry-run exits 0 and reports the changes", dry.returncode == 0 and dry_report["dry_run"] is True
          and set(dry_report["changed_files"]) == {".github/workflows/after.yml", ".github/workflows/ci.yml"})
    check("dry-run prints a unified diff", "--- a/.github/workflows/ci.yml" in dry.stdout
          and "+permissions:" in dry.stdout)
    check("dry-run mutates nothing", snapshot(repo) == before)

    # the real run pins both actions and rewrites write-all
    out = Path(td) / "fix.json"
    fixed = run(["fix", str(repo), "--pins", str(pins), "--json", str(out)])
    report = json.loads(out.read_text())
    text_ci = (repo / ".github" / "workflows" / "ci.yml").read_text()
    text_after = (repo / ".github" / "workflows" / "after.yml").read_text()
    check("fix pins both actions to the resolved SHAs",
          fixed.returncode == 0 and f"actions/checkout@{PINS['actions/checkout@v4']}" in text_ci
          and f"actions/github-script@{PINS['actions/github-script@v7']}" in text_after)
    check("fix rewrites write-all to a read-only block",
          "permissions: write-all" not in text_ci and "permissions:\n  contents: read" in text_ci)
    check("fix leaves scope-level write for a human", any(
        s["file"].endswith("release.yml") and "scope-level" in s["reason"] for s in report["skipped"]))
    check("fix reports what it changed", {x["rule"] for x in report["fixed"]} ==
          {"gha-unpinned-action", "gha-write-permissions"})

    # the re-scan improves and the judgement findings stay
    after_scan = scan(repo)
    after_rules = {f["title"].split(":")[0] for f in after_scan["findings"]}
    check("re-scan drops the fixed findings",
          {"gha-unpinned-action", "gha-write-permissions"} <= before_rules
          and "gha-unpinned-action" not in after_rules
          and all(f["file"].endswith("release.yml") for f in after_scan["findings"]
                  if f["title"].startswith("gha-write-permissions")))
    check("re-scan keeps the judgement findings",
          {"gha-pwn-request", "gha-secret-echo", "gha-curl-pipe-shell"} <= after_rules)
    check("severity counts decrease",
          after_scan["counts"]["critical"] + after_scan["counts"]["high"] + after_scan["counts"]["medium"]
          + after_scan["counts"]["low"]
          < before_scan["counts"]["critical"] + before_scan["counts"]["high"] + before_scan["counts"]["medium"]
          + before_scan["counts"]["low"])

    # idempotent, and a second dry-run has nothing to say
    again = run(["fix", str(repo), "--pins", str(pins), "--json", str(out)])
    check("fix is idempotent", json.loads(out.read_text())["changed_files"] == [] and again.returncode == 0)
    check("only the flagged workflows were touched", set(snapshot(repo)) == set(before))

with tempfile.TemporaryDirectory() as td:
    repo = Path(td) / "trap-gha"
    shutil.copytree(ROOT / "tests" / "fixtures" / "trap-gha", repo)
    partial = Path(td) / "partial.json"
    partial.write_text(json.dumps({"actions/checkout@v4": PINS["actions/checkout@v4"]}))
    out = Path(td) / "report.json"
    run(["fix", str(repo), "--no-network", "--pins", str(partial), "--json", str(out)])
    report = json.loads(out.read_text())
    check("--no-network never guesses an unpinned SHA",
          "actions/checkout@v4" not in (repo / ".github" / "workflows" / "ci.yml").read_text()
          and any("cannot resolve actions/github-script@v7" in s["reason"] for s in report["skipped"]))
    check("partial pins still fix what they cover",
          PINS["actions/checkout@v4"] in (repo / ".github" / "workflows" / "ci.yml").read_text())

check("a URL target is rejected instead of cloned",
      run(["fix", "https://github.com/psf/requests"]).returncode == 1)
check("fix stays stdlib-only", "yaml" not in sys.modules)

sys.exit(fail)
