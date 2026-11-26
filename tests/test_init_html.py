#!/usr/bin/env python3
"""`init` and HTML report tests: generated workflow, shields lines, escaping and self-containment."""
import json, os, subprocess, sys, tempfile, tomllib
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import repobeagle as rb

try:
    import yaml
except ImportError:
    yaml = None

fail = 0
def check(name, ok):
    global fail
    print(("PASS " if ok else "FAIL ") + name)
    if not ok:
        fail = 1

def run(args, cwd=None, timeout=600, env=None):
    return subprocess.run([sys.executable, str(ROOT / "repobeagle.py")] + args,
                           capture_output=True, text=True, timeout=timeout, cwd=cwd,
                           env=dict(os.environ, **(env or {})))

with tempfile.TemporaryDirectory() as td:
    out = Path(td) / ".github" / "workflows" / "repobeagle.yml"
    dry = run(["init", td, "--repo", "o/r", "--dry-run"])
    check("init --dry-run prints the workflow and writes nothing",
          dry.returncode == 0 and not out.exists() and "uses: javierbits/repobeagle/.github/workflows/scan.yml@" in dry.stdout)
    real = run(["init", td, "--repo", "o/r"])
    body = out.read_text()
    check("init writes the documented workflow", real.returncode == 0 and out.is_file()
          and f"scan.yml@{rb.RELEASE}" in body and "id-token: write" in body)
    if yaml:
        doc = yaml.safe_load(body)
        job = doc["jobs"]["scan"]
        check("the generated workflow is valid YAML with the documented inputs",
              job["uses"] == f"javierbits/repobeagle/.github/workflows/scan.yml@{rb.RELEASE}"
              and job["with"] == {"profile": "balanced", "fail-on-red": False, "privacy-only": False,
                                  "badge-branch": "repobeagle", "set-status": True, "tools-ref": rb.RELEASE})
    else:
        print("SKIP workflow YAML parse (pyyaml not installed); text assertions only")
    check("init prints the shield lines", f"raw.githubusercontent.com/o/r/repobeagle/badge.json" in real.stdout
          and "![RepoBeagle](" in real.stdout)
    check("init is idempotent", "is up to date" in run(["init", td, "--repo", "o/r"]).stdout)
    conflict = run(["init", td, "--repo", "o/r", "--profile", "strict"])
    check("init refuses to clobber a different workflow", conflict.returncode == 1 and "--force" in conflict.stderr)
    forced = run(["init", td, "--repo", "o/r", "--profile", "strict", "--force"])
    check("init --force replaces it", forced.returncode == 0 and "profile: strict" in out.read_text())
    check("init can disable publishing", "badge-branch: \"\"" in run(["init", td, "--badge-branch", "", "--force"]).stdout
          or 'badge-branch: ""' in out.read_text())

# the repo slug comes from the origin remote when --repo is absent
with tempfile.TemporaryDirectory() as td:
    subprocess.run(["git", "-C", td, "init", "-q", "-b", "main"], check=False)
    subprocess.run(["git", "-C", td, "remote", "add", "origin", "git@github.com:alice/tool.git"], check=False)
    out = run(["init", td], env={"GITHUB_REPOSITORY": ""})   # CI exports it; here the remote must win
    check("init derives the slug from the origin remote", "raw.githubusercontent.com/alice/tool/repobeagle/badge.json" in out.stdout
          and (Path(td) / ".github" / "workflows" / "repobeagle.yml").is_file())

# --- HTML report -----------------------------------------------------------------
report = {
    "version": "1.170.0", "verdict": "YELLOW",
    "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
    "meta": {"target": "tests/fixtures/<demo>", "mode": "local (no docker)", "profile": "balanced",
             "ruleset": "0123456789ab", "scope": {"scope": "metadata", "paths_fetched": 2, "truncated": False}},
    "notes": ["note <one> & two"],
    "findings": [
        {"tool": "agent-checks", "severity": "high", "file": "src/a&b.js", "line": 3,
         "title": "rule-a: <script>alert(1)</script> & pipe | here", "meaning": "why <b>not</b>",
         "snippet": "if (a < b) { x(); }", "remediation": "use &amp; or escape < >"},
        {"tool": "agent-checks", "severity": "low", "file": "d.js", "line": 9,
         "title": "rule-b: fine", "suppressed": True,
         "suppression": {"rule": "rule-b", "reason": "reviewed <ok>", "until": "2030-01-01"}},
    ],
}
html = rb.html_report(report)
check("html report is a complete self-contained document",
      html.startswith("<!doctype html>") and "<style>" in html and "</html>" in html
      and "http://" not in html and "https://" not in html)
check("html escapes markup from findings and notes",
      "&lt;script&gt;alert(1)&lt;/script&gt;" in html and "<script>alert" not in html
      and "&lt;b&gt;not&lt;/b&gt;" in html and "a&amp;b.js" in html and "note &lt;one&gt; &amp; two" in html
      and "if (a &lt; b)" in html)
check("html shows suppressions with their reason", "accepted: reviewed &lt;ok&gt;" in html
      and "sev-low suppressed" in html)
check("html states the verdict, counts and scope",
      "RepoBeagle:" in html and "critical 0" in html and "scope: scope metadata" in html)
empty = rb.html_report({"verdict": "GREEN", "counts": {}, "findings": []})
check("empty html report is valid", "No findings." in empty and empty.startswith("<!doctype html>"))

with tempfile.TemporaryDirectory() as td:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        rep = Path(fh.name)
    report_path = Path(td) / "r.json"; report_path.write_text(json.dumps(report))
    out = run(["export", str(report_path), "--format", "html", "-o", str(rep)])
    check("export --format html writes the same renderer", out.returncode == 0
          and rep.read_text() == rb.html_report(report))
    rep.unlink(missing_ok=True)
    html_out = Path(td) / "scan.html"
    scan = run(["scan", str(ROOT / "tests" / "fixtures" / "control-clean"), "--no-docker", "--no-osv",
                "--no-trust", "--no-color", "--json", str(Path(td) / "scan.json"), "--html", str(html_out)])
    body = html_out.read_text() if html_out.is_file() else ""
    check("scan --html writes the report", scan.returncode == 0 and body.startswith("<!doctype html>")
          and "RepoBeagle:" in body and ("<table>" in body or "No findings." in body))

sys.exit(fail)
