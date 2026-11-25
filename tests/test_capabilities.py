#!/usr/bin/env python3
"""Capability map tests: empty/doc-only/archive-only repos, doc/test noise collapsing, trace verification hook, --ref."""
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

def run(args, timeout=300):
    return subprocess.run([sys.executable, str(ROOT / "repobeagle.py")] + args,
                          capture_output=True, text=True, timeout=timeout)

def scan(fixture):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        out = Path(fh.name)
    try:
        r = run(["scan", fixture, "--no-docker", "--no-osv", "--no-trust", "--no-color", "--json", str(out)])
        return json.loads(out.read_text(encoding="utf-8")), r
    finally:
        out.unlink(missing_ok=True)

# empty repository: no capabilities, no crash, GREEN
report, proc = scan("tests/fixtures/control-empty")
caps = report["meta"]["capabilities"]
check("empty repo scans clean", proc.returncode == 0 and report["verdict"] == "GREEN")
check("empty repo has no capabilities", not any(v for k, v in caps.items() if isinstance(v, list) and k != "files"))
m = run(["map", "tests/fixtures/control-empty", "--no-docker"])
check("empty repo map exits 0 with a scanned line",
      m.returncode == 0 and "scanned:" in m.stdout and "network hosts" not in m.stdout)

# docs-only repository: hosts are found but marked, and collapsed in the human view
report, _ = scan("tests/fixtures/control-doc-hosts")
hosts = report["meta"]["capabilities"]["network"]
check("doc-only hosts are detected", {h["value"] for h in hosts} >= {"docs.example.org", "example.org"})
check("doc-only hosts are marked as documentation",
      all(h.get("doc") is True and h.get("test") is False for h in hosts))
check("static entries are not claimed as verified",
      all(h.get("verified") is False and h.get("source") == "static" for h in hosts))
m = run(["map", "tests/fixtures/control-doc-hosts", "--no-docker"])
check("map collapses docs/test entries by default",
      m.returncode == 0 and "docs/test" in m.stdout and "only documentation/test entries" in m.stdout)
m = run(["map", "tests/fixtures/control-doc-hosts", "--no-docker", "--all"])
check("map --all lists doc entries with their marker", m.returncode == 0 and "docs.example.org" in m.stdout and " doc" in m.stdout)

# archive-only repository: nothing inspectable, but the report says so
report, _ = scan("tests/fixtures/control-archive-only")
check("archive-only repo is flagged, not silently clean",
      report["verdict"] == "YELLOW" and any(f["title"].startswith("Archive") for f in report["findings"]))
check("archive-only repo has no network hosts", not report["meta"]["capabilities"]["network"])
check("archive-only coverage counts the archive",
      (report["meta"]["coverage"]["skipped"] or {}).get("archive") == 1)

# a normal repo's report summary hides fixture/doc noise and keeps the code entries
report, _ = scan("tests/fixtures/trap-npm")
m = run(["scan", "tests/fixtures/trap-npm", "--no-docker", "--no-osv", "--no-trust", "--no-color"])
check("report summary counts code capabilities", "Capabilities:" in m.stdout and "host(s)" in m.stdout and "secret path(s)" in m.stdout)

# doc/test classification and the T6 trace hook (unit level, no scan)
with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    (root / "src").mkdir(); (root / "tests").mkdir()
    (root / "src" / "app.js").write_text(
        'fetch("https://api.example.org/x");\n'
        'const key = fs.readFileSync(os.homedir() + "/.ssh/id_rsa");\n'
        'subprocess.run(["node", "x"]);\n')
    (root / "tests" / "helper.js").write_text('fetch("https://test.example.org/");\n')
    caps = rb.scan_capabilities(root)
    by_host = {e["value"]: e for e in caps["network"]}
    check("code host and fixture host are classified", by_host["api.example.org"]["test"] is False
          and by_host["test.example.org"]["test"] is True and by_host["api.example.org"]["doc"] is False)
    traced = rb.scan_capabilities(root, trace={"network": ["api.example.org", "traced.example.net"],
                                              "processes": [{"value": "subprocess.run"}]})
    thr = {e["value"]: e for e in traced["network"]}
    check("trace marks static entries verified", thr["api.example.org"]["verified"] is True
          and thr["api.example.org"]["source"] == "trace")
    check("trace adds capabilities static analysis missed", thr["traced.example.net"]["verified"] is True)
    check("trace does not vouch for unrelated entries", thr["test.example.org"]["verified"] is False)
    check("trace covers non-network sections",
          any(e["verified"] is True and e["source"] == "trace" for e in traced["processes"]))

# --ref is forwarded to the scan (which rejects it for a local directory)
m = run(["map", "tests/fixtures/trap-npm", "--ref", "HEAD"])
check("map --ref is forwarded to the scan", m.returncode != 0 and "needs a git URL" in (m.stderr + m.stdout))

sys.exit(fail)
