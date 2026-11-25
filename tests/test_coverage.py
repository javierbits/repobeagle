#!/usr/bin/env python3
"""Coverage accounting tests: arithmetic, skip reasons, language blind spots, the documented profile decision."""
import json, subprocess, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fail = 0
def check(name, ok):
    global fail
    print(("PASS " if ok else "FAIL ") + name)
    if not ok:
        fail = 1

def scan(target, *extra, timeout=900):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        out = Path(fh.name)
    try:
        r = subprocess.run([sys.executable, str(ROOT / "repobeagle.py"), "scan", str(target), "--no-docker",
                            "--no-osv", "--no-trust", "--no-color", "--json", str(out)] + list(extra),
                           capture_output=True, text=True, timeout=timeout)
        try:
            return json.loads(out.read_text(encoding="utf-8")), r
        except ValueError:
            return {}, r
    finally:
        out.unlink(missing_ok=True)

def tree(td, files):
    for name, content in files.items():
        p = Path(td) / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)

# arithmetic and shape on a real fixture
report, _ = scan("tests/fixtures/trap-privacy")
cov = report["meta"]["coverage"]
check("coverage accounting is present and consistent",
      cov["files_total"] >= 10 and 0 < cov["files_scanned"] <= cov["files_total"]
      and cov["bytes_scanned"] <= cov["bytes_total"]
      and cov["bytes_scanned_pct"] == round(100.0 * cov["bytes_scanned"] / cov["bytes_total"], 1))
check("skip reasons cover every documented category",
      set(cov["skipped"]) == {"archive", "binary", "oversize", "unreadable", "unsupported"})
check("unscanned extensions are listed", isinstance(cov["unscanned_extensions"], list))
check("language inventory separates inspected from unread",
      isinstance(cov["languages"].get("inspected"), dict) and isinstance(cov["languages"].get("no_rules"), dict))

# empty repository: nothing to inspect, and the percentage is not NaN
report, _ = scan("tests/fixtures/control-empty")
cov = report["meta"]["coverage"]
check("empty repository coverage is honest",
      cov["files_total"] == 1 and cov["bytes_total"] == 0 and cov["bytes_scanned_pct"] == 100.0
      and cov["skipped"]["unsupported"] == 1          # the .gitkeep itself has no language rules
      and cov["languages"] == {"inspected": {}, "no_rules": {}})

# binary-only repository
report, _ = scan("tests/fixtures/control-binary-only")
cov = report["meta"]["coverage"]
check("binary-only repository inspects nothing",
      cov["skipped"]["binary"] == 1 and cov["files_scanned"] == 0
      and cov["bytes_scanned"] == 0 and cov["bytes_scanned_pct"] == 0.0)

# oversize-only repository
report, _ = scan("tests/fixtures/control-oversize-only")
cov = report["meta"]["coverage"]
check("oversize-only repository inspects nothing",
      cov["skipped"]["oversize"] == 1 and cov["files_scanned"] == 0 and cov["bytes_scanned_pct"] == 0.0)

# mixed tree: one language we read, one with no rules, one unknown extension
with tempfile.TemporaryDirectory() as td:
    tree(td, {"app.py": "x = 1\n", "main.ex": "defmodule M do\nend\n", "data.xyz": "a,b\n"})
    report, printed = scan(td)
    cov = report["meta"]["coverage"]
    check("inspected language is counted", cov["languages"]["inspected"].get("Python") == 1)
    check("languages without rules are named, not just skipped", cov["languages"]["no_rules"] == {"Elixir": 1})
    exts = dict(cov["unscanned_extensions"])
    check("unknown and uncovered extensions remain visible", exts.get(".ex") == 1 and exts.get(".xyz") == 1
          and cov["skipped"]["unsupported"] == 2)
    check("printed report surfaces languages without rules",
          "Coverage:" in printed.stdout and "no language rules for:" in printed.stdout
          and "Elixir (1)" in printed.stdout and "unsupported extension(s)" in printed.stdout)

# threshold semantics: under 60% only counts with at least 20 files
big = "# Oversize document\n\n" + ("a" * 1_600_000) + "\n"
def low_cov_findings(report):
    return [f for f in report["findings"] if f["title"].startswith("Coverage-low")]

with tempfile.TemporaryDirectory() as td:
    tree(td, {**{f"f{i}.py": "x = 1\n" for i in range(18)}, "big.md": big})
    report, _ = scan(td)
    check("no coverage-low below the 20-file floor",
          report["meta"]["coverage"]["files_total"] == 19 and not low_cov_findings(report))

with tempfile.TemporaryDirectory() as td:
    tree(td, {**{f"f{i}.py": "x = 1\n" for i in range(19)}, "big.md": big})
    report, _ = scan(td)
    low = low_cov_findings(report)
    check("coverage-low fires under 60% with 20 files",
          report["meta"]["coverage"]["bytes_scanned_pct"] < 60 and len(low) == 1
          and low[0]["severity"] == "low" and low[0].get("remediation"))
    check("coverage-low does not raise the balanced verdict",
          report["verdict"] == "GREEN")
    strict, _ = scan(td, "--strict")
    check("coverage-low does raise the strict verdict",
          strict["verdict"] == "YELLOW" and low_cov_findings(strict))

sys.exit(fail)
