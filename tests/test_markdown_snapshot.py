#!/usr/bin/env python3
"""Markdown export snapshot: exact PR-comment output, with pipe/newline escaping and suppression cases."""
import copy, json, sys
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

snap = ROOT / "tests" / "snapshots"
report = json.loads((snap / "markdown-report.json").read_text(encoding="utf-8"))
expected = (snap / "markdown-report.md").read_text(encoding="utf-8")
before = json.dumps(report, sort_keys=True)

md = rb.markdown_report(report)
check("markdown export matches the reviewed snapshot", md == expected)
check("markdown export is pure and deterministic",
      rb.markdown_report(report) == md and json.dumps(report, sort_keys=True) == before)
check("pipes are escaped in every table cell",
      "| rule-a: pipe \\| in title second line |" in md and "fix \\| this |" in md
      and "third-party-script: loads \\| from cdn" in md)
check("newlines never break a table row",
      all("\n" not in ln or ln.startswith("|") or ln.startswith("##") or not ln for ln in md.splitlines())
      and "pipe \\| in title second line" in md)
check("suppressed findings are not rendered", "md-padded-line" not in md)
check("missing locations render as ?", "| high | `no-file` | `?` |" in md)
check("cells are truncated", "y" * 189 in md and "y" * 190 not in md)
check("verdict header and why line are present",
      md.startswith("## RepoBeagle: YELLOW\n") and "No critical issues" in md)

empty = rb.markdown_report({"verdict": "GREEN", "counts": {"critical": 0}, "findings": []})
check("empty report renders a plain line", empty.startswith("## RepoBeagle: GREEN") and "No findings." in empty)
check("missing report fields do not crash", rb.markdown_report({}).startswith("## RepoBeagle: ?"))

sys.exit(fail)
