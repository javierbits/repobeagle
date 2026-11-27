#!/usr/bin/env python3
"""U17: every documented rule resolves via `explain <rule>`; corpus examples link to the exact line."""
import argparse
import contextlib
import io
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import repobeagle as rb

fail = 0


def check(name, ok, detail=""):
    global fail
    print(("PASS " if ok else "FAIL ") + name + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        fail = 1


def explain(target):
    args = argparse.Namespace(report=str(target), accept=[], target=None, write=False,
                              ignore_file=".repobeagleignore", reason="", no_color=True)
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = rb.cmd_explain(args)
    return rc, out.getvalue(), err.getvalue()


baseline = json.loads((ROOT / "tests" / "corpus-baseline.json").read_text(encoding="utf-8"))
examples = baseline.get("examples") or {}
unresolved = []
for rule in sorted(rb.RULES):
    rc, out, err = explain(rule)
    if rc != 0 or not out.startswith(f"rule: {rule}"):
        unresolved.append(f"{rule} (rc={rc}: {err.strip()[:80]})")
check("every documented rule id resolves", not unresolved, str(unresolved[:5]))
check("a documented rule prints its severity, meaning and remediation",
      all(token in explain("cookie-flags")[1] for token in ("severity:", "meaning:", "remediation:")))
check("sentence-style known rules resolve too", explain("gha-curl-pipe-shell")[0] == 0
      and "not documented" in explain("gha-curl-pipe-shell")[1])

rc, out, err = explain("definitely-not-a-rule")
check("an unknown rule id exits 2", rc == 2 and "unknown rule id" in err, err.strip())

# Examples: exact repo@sha:file:line from the R7 baseline, and a GitHub URL pinned to that line.
recorded = examples.get("cookie-flags") or []
rc, out, err = explain("cookie-flags")
check("a corpus example is printed with its exact location",
      bool(recorded) and f"{recorded[0]['repo']}@{recorded[0]['sha'][:12]}:{recorded[0]['file']}:{recorded[0]['line']}" in out,
      out[-400:])
urls = re.findall(r"https://github\.com/[^\s]+#L(\d+)", out)
check("the GitHub link points at the example line",
      bool(urls) and str(recorded[0]["line"]) in urls, str(urls[:2]))
rc, out, _ = explain("gha-curl-pipe-shell")
check("fixture examples carry the exact fixture line",
      "fixture:tests/fixtures/trap-gha@worktree:.github/workflows/ci.yml:14" in out, out[-300:])

missing = sorted(set(rb.RULES) - set(examples))
if missing:
    rc, out, _ = explain(missing[0])
    check("a rule without a corpus example says so", rc == 0 and "none recorded" in out, out[-200:])

# Report mode keeps working (the full report planner is covered by test_explain.py).
rc, out, _ = explain("tests/snapshots/markdown-report.json")
check("report mode still explains a stored report", rc == 0 and ("verdict" in out.lower() or "threshold" in out.lower()),
      out[:300])

sys.exit(fail)
