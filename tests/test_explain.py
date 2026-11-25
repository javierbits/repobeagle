#!/usr/bin/env python3
"""Explain/planner tests: threshold arithmetic per profile, planner transitions, --write, malformed reports (no network)."""
import json, subprocess, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import repobeagle as rb

ROOT = Path(__file__).resolve().parent.parent
fail = 0
def check(name, ok):
    global fail
    print(("PASS " if ok else "FAIL ") + name)
    if not ok:
        fail = 1

def f(sev, rule, line=1, file="a.js"):
    return {"tool": "agent-checks", "severity": sev, "file": file, "line": line,
            "title": f"{rule}: detail", "rule": rule}

# threshold arithmetic, per profile: what turns GREEN, YELLOW and RED
cases = {
    "strict": [([], "GREEN"), ([f("low", "r")], "YELLOW"), ([f("medium", "r")], "YELLOW"), ([f("high", "r")], "RED")],
    "balanced": [([], "GREEN"), ([f("low", "r")], "GREEN"), ([f("medium", "r")], "YELLOW"),
                 ([f("high", "r")], "YELLOW"), ([f("critical", "r")], "RED")],
    "relaxed": [([], "GREEN"), ([f("medium", "r")], "GREEN"), ([f("high", "r")], "YELLOW"),
                ([f("critical", "r")], "RED")],
}
for prof, rows in cases.items():
    check(f"{prof} thresholds", all(rb.verdict(fs, prof, None)[0] == want for fs, want in rows))

# accepting rules: the count that remains is always available, and the verdict follows
findings = [f("critical", "critical-rule"), f("high", "high-rule", 2), f("high", "high-rule", 3),
            f("low", "low-rule", 4)]
check("baseline is RED (balanced)", rb.verdict(findings, "balanced", None)[0] == "RED")
keep, dropped = rb.planner_apply(findings, ["critical-rule"])
check("accept simulation drops the accepted rule", len(dropped) == 1 and len(keep) == 3)
check("accept simulation still RED before the critical is accepted", rb.verdict(findings, "balanced", None)[0] == "RED")
check("accept simulation leaves YELLOW after accepting the critical", rb.verdict(keep, "balanced", None)[0] == "YELLOW")
check("globs match like .repobeagleignore", rb.planner_apply(findings, ["*-rule"])[0] == [])
check("counts after accepting", rb._explain_counts(keep) == "high 2, low 1")

# planner transitions: the shortest way down, not every rule in severity order
plan, remaining, after = rb.planner_plan(findings, "balanced", None, "yellow")
check("plan to YELLOW accepts only the critical rule", [r for r, _ in plan] == ["critical-rule"] and after == "YELLOW")
check("plan to GREEN accepts the high rule too",
      [r for r, _ in rb.planner_plan(findings, "balanced", None, "green")[0]] == ["critical-rule", "high-rule"]
      and rb.planner_plan(findings, "balanced", None, "green")[2] == "GREEN")
check("planning from GREEN is empty", rb.planner_plan([f("low", "r")], "balanced", None, "green")[0] == [])
check("pressure reports distance to the binding threshold", rb._planner_pressure(findings, "balanced") == (2, 1))

# --write: rule ids with a reason comment, no duplicates, no PII, deterministic
with tempfile.TemporaryDirectory() as td:
    report = Path(td) / "report.json"
    report.write_text(json.dumps({
        "version": "1.155.0", "verdict": "RED", "meta": {"profile": "balanced"}, "findings": findings}))
    ignore = Path(td) / ".repobeagleignore"
    ignore.write_text("# existing review\nkeep-me\n")
    base = [sys.executable, str(ROOT / "repobeagle.py"), "explain", str(report)]
    run = lambda *args: subprocess.run(base + list(args), capture_output=True, text=True, timeout=120)
    r = run("--accept", "critical-rule", "--write", "--ignore-file", str(ignore), "--reason", "reviewed: 2 criticals are test fixtures")
    text = ignore.read_text()
    check("--write appends the rule with a reason", r.returncode == 0
          and "reviewed: 2 criticals are test fixtures" in text and "\ncritical-rule\n" in text)
    check("--write keeps existing lines", "# existing review\nkeep-me\n" in text)
    r2 = run("--accept", "critical-rule", "--write", "--ignore-file", str(ignore))
    check("--write is idempotent", text == ignore.read_text() and "0 rule(s) appended" in r2.stdout)
    check("accept output names the remaining counts", "remaining findings:" in r.stdout and "after accepting: YELLOW" in r.stdout)
    o1, o2 = run("--target", "green").stdout, run("--target", "green").stdout
    check("planner output is deterministic", o1 == o2 and "target green: reached" in o1)
    check("planner prints what remains after the plan", "remaining findings: low 1" in o1)
    check("planner does not re-scan or need the target tree", "largest contributors:" in o1)
    # malformed inputs
    bad = Path(td) / "bad.json"; bad.write_text("[1, 2, 3]")
    check("malformed report root rejected",
          subprocess.run(base[:3] + [str(bad)], capture_output=True).returncode == 1)
    broken = Path(td) / "broken.json"; broken.write_text("{not json")
    check("invalid JSON rejected", subprocess.run(base[:3] + [str(broken)], capture_output=True).returncode == 1)
    check("--write without a selection rejected", run("--write").returncode == 1)
    check("plain explain on a good report exits 0", subprocess.run(
        base[:3] + [str(report)], capture_output=True).returncode == 0)

sys.exit(fail)
