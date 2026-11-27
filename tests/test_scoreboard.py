#!/usr/bin/env python3
"""R7 scoreboard: baseline gate, median/rule regression detection, detection cohort, verdict labels."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools" / "scoreboard.py"
FIXTURES = ROOT / "tests" / "fixtures"
fail = 0


def check(name, ok, detail=""):
    global fail
    print(("PASS " if ok else "FAIL ") + name + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        fail = 1


def run(corpus, baseline, *extra):
    return subprocess.run([sys.executable, str(TOOL), "--corpus", str(corpus), "--baseline", str(baseline),
                           "--jobs", "2", "--no-docker", "--out", str(Path(baseline).with_suffix(".md")),
                           *extra], cwd=ROOT, capture_output=True, text=True,
                          timeout=900, env=dict(__import__("os").environ, BEAGLE_NO_UPDATE_CHECK="1"))


with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    corpus, baseline = td / "corpus.yml", td / "baseline.json"
    corpus.write_text(f"""# local fixtures: honest = a repo with findings but no criticals; detection = labeled trap
honest:
  - path: {FIXTURES / 'trap-markdown'}
    sha: local
malicious:
  - path: {FIXTURES / 'trap-gha'}
    expect:
      - gha-curl-pipe-shell
      - gha-unpinned-action
    verdict: YELLOW|RED
""", encoding="utf-8")
    r = run(corpus, baseline, "--update-baseline", "--json", str(td / "score.json"))
    base = json.loads(baseline.read_text(encoding="utf-8")) if baseline.exists() else {}
    check("baseline builds from a local corpus", r.returncode == 0 and base.get("honest")
          and base.get("detection") and base["detection"][0]["missing"] == [],
          (r.stderr or r.stdout)[-500:])
    check("the baseline records a median and per-rule totals",
          base.get("median_findings", 0) >= 1 and base.get("totals_by_rule", {}).get("md-css-hidden", 0) >= 1,
          json.dumps(base.get("totals_by_rule", {}))[:300])

    r = run(corpus, baseline)
    check("an unchanged run passes the committed baseline", r.returncode == 0 and "**Result:** PASS" in
          (td / "baseline.md").read_text(encoding="utf-8"), (r.stderr or r.stdout)[-400:])

    # A rule that now fires on the honest cohort must be a regression.
    tampered = json.loads(baseline.read_text(encoding="utf-8"))
    tampered["totals_by_rule"]["md-css-hidden"] = 0
    (td / "tampered-rules.json").write_text(json.dumps(tampered), encoding="utf-8")
    r = run(corpus, td / "tampered-rules.json")
    check("a rule's honest hits cannot increase", r.returncode == 1 and "md-css-hidden" in r.stderr,
          (r.stderr or r.stdout)[-400:])

    # Median findings are the acceptance budget.
    tampered = json.loads(baseline.read_text(encoding="utf-8"))
    tampered["median_findings"] = float(tampered["median_findings"]) - 1
    (td / "tampered-median.json").write_text(json.dumps(tampered), encoding="utf-8")
    r = run(corpus, td / "tampered-median.json")
    check("the honest median finding count cannot increase", r.returncode == 1 and "median" in r.stderr,
          (r.stderr or r.stdout)[-400:])

    # Detection: every expected rule must fire, and the verdict must match the label.
    lost = td / "corpus-lost-rule.yml"
    lost.write_text(corpus.read_text(encoding="utf-8").replace("gha-unpinned-action", "not-a-real-rule"),
                    encoding="utf-8")
    r = run(lost, baseline)
    check("a lost detection fails the scoreboard", r.returncode == 1 and "not-a-real-rule" in r.stderr,
          (r.stderr or r.stdout)[-400:])

    wrong = td / "corpus-wrong-verdict.yml"
    wrong.write_text(corpus.read_text(encoding="utf-8").replace("verdict: YELLOW|RED", "verdict: GREEN"),
                     encoding="utf-8")
    r = run(wrong, baseline)
    check("a verdict label mismatch fails the scoreboard", r.returncode == 1 and "verdict" in r.stderr,
          (r.stderr or r.stdout)[-400:])

    # The baseline gate must not hide a scan failure.
    broken = td / "corpus-broken.yml"
    broken.write_text(corpus.read_text(encoding="utf-8").replace(str(FIXTURES / "trap-markdown"),
                                                               str(td / "no-such-directory")),
                      encoding="utf-8")
    r = run(broken, baseline)
    check("a failed honest scan fails the scoreboard", r.returncode == 1 and "failed" in r.stderr,
          (r.stderr or r.stdout)[-400:])

sys.exit(fail)
