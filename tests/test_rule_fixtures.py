#!/usr/bin/env python3
"""Rule fixture pairs: every rule a fixture declares must fire there, and stay silent on the clean control.

The declarations live in tests/run_tests.sh (RULES="…" before the check that scans the fixture).
The negative fixture is tests/fixtures/control-clean: a rule that fires there is a false positive.
"""
import json, re, subprocess, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
SCANNER = ROOT / "repobeagle.py"
PAIRS = re.findall(r'RULES="([^"]*)"[^\n]*\n\s*check\s+(tests/fixtures/[\w-]+)',
                   (ROOT / "tests" / "run_tests.sh").read_text(encoding="utf-8"))

fail = 0
def check(name, ok):
    global fail
    print(("PASS " if ok else "FAIL ") + name)
    if not ok:
        fail = 1

def scan(target):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        out = Path(fh.name)
    try:
        r = subprocess.run([sys.executable, str(SCANNER), "scan", target, "--no-color", "--json", str(out),
                            "--no-osv", "--no-trust"], capture_output=True, text=True, timeout=900)
        try:
            return json.loads(out.read_text()), r.returncode, (r.stderr or r.stdout)[-400:]
        except ValueError:
            return {}, r.returncode, (r.stderr or r.stdout)[-400:]
    finally:
        out.unlink(missing_ok=True)

def rules_of(report):
    return {str(f.get("title", "")).split(":")[0] for f in report.get("findings") or []
            if isinstance(f, dict) and not f.get("suppressed")}

declared = sorted({r for rules, _ in PAIRS for r in rules.split()})
check(f"rule declarations parsed ({len(PAIRS)} fixtures, {len(declared)} rules)", len(PAIRS) >= 6 and len(declared) >= 80)
check("declared fixtures exist", all((ROOT / fx).is_dir() for _, fx in PAIRS))

for rules, fixture in PAIRS:
    report, rc, tail = scan(fixture)
    found = rules_of(report)
    missing = [r for r in rules.split() if r not in found]
    check(f"positive fixture fires every declared rule: {fixture}" + (f" (missing {', '.join(missing)})" if missing else ""),
          rc <= 2 and report.get("findings") is not None and not missing)

control, rc, tail = scan("tests/fixtures/control-clean")
false_positives = sorted(set(declared) & rules_of(control))
check("negative fixture (control-clean) is GREEN", rc == 0 and control.get("verdict") == "GREEN")
check("negative fixture fires no declared rule" + (f": {', '.join(false_positives)}" if false_positives else ""),
      not false_positives)

sys.exit(fail)
