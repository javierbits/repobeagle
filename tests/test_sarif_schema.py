#!/usr/bin/env python3
"""Validate the SARIF exporter against the vendored official 2.1.0 schema (offline; skips without jsonschema)."""
import json, subprocess, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import repobeagle as rb

try:
    import jsonschema
except ImportError:
    print("SKIP sarif schema: jsonschema not installed (pip install -r requirements-dev.txt)")
    sys.exit(0)

fail = 0
def check(name, ok):
    global fail
    print(("PASS " if ok else "FAIL ") + name)
    if not ok:
        fail = 1

SCHEMA = json.loads((ROOT / "tests" / "schema" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))
VALIDATOR = jsonschema.validators.validator_for(SCHEMA)(SCHEMA)

def scan_report(fixture):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        out = Path(fh.name)
    try:
        subprocess.run([sys.executable, str(ROOT / "repobeagle.py"), "scan", fixture, "--no-color",
                        "--json", str(out), "--no-osv", "--no-trust"],
                       capture_output=True, text=True, timeout=900)
        return json.loads(out.read_text(encoding="utf-8"))
    finally:
        out.unlink(missing_ok=True)

for fixture in ("tests/fixtures/trap-npm", "tests/fixtures/trap-privacy"):
    report = scan_report(fixture)
    before = json.dumps(report, sort_keys=True)
    doc = rb.sarif_report(report)
    errors = sorted(VALIDATOR.iter_errors(doc), key=lambda e: list(e.path))
    check(f"{fixture}: SARIF validates against the vendored 2.1.0 schema", not errors)
    for e in errors[:5]:
        print(f"  schema error at {list(e.path)}: {e.message[:200]}")
    run = doc["runs"][0]
    results = run["results"]
    active = [f for f in report["findings"] if isinstance(f, dict) and not f.get("suppressed")]
    check(f"{fixture}: one result per non-suppressed finding", len(results) == len(active))
    check(f"{fixture}: declared rules cover every result",
          {r["ruleId"] for r in results} <= {r["id"] for r in run["tool"]["driver"]["rules"]})
    check(f"{fixture}: fingerprints unique and relative URIs",
          len({r["partialFingerprints"]["repobeagle/v1"] for r in results}) == len(results)
          and all(not r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("/") for r in results))
    check(f"{fixture}: exporter is pure and deterministic",
          rb.sarif_report(report) == doc and json.dumps(report, sort_keys=True) == before)
    with_fix = [f for f in active if f.get("remediation")]
    check(f"{fixture}: remediation travels as a SARIF property",
          len(with_fix) == sum(1 for r in results if r["properties"].get("remediation")))

sys.exit(fail)
