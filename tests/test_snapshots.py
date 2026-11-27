#!/usr/bin/env python3
"""Byte-stable report snapshots per fixture (R4).

The snapshot is the deterministic, environment-independent core of a scan: agent/privacy/
telemetry findings plus the stable report metadata. External scanner findings and tool
versions are excluded because their presence depends on what is installed; the tool
version, timings, run URLs and cache state are excluded because they are volatile or
release-scoped by design (report shape is covered by the schema/other tests).

Run with --update to regenerate the goldens (then review the diff).
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCANNER = ROOT / "repobeagle.py"
SNAPS = ROOT / "tests" / "snapshots" / "reports"
FIXTURES = [
    "control-clean",
    "trap-gha",
    "trap-privacy",
    "trap-npm",
    "trap-build",
    "trap-markdown",
    "trap-binary",
    "trap-telemetry",
    "trap-supply",
    "workspace-two",
]
BUILTIN_TOOLS = {"agent-checks", "privacy", "telemetry"}
VOLATILE_META = {"seconds", "scanned_at", "run_url", "cache", "tools"}
fail = 0


def check(name, ok, detail=""):
    global fail
    print(("PASS " if ok else "FAIL ") + name + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        fail = 1


def snapshot(d):
    """Canonical, environment-independent view of a report (see docstring)."""
    meta = d.get("meta") or {}
    findings = [f for f in (d.get("findings") or [])
                if isinstance(f, dict) and f.get("tool") in BUILTIN_TOOLS]
    findings.sort(key=lambda f: (f.get("tool") or "", f.get("severity") or "", str(f.get("title") or ""),
                                 f.get("file") or "", int(f.get("line") or 0)))
    snap = {
        "findings": findings,
        "privacy_summary": d.get("privacy_summary") or {},
        "meta": {k: v for k, v in sorted(meta.items()) if k not in VOLATILE_META},
    }
    return json.dumps(snap, indent=2, sort_keys=True) + "\n"


def scan(fixture):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        out = Path(fh.name)
    try:
        r = subprocess.run([sys.executable, str(SCANNER), "scan", f"tests/fixtures/{fixture}",
                            "--no-docker", "--no-osv", "--no-trust", "--no-cache", "--no-color",
                            "--json", str(out)],
                           cwd=ROOT, capture_output=True, text=True, timeout=900,
                           env=dict(os.environ, XDG_CACHE_HOME=tempfile.mkdtemp(),
                                    BEAGLE_NO_UPDATE_CHECK="1"))
        assert out.exists() and out.stat().st_size, (r.returncode, (r.stderr or r.stdout)[-500:])
        return json.loads(out.read_text(encoding="utf-8"))
    finally:
        out.unlink(missing_ok=True)


def main():
    update = "--update" in sys.argv[1:]
    SNAPS.mkdir(parents=True, exist_ok=True)
    for fixture in FIXTURES:
        text = snapshot(scan(fixture))
        gold = SNAPS / f"{fixture}.json"
        if update:
            gold.write_text(text, encoding="utf-8")
            print(f"wrote {gold.relative_to(ROOT)}")
            continue
        expected = gold.read_text(encoding="utf-8") if gold.is_file() else None
        detail = ""
        if expected is not None and expected != text:
            import difflib
            diff = [ln for ln in difflib.unified_diff(expected.splitlines(), text.splitlines(),
                                                      "golden", "current", lineterm="", n=1)
                    if ln.startswith(("+", "-")) and not ln.startswith(("+++", "---"))]
            detail = " | ".join(diff[:6])[:600] or "whitespace/trailing newline differs"
        check(f"report snapshot: {fixture}", expected == text,
              detail or ("missing golden: run tests/test_snapshots.py --update" if expected is None else ""))
    return fail


if __name__ == "__main__":
    sys.exit(main())
