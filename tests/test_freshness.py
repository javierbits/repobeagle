#!/usr/bin/env python3
"""U16 freshness: --max-age exit codes, age in verify output and badge text; local-key signing."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
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


for text, want in (("30d", 30 * 86400), ("12h", 12 * 3600), ("45m", 45 * 60), ("90s", 90), ("2w", 14 * 86400)):
    check(f"duration parses: {text}", rb.parse_max_age(text) == want, str(rb.parse_max_age(text)))
for bad in ("3x", "", "d", "-1d", "1.5d"):
    try:
        rb.parse_max_age(bad)
    except ValueError:
        ok = True
    else:
        ok = False
    check(f"invalid duration rejected: {bad!r}", ok)

now = 1_800_000_000
old = {"scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 40 * 86400))}
current = {"scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 3600))}
check("age text is compact", rb.human_age(40 * 86400) == "40d" and rb.human_age(3600 * 3) == "3h"
      and rb.human_age(120) == "2m" and rb.human_age(None) == "unknown")
check("a 40-day-old report is stale under 30d",
      rb.stale(old, 30 * 86400, now=now)[0] is True, str(rb.stale(old, 30 * 86400, now=now)))
check("a current report is fresh under 30d",
      rb.stale(current, 30 * 86400, now=now)[0] is False, str(rb.stale(current, 30 * 86400, now=now)))
check("a report without a timestamp is stale when a policy is set",
      rb.stale({}, 30 * 86400, now=now)[0] is True)
check("without a policy nothing is stale", rb.stale({}, None, now=now)[0] is False)

# Badge text: age appended only when the report records a scan timestamp.
td = Path(tempfile.mkdtemp())
try:
    (td / "old.json").write_text(json.dumps({"verdict": "YELLOW", "counts": {}, "findings": [],
                                             "privacy_summary": {}, "meta": {"complete": True,
                                             "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 40 * 86400))}}))
    r = subprocess.run([sys.executable, "tools/make_badge.py", str(td / "old.json"),
                        "--endpoint", str(td / "badge.json"), "--svg", str(td / "badge.svg"),
                        "--now", str(now)], cwd=ROOT, capture_output=True, text=True, timeout=60)
    endpoint = json.loads((td / "badge.json").read_text())
    check("the endpoint badge shows the scan age", r.returncode == 0 and endpoint.get("age") == "40d"
          and "40d" in endpoint.get("message", ""), json.dumps(endpoint))
    check("the SVG badge shows the scan age", "40d" in (td / "badge.svg").read_text())

    (td / "legacy.json").write_text(json.dumps({"verdict": "GREEN", "counts": {}, "findings": [],
                                                "privacy_summary": {}, "meta": {"complete": True}}))
    r = subprocess.run([sys.executable, "tools/make_badge.py", str(td / "legacy.json"),
                        "--endpoint", str(td / "legacy-badge.json")],
                       cwd=ROOT, capture_output=True, text=True, timeout=60)
    legacy = json.loads((td / "legacy-badge.json").read_text())
    check("a timestamp-less report keeps the old badge text", r.returncode == 0
          and legacy.get("message") == "GREEN" and "age" not in legacy, json.dumps(legacy))
finally:
    shutil.rmtree(td, ignore_errors=True)


def verify_report(meta, *extra):
    work = Path(tempfile.mkdtemp())
    report, bundle = work / "report.json", work / "report.sigstore.json"
    report.write_text(json.dumps({"version": rb.VERSION, "verdict": "YELLOW", "why": "", "counts": {},
                                  "findings": [], "meta": {"profile": "balanced", "privacy_mode": "full",
                                                           "pii_redacted": True, **meta}}))
    subprocess.run([cosign, "sign-blob", "--yes", "--key", str(keys / "cosign.key"), "--bundle",
                    str(bundle), str(report)], capture_output=True, text=True, check=True,
                   env=dict(os.environ, COSIGN_PASSWORD=""))
    r = subprocess.run([sys.executable, "repobeagle.py", "verify", "--report", str(report), "--bundle",
                        str(bundle), "--key", str(keys / "cosign.pub"), *extra],
                       cwd=ROOT, capture_output=True, text=True, timeout=120)
    shutil.rmtree(work, ignore_errors=True)
    return r


if shutil.which("cosign"):
    keys = Path(tempfile.mkdtemp())
    gen = subprocess.run(["cosign", "generate-key-pair"], cwd=keys, capture_output=True, text=True,
                         env=dict(os.environ, COSIGN_PASSWORD=""))
    cosign = shutil.which("cosign")
    try:
        r = verify_report({"scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 40 * 86400))},
                          "--max-age", "30d")
        check("a 40-day-old report with --max-age 30d exits 2", r.returncode == 2,
              (r.stdout + r.stderr)[-400:])
        check("verify prints the age and the stale policy", "40d old" in r.stdout and "STALE" in r.stdout
              and "--max-age 30d" in r.stdout, r.stdout[-400:])
        r = verify_report({"scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3600))},
                          "--max-age", "30d")
        check("a current report with --max-age 30d exits 0", r.returncode == 0, (r.stdout + r.stderr)[-400:])
        check("verify prints the age for a current report", "1h old" in r.stdout, r.stdout[-400:])
        r = verify_report({}, "--max-age", "30d")
        check("a timestamp-less report is stale under a policy", r.returncode == 2 and "no meta.scanned_at" in r.stdout,
              (r.stdout + r.stderr)[-400:])
        r = verify_report({"scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 40 * 86400))})
        check("without --max-age an old report stays valid (compatibility)", r.returncode == 0,
              (r.stdout + r.stderr)[-400:])
        r = verify_report({}, "--max-age", "3x")
        check("an invalid --max-age is rejected", r.returncode == 1 and "invalid duration" in r.stderr, r.stderr[-300:])
    finally:
        shutil.rmtree(keys, ignore_errors=True)
else:
    print("SKIP verify age exit codes (cosign is not installed)")

sys.exit(fail)
