"""Hard deadline: an unfinished scan is a partial report (meta.complete=false, YELLOW floor, exit 1)."""
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import repobeagle as rb

FIXTURE = "tests/fixtures/trap-gha"


def scan(*args, env=None):
    return subprocess.run([sys.executable, "repobeagle.py", "scan", *args, "--no-color"],
                          cwd=ROOT, capture_output=True, text=True, timeout=300,
                          env=dict(os.environ, **(env or {})))


def test_budget_expiry_is_a_partial_report():
    with tempfile.TemporaryDirectory() as td:
        out = Path(td, "r.json")
        r = scan(FIXTURE, "--max-seconds", "0.001", "--no-cache", "--no-docker", "--no-osv", "--no-trust",
                 "--json", str(out))
        assert r.returncode == 1, (r.returncode, r.stdout[-400:], r.stderr[-400:])
        assert "Traceback" not in r.stderr, r.stderr[-500:]
        assert "VERDICT: YELLOW (partial)" in r.stdout, r.stdout[-400:]
        d = json.loads(out.read_text(encoding="utf-8"))
        assert d["verdict"] == "YELLOW" and d["meta"]["complete"] is False, d["verdict"]
        assert any("--max-seconds" in n for n in d["notes"]), d["notes"]
        assert any("incomplete" in n for n in d["notes"]), d["notes"]
        # the badge must be visibly partial
        ep, svg = Path(td, "badge.json"), Path(td, "badge.svg")
        b = subprocess.run([sys.executable, "tools/make_badge.py", str(out), "--endpoint", str(ep), "--svg", str(svg)],
                           cwd=ROOT, capture_output=True, text=True, timeout=60)
        assert b.returncode == 0, b.stderr
        badge = json.loads(ep.read_text(encoding="utf-8"))
        assert badge["message"] == "YELLOW (partial)" and badge["complete"] is False, badge
        assert "YELLOW (partial)" in svg.read_text(encoding="utf-8")
    print("PASS --max-seconds writes a partial YELLOW report, exit 1, no traceback, partial badge")


def test_per_file_alarm_end_to_end():
    with tempfile.TemporaryDirectory() as td:
        out = Path(td, "r.json")
        r = scan(FIXTURE, "--no-cache", "--no-docker", "--no-osv", "--no-trust", "--json", str(out),
                 env={"BEAGLE_FILE_SECONDS": "0.000001"})
        assert r.returncode == 1, (r.returncode, r.stdout[-400:])
        assert "Traceback" not in r.stderr, r.stderr[-400:]
        d = json.loads(out.read_text(encoding="utf-8"))
        assert d["verdict"] == "YELLOW" and d["meta"]["complete"] is False, d["verdict"]
        assert any("per-file alarm" in n for n in d["notes"]), d["notes"]
        slow = [f for f in d["findings"] if f["title"].startswith("Slow-file")]
        assert slow and slow[0]["severity"] == "info", slow[:1]
    print("PASS per-file alarm skips slow files, reports them and floors the verdict")


def test_inner_and_head_completeness():
    with tempfile.TemporaryDirectory() as td:
        full = rb.inner(ROOT / FIXTURE, td)
        assert full["complete"] is True, full["notes"]
        partial = rb.inner(ROOT / FIXTURE, td, deadline=time.monotonic() - 1)
        assert partial["complete"] is False
        assert any("skipped" in n or "incomplete" in n for n in partial["notes"]), partial["notes"]
    orig_check, orig_seconds = rb.check_patterns, rb.SCAN_FILE_SECONDS
    def slow(*args):
        time.sleep(0.2)
        return orig_check(*args)
    try:
        rb.check_patterns = slow
        rb.SCAN_FILE_SECONDS = 0.05
        t0 = time.time()
        doc, notes, source = rb.head_report(str(ROOT / FIXTURE), "balanced", "", True)
        took = time.time() - t0
        assert doc["verdict"] == "YELLOW" and doc["meta"]["complete"] is False, doc["verdict"]
        assert any(f["title"].startswith("Slow-file") for f in doc["findings"])
        assert took < 5, f"head per-file alarm did not cut the slow check ({took:.1f}s)"
    finally:
        rb.check_patterns, rb.SCAN_FILE_SECONDS = orig_check, orig_seconds
    print("PASS inner/head mark incomplete scans and floor GREEN to YELLOW")


def test_argument_validation_and_complete_scan():
    r = scan(FIXTURE, "--max-seconds", "0")
    assert r.returncode == 1 and "greater than 0" in r.stderr, r.stderr[-300:]
    with tempfile.TemporaryDirectory() as td:
        out = Path(td, "r.json")
        r = scan(FIXTURE, "--strict", "--no-docker", "--no-osv", "--no-trust", "--json", str(out))
        assert r.returncode == 2, r.returncode
        d = json.loads(out.read_text(encoding="utf-8"))
        assert d["meta"]["complete"] is True and d["verdict"] == "RED", (d["verdict"], d["meta"].get("complete"))
    print("PASS --max-seconds validation and complete scans stay unchanged")


if __name__ == "__main__":
    test_budget_expiry_is_a_partial_report()
    test_per_file_alarm_end_to_end()
    test_inner_and_head_completeness()
    test_argument_validation_and_complete_scan()
    print("deadline tests passed")
