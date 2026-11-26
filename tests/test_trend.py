#!/usr/bin/env python3
"""trend: ordered verdict/rule history over local reports; malformed and foreign-ruleset reports are skipped."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCANNER = ROOT / "repobeagle.py"
FIXTURES = ROOT / "tests" / "fixtures" / "trend"
fail = 0


def check(name, ok, detail=""):
    global fail
    print(("PASS " if ok else "FAIL ") + name + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        fail = 1


def run(*args, timeout=120):
    return subprocess.run([sys.executable, str(SCANNER), *args], cwd=ROOT, capture_output=True, text=True,
                          timeout=timeout, env=dict(os.environ, XDG_CACHE_HOME=tempfile.mkdtemp(),
                                                    BEAGLE_NO_UPDATE_CHECK="1"))


def trend(targets, out):
    if isinstance(targets, (str, Path)):
        targets = [targets]
    r = run("trend", *[str(t) for t in targets], "--no-color", "--json", str(out))
    data = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
    return r, data


with tempfile.TemporaryDirectory() as td:
    tdp = Path(td)
    # Copy the fixture so the test can rewrite one file without touching the repo.
    for p in FIXTURES.glob("report-*.json"):
        shutil.copy(p, tdp / p.name)
    out = tdp / "trend.json"
    r, data = trend(tdp, out)
    check("trend exits 0 with usable reports", r.returncode == 0, (r.stderr or r.stdout)[-400:])
    verdicts = [e["verdict"] for e in data.get("reports") or []]
    check("ordered verdict series, malformed report ignored", verdicts == ["GREEN", "YELLOW", "RED", "GREEN"],
          str(verdicts))
    check("newest timestamp anchors the series", [e["at"] for e in data.get("reports") or []][:1] ==
          ["2026-10-01T00:00:00Z"], str([e["at"] for e in data.get("reports") or []]))
    check("first RED is the earliest RED report", (data.get("first_red") or {}).get("at") == "2026-10-03T00:00:00Z",
          str(data.get("first_red")))
    check("current verdict and streak come from the newest report",
          (data.get("current") or {}).get("verdict") == "GREEN" and (data.get("current") or {}).get("streak") == 1,
          str(data.get("current")))
    rules = [g["rule"] for g in data.get("regressions") or []]
    check("per-rule regressions are ordered by first appearance",
          rules == ["gha-unpinned-action", "gha-curl-pipe-shell"], str(rules))
    reasons = {Path(s["file"]).name: s["reason"] for s in data.get("skipped") or []}
    check("malformed report is skipped with a reason", reasons.get("report-4444444.json") == "not valid JSON",
          str(reasons))
    check("foreign ruleset is skipped with a reason",
          str(reasons.get("report-6666666.json", "")).startswith("different ruleset"), str(reasons))
    check("printed output carries the series and first RED",
          "series: G Y R G" in r.stdout and "first RED: 2026-10-03T00:00:00Z" in r.stdout, r.stdout[-400:])
    check("skipped reports are reported, not fatal",
          "report-4444444.json: not valid JSON" in r.stdout, r.stdout[-400:])

    # Explicit files work like a directory, and the series stays ordered by timestamp.
    out2 = tdp / "trend-files.json"
    r2, data2 = trend([tdp / "report-5555555.json", tdp / "report-1111111.json", tdp / "report-2222222.json"], out2)
    check("explicit report files are accepted and ordered",
          r2.returncode == 0 and [e["verdict"] for e in data2.get("reports") or []] == ["GREEN", "YELLOW", "GREEN"],
          (r2.stderr or r2.stdout)[-400:])

    # Reports without meta.scanned_at fall back to file mtime for ordering.
    mdir = tdp / "mtime"
    mdir.mkdir()
    for name, verdict, when in (("report-aaaaaaa.json", "RED", 1_700_000_000),
                                ("report-bbbbbbb.json", "GREEN", 1_700_100_000)):
        p = mdir / name
        p.write_text(json.dumps({"version": "1.0.0", "verdict": verdict, "counts": {},
                                 "meta": {"scanned_sha": name[7:14], "ruleset": "abc123abc123"},
                                 "findings": []}), encoding="utf-8")
        os.utime(p, (when, when))
    out3 = tdp / "trend-mtime.json"
    r3, data3 = trend(mdir, out3)
    check("local reports without scanned_at are ordered by mtime",
          r3.returncode == 0 and [e["verdict"] for e in data3.get("reports") or []] == ["RED", "GREEN"],
          (r3.stderr or r3.stdout)[-400:])

    # A ruleset change resets the series: older reports cannot be compared with the newest one.
    sdir = tdp / "shift"
    sdir.mkdir()
    for p in (tdp / "report-1111111.json", tdp / "report-2222222.json"):
        shutil.copy(p, sdir / p.name)
    newest = json.loads((sdir / "report-2222222.json").read_text(encoding="utf-8"))
    newest["meta"]["ruleset"] = "ffffffffffff"
    (sdir / "report-2222222.json").write_text(json.dumps(newest), encoding="utf-8")
    out4 = tdp / "trend-shift.json"
    r4, data4 = trend(sdir, out4)
    check("older reports from another ruleset are skipped, not mis-ordered",
          r4.returncode == 0 and [e["verdict"] for e in data4.get("reports") or []] == ["YELLOW"]
          and len(data4.get("skipped") or []) == 1, (r4.stderr or r4.stdout)[-400:])

    # A fresh scan records meta.scanned_at, and its report is a valid single-entry trend input.
    scan_out = tdp / "scan.json"
    rs = run("scan", "tests/fixtures/control-clean", "--no-color", "--json", str(scan_out),
             "--no-osv", "--no-trust", "--no-cache", timeout=600)
    scanned_at = ((json.loads(scan_out.read_text(encoding="utf-8")).get("meta") or {}).get("scanned_at")
                  if scan_out.exists() else None)
    check("a fresh scan records meta.scanned_at",
          rs.returncode == 0 and isinstance(scanned_at, str) and
          bool(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", scanned_at)), f"{scanned_at!r} rc={rs.returncode}")
    out6 = tdp / "trend-one.json"
    r6, data6 = trend(scan_out, out6)
    check("a single report is a valid trend input",
          r6.returncode == 0 and len(data6.get("reports") or []) == 1
          and (data6.get("reports") or [{}])[0].get("verdict") == "GREEN",
          (r6.stderr or r6.stdout)[-400:])

    # Hostile count values degrade to 0 instead of crashing the series.
    wdir = tdp / "weird"
    wdir.mkdir()
    (wdir / "report-ccccccc.json").write_text(json.dumps({
        "version": "1.0.0", "verdict": "YELLOW", "counts": {"high": "many", "low": None},
        "meta": {"scanned_sha": "cccccccc", "scanned_at": "2026-10-06T00:00:00Z", "ruleset": "abc123abc123"},
        "findings": []}), encoding="utf-8")
    out7 = tdp / "trend-weird.json"
    r7, data7 = trend(wdir, out7)
    check("non-numeric counts do not crash the series",
          r7.returncode == 0 and (data7.get("reports") or [{}])[0].get("counts") ==
          {"critical": 0, "high": 0, "medium": 0, "low": 0}, (r7.stderr or r7.stdout)[-400:])

    # Nothing usable is an error, with the reason on stderr.
    bad = tdp / "bad"
    bad.mkdir()
    shutil.copy(tdp / "report-4444444.json", bad / "report-4444444.json")
    out5 = tdp / "trend-bad.json"
    r5, _ = trend(bad, out5)
    check("a directory with only malformed reports exits 1 and says why",
          r5.returncode == 1 and "not valid JSON" in r5.stderr, (r5.stderr or r5.stdout)[-400:])

sys.exit(fail)
