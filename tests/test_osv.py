#!/usr/bin/env python3
"""Offline OSV database tests: missing DB note, stale policy, corrupt zip, report warnings.

Hermetic: no database is downloaded; the cache is a temporary directory with synthetic files.
"""
import json, os, subprocess, sys, tempfile, time, zipfile
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

VULN = ROOT / "tests" / "fixtures" / "control-vuln"

def scan(cache, *extra):
    env = dict(os.environ, XDG_CACHE_HOME=str(cache))
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        out = Path(fh.name)
    try:
        r = subprocess.run([sys.executable, str(ROOT / "repobeagle.py"), "scan", str(VULN), "--no-docker",
                            "--no-trust", "--offline-vulnerabilities", "--no-color", "--json", str(out)] + list(extra),
                           capture_output=True, text=True, timeout=600, env=env)
        try:
            return json.loads(out.read_text(encoding="utf-8")), r
        except ValueError:
            return {}, r
    finally:
        out.unlink(missing_ok=True)

def fake_db(cache, age_days, payload=None):
    """A minimal valid database zip, or exactly `payload` bytes, with a chosen mtime."""
    d = Path(cache) / "osv-scalibr" / "pypi"
    d.mkdir(parents=True, exist_ok=True)
    p = d / "all.zip"
    if payload is None:
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("db.txt", "placeholder\n")
    else:
        p.write_bytes(payload)
    stamp = time.time() - age_days * 86400
    os.utime(p, (stamp, stamp))
    return p

with tempfile.TemporaryDirectory() as td:
    # a missing database must be a note, not a crash or a silent pass
    report, r = scan(Path(td) / "empty")
    meta = report["meta"]
    check("missing database is recorded and explained",
          r.returncode <= 2 and meta.get("offline_vulnerabilities") is True
          and meta["osv_db"]["ecosystems"] == [] and meta["osv_db"]["age_days"] is None
          and meta["osv_db"]["stale"] is False
          and any("offline OSV database missing at" in n for n in report["notes"]))

with tempfile.TemporaryDirectory() as td:
    # a database older than the policy is flagged in meta and in the notes
    fake_db(td, age_days=45)
    info = rb.osv_db_info() if (os.environ.get("XDG_CACHE_HOME") == str(td)) else None
    env = dict(os.environ, XDG_CACHE_HOME=td)
    out = subprocess.run([sys.executable, "-c", "import json,repobeagle as r;print(json.dumps(r.osv_db_info()))"],
                         capture_output=True, text=True, env=dict(env, PYTHONPATH=str(ROOT)), timeout=120)
    info = json.loads(out.stdout)
    check("freshness policy is computed", info["age_days"] >= 45 and info["stale"] is True
          and info["max_age_days"] == 30)
    report, r = scan(td)
    check("stale database is recorded and warned about in the scan",
          r.returncode <= 2 and report["meta"]["osv_db"]["stale"] is True
          and any("day(s) old (policy: 30 days)" in n for n in report["notes"]))

with tempfile.TemporaryDirectory() as td:
    # a corrupt zip must not crash the scan, and must not pass silently
    fake_db(td, age_days=0, payload=b"\x00garbage")
    report, r = scan(td)
    eco = (report["meta"]["osv_db"]["ecosystems"] or [{}])[0]
    check("corrupt database is detected and does not crash the scan",
          r.returncode <= 2 and "Traceback" not in r.stderr and eco.get("corrupt") is True
          and eco.get("bytes") == 8
          and any("offline OSV database unreadable for pypi" in n for n in report["notes"]))
    env = dict(os.environ, XDG_CACHE_HOME=td)
    status = subprocess.run([sys.executable, str(ROOT / "repobeagle.py"), "db"], capture_output=True,
                            text=True, env=env, timeout=120)
    check("db status flags the corrupt database",
          status.returncode == 0 and "(corrupt)" in status.stdout
          and "unreadable database for pypi" in status.stderr)

with tempfile.TemporaryDirectory() as td:
    fake_db(td, age_days=0)
    env = dict(os.environ, XDG_CACHE_HOME=td)
    status = subprocess.run([sys.executable, str(ROOT / "repobeagle.py"), "db"], capture_output=True, text=True,
                            env=env, timeout=120)
    check("db status explains how to use the database",
          status.returncode == 0 and "--offline-vulnerabilities" in status.stdout and "0 day(s) old" in status.stdout)
    stale = subprocess.run([sys.executable, "-c",
                             "import json,repobeagle as r;print(json.dumps(r.osv_db_info()))"],
                            capture_output=True, text=True, env=dict(env, BEAGLE_DB_MAX_AGE_DAYS="90"),
                            timeout=120)
    check("policy threshold is configurable", json.loads(stale.stdout)["stale"] is False
          and json.loads(stale.stdout)["max_age_days"] == 90)

# verify's warning is a pure function over the report meta
check("verify warns on a stale report database",
      "45 day(s) old" in (rb.osv_db_warning({"osv_db": {"stale": True, "age_days": 45, "max_age_days": 30}}) or ""))
check("verify warns when no database was recorded",
      "recorded no database" in (rb.osv_db_warning({"offline_vulnerabilities": True, "osv_db": {"ecosystems": []}}) or ""))
check("verify stays quiet for a fresh database",
      rb.osv_db_warning({"offline_vulnerabilities": True,
                         "osv_db": {"stale": False, "ecosystems": [{"ecosystem": "PyPI", "bytes": 1}],
                                    "age_days": 0, "max_age_days": 30}}) is None)

sys.exit(fail)
