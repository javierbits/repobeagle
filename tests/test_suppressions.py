#!/usr/bin/env python3
"""Suppression lifecycle tests: parse format, expiry re-activation, warnings, meta.suppressions, `ignore`."""
import json, os, shutil, subprocess, sys, tempfile
from datetime import date, timedelta
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

TODAY = "2026-06-15"
ENV = {"BEAGLE_TODAY": TODAY}
os.environ.update(ENV)          # the in-process helpers must see the pinned date too
YESTERDAY = (date.fromisoformat(TODAY) - timedelta(days=1)).isoformat()
TOMORROW = (date.fromisoformat(TODAY) + timedelta(days=1)).isoformat()

# --- grammar: bare ids stay valid, reason and expiry are parsed --------------------
entry = rb.parse_suppression("telemetry-*")
check("bare rule ids still work", entry == {"rule": "telemetry-*", "reason": "", "until": None, "line": 0})
entry = rb.parse_suppression("pii-*  # GDPR review  @2030-01-01", 4)
check("reason and expiry parse", entry["rule"] == "pii-*" and entry["reason"] == "GDPR review"
      and entry["until"] == "2030-01-01" and entry["line"] == 4)
check("expiry without a reason parses", rb.parse_suppression("pii-* @2030-01-01")["until"] == "2030-01-01")
check("comments and blanks are not entries", rb.parse_suppression("# reviewed\n") is None
      and rb.parse_suppression("   ") is None)
bad = rb.parse_suppression("rule  # broken  @2030-13-40")
check("invalid dates are kept for a warning", bad["until"] == "2030-13-40"
      and rb.suppression_status(bad, date.fromisoformat(TODAY)) == "invalid")

check("status: active before the date",
      rb.suppression_status({"rule": "r", "until": TOMORROW}, date.fromisoformat(TODAY)) == "active")
check("status: expired after the date",
      rb.suppression_status({"rule": "r", "until": YESTERDAY}, date.fromisoformat(TODAY)) == "expired")
check("BEAGLE_TODAY pins the clock", rb._today() == date.fromisoformat(TODAY))

def scan(repo, extra=()):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        out = Path(fh.name)
    try:
        r = subprocess.run([sys.executable, str(ROOT / "repobeagle.py"), "scan", str(repo), "--no-docker",
                            "--no-osv", "--no-trust", "--no-color", "--json", str(out)] + list(extra),
                           capture_output=True, text=True, timeout=900, env=dict(os.environ, **ENV))
        try:
            return json.loads(out.read_text(encoding="utf-8")), r
        except ValueError:
            return {}, r
    finally:
        out.unlink(missing_ok=True)

def rule(finding):
    return finding["title"].split(":")[0]

with tempfile.TemporaryDirectory() as td:
    repo = Path(td) / "trap-npm"
    shutil.copytree(ROOT / "tests" / "fixtures" / "trap-npm", repo)
    # a legacy bare line and an entry with a reason and a future expiry
    (repo / rb.SUPPRESS_FILE).write_text(
        "Download-and-execute\n"
        f"npm lifecycle script*  # node setup reviewed  @{TOMORROW}\n")

    report, r = scan(repo)
    suppressed = {rule(f) for f in report["findings"] if f.get("suppressed")}
    check("active entries suppress their findings (legacy and structured)",
          any(r.startswith("Download-and-execute") for r in suppressed)
          and any(rule(f).startswith("npm lifecycle script") for f in report["findings"] if f.get("suppressed")))
    structured = [s for s in report["meta"]["suppressions"] if s["rule"].startswith("npm lifecycle")]
    check("meta.suppressions carries rule, reason, until and status",
          structured and structured[0]["reason"] == "node setup reviewed"
          and structured[0]["until"] == TOMORROW and structured[0]["status"] == "active")
    f = next(f for f in report["findings"] if rule(f).startswith("npm lifecycle"))
    check("the finding carries its suppression record",
          f["suppression"]["reason"] == "node setup reviewed" and f["suppression"]["until"] == TOMORROW)

    # an expired entry re-activates the finding and is warned about
    (repo / rb.SUPPRESS_FILE).write_text(
        f"npm lifecycle script*  # review ran out  @{YESTERDAY}\n")
    report, r = scan(repo)
    f = next(f for f in report["findings"] if rule(f).startswith("npm lifecycle"))
    check("an expired entry re-activates the finding",
          not f.get("suppressed") and f.get("suppression_expired", {}).get("until") == YESTERDAY)
    check("the expiry is warned about in the notes and meta",
          any(f"expired on {YESTERDAY}" in n for n in report["notes"])
          and report["meta"]["suppressions"][0]["status"] == "expired")
    check("the verdict counts the re-activated finding",
          report["counts"]["critical"] >= 1 and r.returncode == 2)

# --- repobeagle ignore: append, update, validate, list ---------------------------
with tempfile.TemporaryDirectory() as td:
    ign = Path(td) / ".repobeagleignore"
    base = [sys.executable, str(ROOT / "repobeagle.py"), "ignore"]
    run = lambda *args: subprocess.run(base + list(args), capture_output=True, text=True, timeout=300,
                                       env=dict(os.environ, **ENV))
    r = run("pii-*", "--reason", "policy reviewed", "--until", "2030-01-01", "--file", str(ign))
    parsed = rb.parse_suppression(ign.read_text().strip())
    check("ignore appends a parseable line",
          r.returncode == 0 and parsed["rule"] == "pii-*" and parsed["reason"] == "policy reviewed"
          and parsed["until"] == "2030-01-01")
    run("pii-*", "--reason", "updated reason", "--file", str(ign))
    lines = [ln for ln in ign.read_text().splitlines() if ln.strip()]
    check("ignore updates instead of duplicating", len(lines) == 1 and "updated reason" in lines[0]
          and "2030-01-01" not in lines[0])
    check("ignore rejects an invalid date", run("x", "--until", "2030-13-40", "--file", str(ign)).returncode == 1)

    r = run("--list", "--json", str(ign) + ".json", "--file", str(ign))
    listed = json.loads(Path(str(ign) + ".json").read_text())
    check("ignore --list shows status", r.returncode == 0 and listed and listed[0]["rule"] == "pii-*"
          and listed[0]["status"] == "active")

    # --report validation: a real rule id passes, a typo fails
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        rep = Path(fh.name)
    subprocess.run([sys.executable, str(ROOT / "repobeagle.py"), "scan", str(ROOT / "tests" / "fixtures" / "trap-npm"),
                    "--no-docker", "--no-osv", "--no-trust", "--json", str(rep), "--no-color"],
                   capture_output=True, timeout=900)
    check("ignore --report accepts a matching rule",
          run("npm lifecycle script*", "--report", str(rep), "--file", str(ign)).returncode == 0)
    check("ignore --report rejects a typo",
          run("npm lifecycl script*", "--report", str(rep), "--file", str(ign)).returncode == 1)
    rep.unlink(missing_ok=True)

sys.exit(fail)
