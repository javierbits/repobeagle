#!/usr/bin/env python3
"""T12 rule-level evidence ledger: zero-hit assertions, hit attribution, incomplete scans, size bound."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import repobeagle as rb

fail = 0
FLAGS = ["--no-docker", "--no-osv", "--no-trust", "--no-cache", "--no-color"]


def check(name, ok, detail=""):
    global fail
    print(("PASS " if ok else "FAIL ") + name + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        fail = 1


def scan(fixture):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        out = Path(fh.name)
    try:
        r = subprocess.run([sys.executable, "repobeagle.py", "scan", f"tests/fixtures/{fixture}", *FLAGS,
                            "--json", str(out)],
                           cwd=ROOT, capture_output=True, text=True, timeout=600,
                           env=dict(__import__("os").environ, XDG_CACHE_HOME=tempfile.mkdtemp()))
        return json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}, r
    finally:
        out.unlink(missing_ok=True)


clean, r = scan("control-clean")
checks = ((clean.get("meta") or {}).get("checks") or {})
check("control-clean records the evaluated rules", r.returncode == 0 and len(checks) == len(rb.EVIDENCE_RULES),
      f"{len(checks)} entries, rc={r.returncode}")
check("zero-hit rules say what they evaluated for",
      all(v["evaluated"] and v["files"] > 0 and v["hits"] == 0 and v["negative"] and v["family"]
          for v in checks.values()),
      json.dumps(list(checks.values())[:1]))
check("the registry documents the privacy rules in the ledger",
      all(checks[rule]["documented"] for rule, family, _ in rb.EVIDENCE_RULES if family == "privacy"))
check("the console lists the rules evaluated with zero hits",
      "Checks run:" in r.stdout and "0 with hits" in r.stdout and "gha-curl-pipe-shell" in r.stdout,
      r.stdout[-400:])

gha, r = scan("trap-gha")
gha_checks = (gha.get("meta") or {}).get("checks") or {}
check("hits are attributed to the exact rule",
      gha_checks.get("gha-curl-pipe-shell", {}).get("hits", 0) >= 1
      and gha_checks.get("gha-unpinned-action", {}).get("hits", 0) >= 1,
      json.dumps({k: v["hits"] for k, v in gha_checks.items() if v["hits"]}))

npm, _ = scan("trap-npm")
npm_checks = (npm.get("meta") or {}).get("checks") or {}
check("sentence-style agent rules are in the ledger too",
      npm_checks.get("npm lifecycle script 'postinstall' runs automatically on install", {}).get("hits", 0) >= 1,
      json.dumps({k: v["hits"] for k, v in npm_checks.items() if v["hits"]}))

bound = rb.build_ledger([], [], 100_000, True)
check("the ledger stays bounded on a 100k-file repo",
      len(json.dumps(bound)) <= rb.LEDGER_JSON_BUDGET and next(iter(bound.values()))["files"] == 100_000,
      f"{len(json.dumps(bound))} bytes")
check("no per-file paths are stored", "files" in next(iter(bound.values()))
      and isinstance(next(iter(bound.values()))["files"], int)
      and all(not isinstance(v, list) or all(isinstance(x, str) and "/" not in x for x in v)
              for v in next(iter(bound.values())).values()))

partial = rb.build_ledger([], [], 10, False)
check("an incomplete scan marks the negatives unproven",
      all(not v["evaluated"] for v in partial.values()), json.dumps(next(iter(partial.values()))))
supp = rb.build_ledger([], [{"rule": "pii-in-url"}], 1, True)
check("suppressed hits are counted separately", supp["pii-in-url"]["hits"] == 0
      and supp["pii-in-url"]["suppressed"] == 1, json.dumps(supp["pii-in-url"]))

sys.exit(fail)
