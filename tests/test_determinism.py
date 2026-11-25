#!/usr/bin/env python3
"""Determinism tests: the normalized comparison must ignore ordering/timings/paths and catch real changes."""
import copy, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import repobeagle as rb

fail = 0
def check(name, ok):
    global fail
    print(("PASS " if ok else "FAIL ") + name)
    if not ok:
        fail = 1

def f(sev, rule, line, file="src/a.js", tool="agent-checks"):
    return {"tool": tool, "severity": sev, "rule": rule, "file": file, "line": line,
            "title": f"{rule}: detail", "meaning": "why this matters", "snippet": "evidence"}

sha = "a" * 40
report_a = {"version": "1.156.0", "verdict": "RED",
            "meta": {"profile": "balanced", "ruleset": "0123456789ab", "seconds": 1.2,
                     "target": "/tmp/scan-one", "scanned_sha": sha},
            "findings": [f("critical", "critical-rule", 8), f("high", "high-rule", 3), f("low", "low-rule", 1)],
            "tools": {"gitleaks": {"version": "8.30.1", "seconds": 5.0},
                      "agent-checks": {"findings": 3, "seconds": 0.1}}}
report_b = copy.deepcopy(report_a)
report_b["findings"].reverse()
report_b["meta"]["seconds"] = 9.9
report_b["meta"]["target"] = "/tmp/scan-two"
report_b["tools"]["gitleaks"]["seconds"] = 6.0
report_b["findings"][0] = dict(reversed(list(report_b["findings"][0].items())))   # different dict insertion order

check("fixture really differs in order and timings",
      json.dumps(report_a["findings"]) != json.dumps(report_b["findings"])
      and report_a["meta"]["seconds"] != report_b["meta"]["seconds"])
check("normalized findings are order-independent",
      json.dumps(rb.normalize_findings(report_a["findings"])) == json.dumps(rb.normalize_findings(report_b["findings"])))
check("normalized findings are sorted by a total key",
      rb.normalize_findings(report_a["findings"]) ==
      sorted(rb.normalize_findings(report_a["findings"]),
             key=lambda f: (f.get("tool", ""), f.get("severity", ""), f.get("rule", ""), f.get("file", ""),
                            f.get("line", 0), f.get("title", ""), f.get("snippet", ""),
                            bool(f.get("suppressed")), f.get("meaning", ""))))
check("fingerprint ignores order, timings and the scan path",
      rb.report_fingerprint(report_a) == rb.report_fingerprint(report_b))
check("fingerprint is a stable sha256",
      len(rb.report_fingerprint(report_a)) == 64
      and rb.report_fingerprint(report_a) == rb.report_fingerprint(report_a))
check("matching reports compare equal", rb.rescan_difference(report_a, report_b)[0])

# a real change must be caught, with detail
changed = copy.deepcopy(report_b)
changed["findings"][0]["severity"] = "critical"
match, added, removed = rb.rescan_difference(report_a, changed)
check("field change caught", not match and added == [] and removed == [])
added_r = copy.deepcopy(report_a)
added_r["findings"].append(f("medium", "new-rule", 2, file="src/b.js"))
match, added, removed = rb.rescan_difference(report_a, added_r)
check("added finding caught with detail", not match and len(added) == 1 and added[0]["rule"] == "new-rule")
removed_r = copy.deepcopy(report_a)
removed_r["findings"].pop()
match, added, removed = rb.rescan_difference(report_a, removed_r)
check("removed finding caught with detail", not match and len(removed) == 1)

# toolchain provenance is part of the core; the network stages are excluded on request
bumped = copy.deepcopy(report_a)
bumped["tools"]["gitleaks"]["version"] = "8.31.0"
check("tool version bump caught", rb.report_fingerprint(report_a) != rb.report_fingerprint(bumped))
signed_net = copy.deepcopy(report_a)
signed_net["findings"] += [f("low", "Vulnerable dependency", 4, file="requirements.txt", tool="osv-scanner"),
                           f("low", "trust: new repository", 1, file="(repo)", tool="trust")]
signed_net["tools"]["osv-scanner"] = {"version": "2.7.0", "seconds": 3.1}
check("network findings are excluded for a rescan comparison",
      rb.rescan_difference(signed_net, report_a, offline_only=True)[0])
check("network findings are included by default",
      rb.report_fingerprint(signed_net) != rb.report_fingerprint(report_a))

# malformed entries never crash the comparison and never count as findings
check("malformed findings ignored",
      rb.normalize_findings([None, "x", {"severity": "nope"}, {"severity": "low", "tool": "agent-checks"}])
      == [{"tool": "agent-checks", "severity": "low"}])

sys.exit(fail)
