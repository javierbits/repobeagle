#!/usr/bin/env python3
"""Rule registry (R4): explicit Rule metadata, stable ids on findings, no title surgery."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))
import repobeagle as rb
import gen_rule_registry

fail = 0


def check(name, ok, detail=""):
    global fail
    print(("PASS " if ok else "FAIL ") + name + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        fail = 1


rows = gen_rule_registry.rows()
check("the README rule table parses into explicit rules", len(rows) >= 50, str(len(rows)))
check("registry.py is in sync with the README rule table",
      gen_rule_registry.TARGET.read_text(encoding="utf-8") == gen_rule_registry.render(),
      "run python3 tools/gen_rule_registry.py")
check("every documented rule has an explicit Rule object",
      all(r in rb.RULES for r, _, _ in rows) and len(rb.RULES) == len(rows), str(len(rb.RULES)))
check("Rule fields are complete",
      all(isinstance(r, rb.Rule) and r.id == key and r.severity and r.meaning and r.docs
          for key, r in rb.RULES.items()))
check("registry ids are accepted by the scanner's known-rule set",
      set(rb.RULES) <= rb.known_rule_ids(),
      str(sorted(set(rb.RULES) - rb.known_rule_ids())[:8]))

f = rb.finding("agent-checks", "high", "a.py", 1, "rule-one: detail text")
check("finding() materializes the stable rule id", f.get("rule") == "rule-one", str(f))
check("_rule_of reads the field instead of splitting the title",
      rb._rule_of({"rule": "rule-one", "title": "something-else: detail"}) == "rule-one")
check("_rule_of still understands pre-registry findings",
      rb._rule_of({"title": "rule-two: detail"}) == "rule-two")

snapshot_dir = ROOT / "tests" / "snapshots" / "reports"
snapshots = sorted(snapshot_dir.glob("*.json"))
check("report snapshots exist", len(snapshots) >= 8, str(len(snapshots)))
missing = []
unknown = set()
for snap in snapshots:
    doc = json.loads(snap.read_text(encoding="utf-8"))
    for finding in doc.get("findings") or []:
        rule = finding.get("rule")
        if not rule:
            missing.append(f"{snap.name}:{finding.get('title')}")
            continue
        prefix = str(finding.get("title", "")).split(":")[0].split(" (")[0]
        if rule != prefix:
            missing.append(f"{snap.name}:{rule} != {prefix}")
        if rule not in rb.known_rule_ids():
            unknown.add(rule)
check("every snapshot finding carries its rule id", not missing, str(missing[:4]))
check("every emitted rule id is known (registry or dynamic tables)", not unknown, str(sorted(unknown)[:8]))

# Rule lookup is additive: reports from before the registry still explain fine.
legacy = {"verdict": "YELLOW", "counts": {"high": 1, "medium": 0, "low": 0, "critical": 0, "info": 0},
          "meta": {"profile": "balanced", "ruleset": "x"}, "findings": [
              {"tool": "agent-checks", "severity": "high", "file": "a.py", "line": 1,
               "title": "legacy-rule: old report", "snippet": "", "meaning": ""}]}
check("legacy findings without `rule` still resolve", rb._rule_of(legacy["findings"][0]) == "legacy-rule")

sys.exit(fail)
