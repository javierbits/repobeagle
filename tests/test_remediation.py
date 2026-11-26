#!/usr/bin/env python3
"""Remediation tests: coverage per rule id, rule-id lookup, wording rules, Markdown/SARIF surfacing."""
import json, subprocess, sys, tempfile
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

def fixture_findings():
    fixtures = ["trap-npm", "trap-skill", "trap-gha", "trap-markdown", "trap-build", "trap-binary",
                "trap-telemetry", "trap-privacy", "ignore-suppressed", "control-clean"]
    out = []
    for fx in fixtures:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
            path = Path(fh.name)
        try:
            subprocess.run([sys.executable, str(ROOT / "repobeagle.py"), "scan", f"tests/fixtures/{fx}",
                            "--no-docker", "--no-osv", "--no-trust", "--no-color", "--json", str(path)],
                           capture_output=True, text=True, timeout=900)
            try:
                out += json.loads(path.read_text(encoding="utf-8")).get("findings") or []
            except ValueError:
                pass
        finally:
            path.unlink(missing_ok=True)
    return out

# coverage review: every rule id seen in the fixtures has an action or a documented reason for none
findings = fixture_findings()
audit = rb.remediation_audit(findings)
check("every fixture rule id is covered", not audit["uncovered"] and len(audit["fixed"]) >= 30)
check("documented no-action rules exist", "consent-manager" in audit["documented_none"]
      and "external-endpoint" in audit["documented_none"])
check("mixed rule families are identified, not hidden", "privacy-doc" in audit["mixed"])
print(f"  remediation audit: {len(audit['fixed'])} fixed, {len(audit['documented_none'])} documented none, "
      f"{len(audit['mixed'])} mixed, {len(audit['uncovered'])} uncovered")

# table lookup by rule id (title prefix), including the scanner classes and the deliberate none
samples = {
    "cookie-flags: Set-Cookie missing HttpOnly": "Secure; HttpOnly; SameSite",
    "gha-unpinned-action: `uses:` is not pinned": "40-character commit SHA",
    "install-time-network: python module scope": "module scope",
    "import-time-storage: javascript module scope": "module scope",
    "Cookie lifetime > 1 year": None,
    "Hardcoded secret: generic-api-key": "rotate the credential",
    "Bandit B113: request_without_timeout": "timeout=",
    "GuardDog npm package: threat-filesystem-read": "pin a version you reviewed",
    "md-padded-line: Line padded with whitespace": "visible text",
}
for title, want in samples.items():
    got = rb.remediation_for({"title": title})
    if want is None:
        continue
    check(f"lookup: {title.split(':')[0]}", bool(got) and want in got)
check("informational rule has a documented reason and no advice",
      rb.remediation_for({"title": "consent-manager: cookiebot"}) is None
      and "positive signal" in (rb.no_remediation_reason({"title": "consent-manager: cookiebot"}) or ""))
check("privacy-doc missing vs present diverge",
      bool(rb.remediation_for({"title": "privacy-doc: no privacy policy file"}))
      and rb.remediation_for({"title": "privacy-doc: privacy policy present"}) is None)
check("semgrep findings get the rule-message action",
      "rule message" in (rb.remediation_for({"title": "python.lang.security.audit.x", "tool": "semgrep"}) or ""))
check("an unknown rule stays without advice", rb.remediation_for({"title": "totally-new-rule: detail"}) is None)

# wording rules: one deterministic line, short, no placeholders
texts = [t for _, t in rb.REMEDIATION] + [rb.remediation_for({"title": k, "tool": f.get("tool")})
                                          for f in findings for k in [f.get("title")]]
texts = [t for t in texts if t]
check("every remediation is one short line",
      all(isinstance(t, str) and t and "\n" not in t and len(t) <= 170 and "TODO" not in t for t in texts))
check("remediation is deterministic", rb.remediation_for({"title": "cookie-flags: x"})
      == rb.remediation_for({"title": "cookie-flags: x"}))
check("advice keeps an alternative where it could be wrong",
      "or " in rb.remediation_for({"title": "GuardDog npm package: threat-filesystem-read"})
      and "or review" in rb.remediation_for({"title": "npm lifecycle script 'postinstall' runs automatically on install"}))

# Markdown: the Fix column escapes pipes and newlines
report = {"verdict": "YELLOW", "counts": {"high": 1}, "meta": {"profile": "balanced"},
          "findings": [{"tool": "agent-checks", "severity": "high", "file": "a.js", "line": 2,
                        "title": "rule-a: fix | this\nnow", "remediation": "fix | this\nand that"}]}
md = rb.markdown_report(report)
row = next(line for line in md.splitlines() if line.startswith("| high |"))
check("markdown Fix column escapes pipes and newlines",
      "fix \\| this and that" in row and "| Fix |" in md)
check("markdown keeps the advice in its own column",
      any(line.startswith("| high | `rule-a` | `a.js:2` |") and "fix \\| this and that" in line
          for line in md.splitlines()))

# SARIF: remediation travels as a result property
doc = rb.sarif_report(report)
props = [r.get("properties", {}).get("remediation") for r in doc["runs"][0]["results"]]
check("SARIF carries the remediation property", props and props[0] == "fix | this\nand that")

sys.exit(fail)
