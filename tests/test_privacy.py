#!/usr/bin/env python3
"""Unit tests for the privacy helpers (no network, no repo code)."""
import sys, tempfile, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import repobeagle as rb

fail = 0
def check(name, ok):
    global fail
    print(("PASS " if ok else "FAIL ") + name)
    if not ok:
        fail = 1

check("redacts email", rb.redact_pii("mail support@example.dev") == "mail s***@example.dev")
check("redacts card", rb.redact_pii("4111 1111 1111 1111") == "4111 **** **** 1111")
check("redacts ssn", rb.redact_pii("123-45-6789") == "***-**-6789")
check("redacts phone", "****" in rb.redact_pii("+46701234567"))
check("keeps text", rb.redact_pii("no pii here") == "no pii here")

check("luhn visa", rb._card_number_ok("4111 1111 1111 1111"))
check("rejects timestamp", not rb._card_number_ok("1700000000000"))
check("rejects decimal", not rb._card_number_ok("435.258435754"))

findings = [
    {"tool": "privacy", "severity": "low", "file": "a.js", "line": 1, "title": "pii-email: a***@x.dev", "snippet": "", "meaning": ""},
    {"tool": "telemetry", "severity": "high", "file": "a.js", "line": 2, "title": "telemetry-session-replay: Hotjar (transitive)", "snippet": "", "meaning": ""},
]
s = rb.privacy_summary(findings)
check("summary groups trackers", s.get("trackers", {}).get("session-replay") == ["Hotjar"])
check("summary groups pii", s.get("pii") == ["a***@x.dev"])

with tempfile.TemporaryDirectory() as d:
    Path(d, "CNAME").write_text("widget.dev\n")
    Path(d, "package.json").write_text(json.dumps({"homepage": "https://www.widget.dev/x"}))
    own = rb.own_domains(d)
    check("own domains from CNAME", "widget.dev" in own)
    check("own host match", rb._is_own("api.widget.dev", own))
    check("foreign host mismatch", not rb._is_own("api.other.dev", own))

with tempfile.TemporaryDirectory() as d:
    Path(d, ".repobeagleignore").write_text("# reviewed\ntelemetry-*\n")
    pats = rb.load_suppressions(d)
    act, sup = rb.apply_suppressions([dict(findings[1])], pats)
    check("suppression glob", not act and sup and sup[0].get("suppressed") is True)

sys.exit(fail)
