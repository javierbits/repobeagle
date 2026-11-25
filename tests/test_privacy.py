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
check("url userinfo is not email", rb._in_url_authority("http://user:pass@host/path", 12))
check("email outside authority", not rb._in_url_authority("contact user@host now", 10))
check("address via the 1104 ignored", not rb.ADDRESS_INTL_RE.search("via the 1104"))
check("address Via Roma kept", bool(rb.ADDRESS_INTL_RE.search("Via Roma 12")))
check("address US", bool(rb.ADDRESS_RE.search("221B Baker Street")))
check("address prose ignored", not rb.ADDRESS_RE.search("2 gives your words a fresh place"))
check("address license kept", bool(rb.ADDRESS_RE.search("51 Franklin Street, Fifth Floor")))
check("address DE", bool(rb.ADDRESS_INTL_RE.search("Hauptstraße 12")))
check("address PO box", bool(rb.ADDRESS_INTL_RE.search("P.O. Box 42")))
check("reserved tld ignored", rb._endpoint_noise("example.invalid") and not rb._endpoint_noise("example.org"))

check("luhn visa", rb._card_number_ok("4111 1111 1111 1111"))
check("rejects timestamp", not rb._card_number_ok("1700000000000"))
check("rejects 14-digit int", not rb._card_number_ok("42424242424242"))
check("accepts amex", rb._card_number_ok("378282246310005"))
check("rejects decimal", not rb._card_number_ok("435.258435754"))

findings = [
    {"tool": "privacy", "severity": "low", "file": "a.js", "line": 1, "title": "pii-email: a***@x.dev", "snippet": "", "meaning": ""},
    {"tool": "telemetry", "severity": "high", "file": "a.js", "line": 2, "title": "telemetry-session-replay: Hotjar (transitive)", "snippet": "", "meaning": ""},
]
findings += [
    {"tool": "privacy", "severity": "low", "file": "a.js", "line": 3, "title": "third-party-script: cdn.x.dev", "snippet": "", "meaning": ""},
    {"tool": "privacy", "severity": "info", "file": "a.js", "line": 5, "title": "first-party-endpoint: own.dev", "snippet": "", "meaning": ""},
    {"tool": "privacy", "severity": "low", "file": "a.js", "line": 4, "title": "vendor-pii: anonymize_ip", "snippet": "", "meaning": ""},
]
s = rb.privacy_summary(findings)
check("summary groups trackers", s.get("trackers", {}).get("session-replay") == ["Hotjar"])
check("summary groups pii", s.get("pii") == ["a***@x.dev"])
check("summary groups third-party network", "cdn.x.dev" in (s.get("network") or []))
check("summary groups vendor configs", (s.get("vendor") or []) == ["anonymize_ip"])
check("summary separates first-party", (s.get("first_party") or []) == ["own.dev"] and "own.dev" not in (s.get("network") or []))
check("profile line", rb.privacy_profile(s).startswith("Privacy profile: 1 tracker"))

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

only = {"meta": {"privacy_mode": "only"}, "findings": [{"tool": "privacy"}, {"tool": "telemetry"}]}
mixed = {"meta": {"privacy_mode": "only"}, "findings": [{"tool": "privacy"}, {"tool": "gitleaks"}]}
excl = {"meta": {"privacy_mode": "excluded"}, "findings": [{"tool": "gitleaks"}]}
check("mode only consistent", rb.privacy_mode_consistent(only))
check("mode only mismatch", not rb.privacy_mode_consistent(mixed))
check("mode excluded consistent", rb.privacy_mode_consistent(excl))
check("mode full no constraint", rb.privacy_mode_consistent({"findings": [{"tool": "gitleaks"}]}))

sys.exit(fail)
