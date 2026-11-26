#!/usr/bin/env python3
"""Unit tests for the privacy helpers (no network, no repo code)."""
import os, sys, tempfile, json
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
check("redacts local phone", "****" in rb.redact_pii("call (415) 555-0132"))
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
    entries = rb.load_suppressions(d)
    act, sup, exp = rb.apply_suppressions([dict(findings[1])], entries)
    check("suppression glob", not act and sup and sup[0].get("suppressed") is True
          and sup[0]["suppression"]["rule"] == "telemetry-*" and not exp)

only = {"meta": {"privacy_mode": "only"}, "findings": [{"tool": "privacy"}, {"tool": "telemetry"}]}
mixed = {"meta": {"privacy_mode": "only"}, "findings": [{"tool": "privacy"}, {"tool": "gitleaks"}]}
excl = {"meta": {"privacy_mode": "excluded"}, "findings": [{"tool": "gitleaks"}]}
check("mode only consistent", rb.privacy_mode_consistent(only))
check("mode only mismatch", not rb.privacy_mode_consistent(mixed))
check("mode excluded consistent", rb.privacy_mode_consistent(excl))
check("mode full no constraint", rb.privacy_mode_consistent({"findings": [{"tool": "gitleaks"}]}))

with tempfile.TemporaryDirectory() as td:
    def lock(name, body):
        f = Path(td) / name; f.write_text(body); return rb.lockfile_packages(f, body)
    check("Gemfile.lock packages", "sentry-ruby" in lock("Gemfile.lock", "GEM\n  specs:\n    sentry-ruby (5.1.0)\n"))
    check("Pipfile.lock packages", "sentry-sdk" in lock("Pipfile.lock", '{"default": {"sentry-sdk": {"version": "1"}}}'))
    check("pubspec.lock packages", "sentry_flutter" in lock("pubspec.lock", 'packages:\n  sentry_flutter:\n    version: "7.0"\n'))
    check("mix.lock packages", "sentry" in lock("mix.lock", '%{\n  "sentry": {:hex, :sentry, "1.0"},\n}'))
    check("Package.resolved packages", "sentry-cocoa" in lock("Package.resolved", '{"pins": [{"identity": "sentry-cocoa"}]}'))
    check("packages.lock.json packages", "Sentry" in lock("packages.lock.json", '{"dependencies": {"net8.0": {"Sentry": {}}}}'))
    check("sentry gem matches", any(rb._pkg_is("sentry-ruby", pat) for pat in ("sentry-",)))

fs = [{"tool": "privacy", "title": "pii-email: a@b.c", "severity": "low", "file": "x", "line": 1, "snippet": "", "meaning": ""}]
summary = rb.privacy_summary(fs)
check("summary consistent", rb.privacy_summary_consistent({"version": rb.VERSION, "findings": fs, "privacy_summary": summary}))
check("summary mismatch", not rb.privacy_summary_consistent({"version": rb.VERSION, "findings": fs, "privacy_summary": {"trackers": {"ads": ["x"]}}}))
check("summary older version skipped", rb.privacy_summary_consistent({"version": "v0.1.0", "findings": fs, "privacy_summary": {"trackers": {}}}))

check("sdk opt-out call", bool(rb.TELEMETRY_OPTOUT_RE.search("posthog.opt_out_capturing()")))
check("sdk opt-out setter", bool(rb.TELEMETRY_OPTOUT_RE.search("analytics.setOptOut(true)")))
check("tracking false", bool(rb.TELEMETRY_OPTOUT_RE.search("trackingEnabled: false")))

check("own host match", rb._is_own("www.widget.dev", {"widget.dev"}))
check("foreign host mismatch", not rb._is_own("api.other.dev", {"widget.dev"}))

check("expiry RFC date", rb._expiry_days("Wed, 21 Oct 2015 07:28:00 GMT") < 0)
check("expiry ISO date", rb._expiry_days("2027-01-01T00:00:00Z") > 0)
check("expiry epoch", rb._expiry_days("1798761600") > 0)
check("expiry invalid", rb._expiry_days("not a date") is None)

check("ip header cf", bool(rb.IP_LOG_RE.search('headers.get("CF-Pseudo-IPv4")')))
check("ip header fastly", bool(rb.IP_LOG_RE.search("Fastly-Client-IP")))
check("ip header xclient", bool(rb.IP_LOG_RE.search("X-Client-IP")))

check("upload sink java", bool(rb.UPLOAD_SINK_RE.search("public void upload(MultipartFile file)")))
check("upload limit singular", bool(rb.UPLOAD_LIMIT_RE.search("express.json({ limit: '1mb' })")))
check("upload limit max", bool(rb.UPLOAD_LIMIT_RE.search("client_max_body_size 10m;")))

fs_v = [{"tool": "privacy", "title": "pii-email: a@b.c", "severity": "low", "file": "x", "line": 1, "snippet": "", "meaning": ""}]
_v, _w, _c = rb.verdict(fs_v, "balanced", None)
check("verdict consistent", rb.verdict_consistent({"verdict": _v, "counts": _c, "findings": fs_v, "meta": {"profile": "balanced"}}))
check("verdict mismatch", not rb.verdict_consistent({"verdict": "RED", "counts": _c, "findings": fs_v, "meta": {"profile": "balanced"}}))
check("verdict suppressed ignored", rb.verdict_consistent({"verdict": rb.verdict([], "balanced", None)[0], "findings": [dict(fs_v[0], suppressed=True)], "meta": {"profile": "balanced"}}))

hist = [rx for k, sev, rx, m in rb.BROWSER_CAPABILITIES if k == "browsing history"][0]
check("history bare window ignored", not re.search(hist, "window.history.back()") if (re := __import__("re")) else False)
check("history length matched", bool(__import__("re").search(hist, "if (history.length > 1)")))

pat = {v: pats for k, v, pats in rb.TELEMETRY_PACKAGES}
check("vercel speed package", any(rb._pkg_is("@vercel/speed-insights", x) for x in pat["Vercel Speed Insights"]))
check("embrace package", any(rb._pkg_is("@embrace-io/web-sdk", x) for x in pat["Embrace"]))
check("instabug package", any(rb._pkg_is("instabug-reactnative", x) for x in pat["Instabug"]))

pat = {v: pats for k, v, pats in rb.TELEMETRY_PACKAGES}
check("heap package", any(rb._pkg_is("heap-analytics", x) for x in pat["Heap Analytics"]))
check("onesignal package", any(rb._pkg_is("onesignal-cordova-plugin", x) for x in pat["OneSignal"]))
check("braze package", any(rb._pkg_is("@braze/web-sdk", x) for x in pat["Braze"]))
check("pendo package", any(rb._pkg_is("pendo-ios", x) for x in pat["Pendo"]))

check("iframe allow origin", rb._iframe_allow_perms('allow="camera https://cam.example; geolocation"') == ["camera (https://cam.example)", "geolocation"])
check("pii object prose ignored", not rb.PII_OBJECT_RE.search("closed for this session."))
check("pii object field matched", bool(rb.PII_OBJECT_RE.search("console.log(user.id)")))
check("phone US local", bool(rb.PHONE_LOCAL_RE.search("(415) 555-0132")))
check("phone UK local", bool(rb.PHONE_LOCAL_RE.search("020 7946 0958")))
check("phone AU local", bool(rb.PHONE_LOCAL_RE.search("0412 345 678")))
check("ruleset fingerprint", len(rb.RULESET) == 12)
with tempfile.TemporaryDirectory() as td:
    Path(td, "package.json").write_text('{"dependencies": {"posthog-js": "1"}, "pad": "' + "a" * 2_100_000 + '"}')
    big_findings, _ = rb.run_agent_checks(Path(td))
    check("huge file skipped for telemetry", not any(f["title"].startswith("telemetry-analytics: PostHog") for f in big_findings))

with tempfile.TemporaryDirectory() as td:
    f = Path(td) / "alert.sh"
    f.write_text('source "$(dirname "$0")/.env"\nHOST=$(hostname)\ncurl -fsS -X POST -d "host=$HOST" "$ALERT_WEBHOOK"\n')
    ex = []
    rb.check_exfil(Path(td), f, f.read_text(), ex)
    check("env read near network is not critical", ex and all(x["severity"] != "critical" for x in ex))
    check("env read is reported as medium", any(x["severity"] == "medium" for x in ex))

check("semver ordering", rb._parse_ver("v1.152.0") > rb._parse_ver("v1.3.0"))
check("semver reject", rb._parse_ver("stable") is None)
_no_update = os.environ.pop("BEAGLE_NO_UPDATE_CHECK", None)
with tempfile.TemporaryDirectory() as td:
    os.makedirs(Path(td) / "repobeagle")
    cache = Path(td) / "repobeagle" / "update.json"
    os.environ["XDG_CACHE_HOME"] = td
    cache.write_text(json.dumps({"ts": __import__("time").time(), "latest": "v9.9.9"}))
    check("update detection", rb.update_available() == "v9.9.9")
    cache.write_text(json.dumps({"ts": __import__("time").time(), "latest": "v1.152.0"}))
    check("no update when current", rb.update_available() is None)
    del os.environ["XDG_CACHE_HOME"]
if _no_update is not None:
    os.environ["BEAGLE_NO_UPDATE_CHECK"] = _no_update

with tempfile.TemporaryDirectory() as td:
    w = Path(td) / "repobeagle"
    w.write_text('#!/usr/bin/env bash\nexport BEAGLE_IMAGE="${BEAGLE_IMAGE:-ghcr.io/jvr0x/repobeagle:v1.0.0}"\n')
    os.environ["BEAGLE_BIN"] = td
    check("wrapper retarget", rb._retarget_wrapper("v1.152.0") and "javierbits/repobeagle:v1.152.0" in w.read_text())
    del os.environ["BEAGLE_BIN"]

sys.exit(fail)
