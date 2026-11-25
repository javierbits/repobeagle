#!/usr/bin/env bash
# Regression tests. Shallow clone only; nothing is executed or extracted.
# Usage: tests/run_tests.sh [--offline]   (offline = local fixtures only)
cd "$(dirname "$0")/.." || exit 1
RG=./repobeagle; fail=0
export BEAGLE_NO_UPDATE_CHECK=1   # offline suite: no GitHub release API calls
check(){ # target expected-verdicts(regex) [extra args]; RULES="a b" = rule names that must appear
  local t=$1 exp=$2; shift 2
  local j; j=$(mktemp)
  $RG scan "$t" --no-color --json "$j" "$@" >/dev/null 2>&1
  local v; v=$(python3 -c "import json;print(json.load(open('$j'))['verdict'])" 2>/dev/null || echo ERROR)
  if [[ $v =~ ^($exp)$ ]]; then echo "PASS $v  $t"; else echo "FAIL $v (want $exp)  $t"; fail=1; fi
  if [[ -n "${RULES:-}" ]]; then
    local miss; miss=$(python3 -c "import json,sys;t={f['title'].split(':')[0] for f in json.load(open('$j'))['findings']};print(' '.join(r for r in sys.argv[1:] if r not in t))" $RULES 2>/dev/null)
    if [[ -z $miss ]]; then echo "PASS rules  $t"; else echo "FAIL missing rules: $miss  $t"; fail=1; fi
  fi
  rm -f "$j"
}
check tests/fixtures/trap-npm   RED
check tests/fixtures/trap-skill RED
L="--no-osv --no-trust"
RULES="gha-pwn-request gha-secret-echo gha-curl-pipe-shell gha-privileged-trigger gha-write-permissions gha-unpinned-action" \
  check tests/fixtures/trap-gha "YELLOW|RED" $L
RULES="md-comment-instruction md-details-instruction md-alt-title-instruction md-css-hidden md-padded-line" \
  check tests/fixtures/trap-markdown "YELLOW|RED" $L
RULES="go-generate-fetch rust-build-rs node-gyp-action pip-build-hook install-time-fetch make-just-hooks" \
  check tests/fixtures/trap-build "YELLOW|RED" $L
RULES="magic-mismatch typosquat-dep high-entropy-blob minified-outside-dist" \
  check tests/fixtures/trap-binary "YELLOW|RED" $L
RULES="telemetry-session-replay telemetry-analytics telemetry-crash telemetry-apm telemetry-identify session-replay-mask" \
  check tests/fixtures/trap-telemetry "YELLOW|RED" $L
RULES="third-party-cdn insecure-endpoint cookie-write browser-storage consent-manager android-permission extension-permission cookie-flags fingerprint pii-log pii-email pii-phone pii-address pii-postcode import-time-network import-time-storage ip-logging android-feature tracking-params pii-in-url privacy-doc browser-capability macos-entitlement client-id ios-tracking ios-tracking-domain ios-api-category ios-data-type dnt-respect consent-order data-retention upload-surface upload-limit store-disclosure referrer-policy permissions-policy session-replay-mask android-cleartext android-queries form-method ios-cleartext ios-tracking-declaration tracking-cookie pii-ssn pii-card ios-purpose-string consent-mode consent-state vendor-pii extension-connectable first-party-endpoint third-party-embed third-party-form third-party-script third-party-preconnect third-party-preload third-party-stylesheet third-party-media cookie-lifetime iframe-allow extension-resource undisclosed-vendor telemetry-crash telemetry-analytics telemetry-session-replay telemetry-ads" \
  check tests/fixtures/trap-privacy "YELLOW|RED" $L
j=$(mktemp); $RG scan tests/fixtures/trap-privacy --no-color --json "$j" $L >/dev/null 2>&1
python3 -c "import json,sys;d=json.load(open('$j'));s=d.get('privacy_summary') or {};ok=bool(s.get('trackers',{}).get('session-replay')) and bool(s.get('pii'));print('PASS privacy summary' if ok else 'FAIL privacy summary');sys.exit(0 if ok else 1)" || fail=1
python3 -c "import json,sys;d=json.load(open('$j'));p=(d.get('meta') or {}).get('privacy_profile') or '';ok=p.startswith('Privacy profile:') and 'tracker vendor' in p;print('PASS privacy profile in JSON' if ok else 'FAIL privacy profile in JSON');sys.exit(0 if ok else 1)" || fail=1
python3 -c "import json,sys;d=json.load(open('$j'));s=d.get('privacy_summary') or {};ok=bool(s.get('masking')) and bool(s.get('identity')) and any('IP address' in x for x in (s.get('pii') or [])) and any('clipboard' == x for x in (s.get('permissions') or []));print('PASS privacy summary completeness' if ok else 'FAIL privacy summary completeness');sys.exit(0 if ok else 1)" || fail=1
python3 -c "import json,sys;d=json.load(open('$j'));e=[x for x in d['findings'] if x['title'].startswith('pii-email')];ok=any('s***@widget.dev' in x['snippet'] and 's***@widget.dev' in x['title'] for x in e);print('PASS PII redacted in snippets' if ok else 'FAIL PII redaction');sys.exit(0 if ok else 1)" || fail=1
python3 tools/make_badge.py "$j" --endpoint "$j.badge" >/dev/null 2>&1
python3 -c "import json,sys;d=json.load(open('$j.badge'));ok=bool(d.get('privacy',{}).get('trackers'));print('PASS badge privacy counts' if ok else 'FAIL badge privacy counts');sys.exit(0 if ok else 1)" || fail=1
rm -f "$j.badge"
python3 -c "import json,sys;d=json.load(open('$j'));e=[f for f in d['findings'] if f['title'].startswith('pii-email')];m=[f for f in d['findings'] if f['title'].startswith('pii-log')];ok=bool(e) and all(f['severity']=='info' for f in e) and any(f['severity']=='info' for f in m);print('PASS role email + masked log are info' if ok else 'FAIL severity refinement');sys.exit(0 if ok else 1)" || fail=1
python3 -c "import json,sys;d=json.load(open('$j'));fs=d['findings'];ok=(any(f['title'].startswith('third-party-script') and 'preloadscript' in f['title'] for f in fs) and any(f['title'].startswith('iframe-allow') and 'cam.example' in f['meaning'] for f in fs) and any(f['title'].startswith('android-queries') and 'android.intent.action.VIEW' in f['title'] for f in fs) and any('020 7946 0958' in f['title'] for f in fs) and any('0412 345 678' in f['title'] for f in fs) and len((d.get('meta') or {}).get('ruleset',''))==12);print('PASS aggregated rule coverage' if ok else 'FAIL aggregated rule coverage');sys.exit(0 if ok else 1)" || fail=1
j2=$(mktemp); $RG scan tests/fixtures/trap-privacy --no-color --json "$j2" --min-severity high $L >/tmp/rb-minsev.txt 2>&1 || true
if grep -q "printing findings at/above high" /tmp/rb-minsev.txt && ! grep -q "^  LOW" /tmp/rb-minsev.txt; then echo "PASS --min-severity hides lows"; else echo "FAIL --min-severity hides lows"; fail=1; fi
python3 -c "import json,sys;d=json.load(open('$j2'));ok=any(f['severity']=='low' for f in d['findings']);print('PASS --min-severity keeps JSON' if ok else 'FAIL --min-severity JSON');sys.exit(0 if ok else 1)" || fail=1
rm -f "$j2" /tmp/rb-minsev.txt
rm -f "$j"
if [[ "$($RG --version)" == *"RepoBeagle $(sed 's/^v//' VERSION)"* ]] && [[ "$($RG version)" == "$(sed 's/^v//' VERSION)" ]]; then
  echo "PASS version flags"; else echo "FAIL version flags"; fail=1; fi
check tests/fixtures/trap-gha RED $L --strict
check tests/fixtures/control-clean GREEN $L --strict   # pinned actions, dist bundle, normal README, real deps
check tests/fixtures/ignore-suppressed GREEN $L   # .repobeagleignore suppresses the curl|sh finding
j=$(mktemp); $RG scan tests/fixtures/ignore-suppressed --no-color --json "$j" $L >/dev/null 2>&1
python3 -c "import json,sys;d=json.load(open('$j'));s=[f for f in d['findings'] if f.get('suppressed')];print('PASS suppressed findings kept in JSON' if s else 'FAIL suppressed findings missing');sys.exit(0 if s else 1)" || fail=1
rm -f "$j"
j=$(mktemp); $RG scan tests/fixtures/trap-privacy --no-color --json "$j" $L --privacy-only >/dev/null 2>&1
python3 -c "import json,sys;d=json.load(open('$j'));t={f['tool'] for f in d['findings']};ok=bool(t) and t <= {'privacy','telemetry'};print('PASS --privacy-only' if ok else 'FAIL --privacy-only');sys.exit(0 if ok else 1)" || fail=1
rm -f "$j"
j=$(mktemp); $RG scan tests/fixtures/trap-privacy --no-color --json "$j" $L --no-privacy >/dev/null 2>&1
python3 -c "import json,sys;d=json.load(open('$j'));t={f['tool'] for f in d['findings']};ok=not (t & {'privacy','telemetry'});print('PASS --no-privacy' if ok else 'FAIL --no-privacy');sys.exit(0 if ok else 1)" || fail=1
rm -f "$j"
j=$(mktemp); $RG privacy tests/fixtures/trap-privacy --no-color --json "$j" $L >/dev/null 2>&1
python3 -c "import json,sys;d=json.load(open('$j'));t={f['tool'] for f in d['findings']};ok=bool(t) and t <= {'privacy','telemetry'} and d.get('meta',{}).get('privacy_mode')=='only' and all('rule' in f for f in d['findings']);print('PASS privacy subcommand' if ok else 'FAIL privacy subcommand');sys.exit(0 if ok else 1)" || fail=1
python3 tools/make_badge.py "$j" --endpoint "$j.badge" >/dev/null 2>&1
python3 -c "import json,sys;b=json.load(open('$j.badge'));print('PASS badge marks privacy-only' if b.get('privacy_only') is True else 'FAIL badge privacy-only flag');sys.exit(0 if b.get('privacy_only') is True else 1)" || fail=1
rm -f "$j" "$j.badge"
j=$(mktemp); $RG privacy tests/fixtures/trap-privacy --no-color --json "$j" --no-docker >/dev/null 2>&1
python3 -c "import json,sys;d=json.load(open('$j'));ok=any('privacy-only: skipped' in n for n in d.get('notes') or []);print('PASS privacy-only skips OSV/trust' if ok else 'FAIL privacy-only skip note');sys.exit(0 if ok else 1)" || fail=1
rm -f "$j"
python3 tests/test_trust.py || fail=1
python3 tests/test_banner.py || fail=1
python3 tests/test_privacy.py || fail=1
python3 tests/test_toolchain.py || fail=1
python3 tests/test_explain.py || fail=1
tests/test_cleanup.sh || fail=1
# Determinism: the same fixture must produce identical findings (timings excluded).
d1=$(mktemp); d2=$(mktemp)
$RG scan tests/fixtures/trap-npm --no-color --json "$d1" $L >/dev/null 2>&1 || true
$RG scan tests/fixtures/trap-npm --no-color --json "$d2" $L >/dev/null 2>&1 || true
python3 - "$d1" "$d2" <<'PY' || fail=1
import json, sys
def sig(p):
    d = json.load(open(p))
    return d["verdict"], sorted((f["tool"], f["severity"], f["file"], f["line"], f["title"]) for f in d["findings"])
a, b = sig(sys.argv[1]), sig(sys.argv[2])
print("PASS deterministic findings" if a == b else "FAIL non-deterministic findings")
sys.exit(0 if a == b else 1)
PY
# explain: threshold arithmetic from a stored report, never a re-scan.
if out=$($RG explain "$d1" 2>/dev/null) && grep -q "thresholds:" <<<"$out" && grep -q "decision: RED" <<<"$out" && grep -q "to leave RED" <<<"$out"; then
  echo "PASS explain verdict"; else echo "FAIL explain verdict"; fail=1; fi
if $RG explain /nonexistent.json >/dev/null 2>&1; then echo "FAIL explain missing report"; fail=1; else echo "PASS explain missing report"; fi
rm -f "$d1" "$d2"
# diff gate: unchanged reports pass, newly added high/critical findings fail, line moves are not changes.
g1=$(mktemp); g2=$(mktemp); g3=$(mktemp)
$RG scan tests/fixtures/control-clean --no-color --json "$g1" $L >/dev/null 2>&1 || true
$RG scan tests/fixtures/trap-npm --no-color --json "$g2" $L >/dev/null 2>&1 || true
if $RG diff "$g1" "$g1" --no-color >/dev/null 2>&1; then echo "PASS diff unchanged"; else echo "FAIL diff unchanged"; fail=1; fi
if $RG diff "$g1" "$g2" --no-color --min-severity high --json "$g3" >/tmp/rb-diff.txt 2>&1; then echo "FAIL diff gate added"; fail=1; else echo "PASS diff gate added"; fi
python3 - "$g3" <<'PY' || fail=1
import json, sys
d = json.load(open(sys.argv[1]))
ok = d["gate"]["added"] > 0 and d["gate"]["min_severity"] == "high" and any(f["severity"] in ("critical", "high") for f in d["added"])
print("PASS diff JSON" if ok else "FAIL diff JSON")
sys.exit(0 if ok else 1)
PY
# same rule+file at a different line must not be reported as added
python3 - "$g2" "$g3" <<'PY' || fail=1
import json, sys
old = json.load(open(sys.argv[1])); new = json.load(open(sys.argv[1]))
for f in new["findings"]:
    f["line"] = (f.get("line") or 0) + 10
json.dump(new, open(sys.argv[2], "w"))
PY
if $RG diff "$g2" "$g3" --no-color --min-severity info >/tmp/rb-diff2.txt 2>&1; then echo "PASS diff ignores line drift"; else echo "FAIL diff ignores line drift"; fail=1; fi
# ruleset mismatch: loudly compared, but a version change alone is not a gate failure
rf=$(mktemp)
python3 - "$g2" "$rf" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d["meta"]["ruleset"] = "000000000000"
json.dump(d, open(sys.argv[2], "w"))
PY
if $RG diff "$rf" "$g2" --no-color 2>&1 | grep -q "different rulesets"; then echo "PASS diff ruleset warning"; else echo "FAIL diff ruleset warning"; fail=1; fi
if $RG diff "$rf" "$g2" --no-color >/dev/null 2>&1; then echo "PASS diff ruleset mismatch does not gate"; else echo "FAIL diff ruleset mismatch gated"; fail=1; fi
rm -f "$rf"
# profile mismatch is warned about: thresholds changed, not necessarily the code
pf=$(mktemp)
python3 - "$g2" "$pf" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d["meta"]["profile"] = "strict"
json.dump(d, open(sys.argv[2], "w"))
PY
if $RG diff "$pf" "$g2" --no-color 2>&1 | grep -q "different profiles"; then echo "PASS diff profile warning"; else echo "FAIL diff profile warning"; fail=1; fi
rm -f "$pf"
# removed findings: reported as removed, never as a failure
rmv=$(mktemp)
python3 - "$g2" "$rmv" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["findings"] = d["findings"][1:]
json.dump(d, open(sys.argv[2], "w"))
PY
if out=$($RG diff "$g2" "$rmv" --min-severity info --no-color 2>/dev/null) && grep -q "added 0, removed" <<<"$out"; then echo "PASS diff removed"; else echo "FAIL diff removed"; fail=1; fi
if $RG diff "$g2" "$rmv" --min-severity info --no-color >/dev/null 2>&1; then echo "PASS diff removal is not a gate failure"; else echo "FAIL diff removal gated"; fail=1; fi
rm -f "$rmv"
# scan --baseline: one command scans and gates on new findings, suppressing the verdict code
if $RG scan tests/fixtures/trap-npm --baseline "$g1" --baseline-min-severity high $L >/dev/null 2>&1; then echo "FAIL baseline gate on new findings"; fail=1; else echo "PASS baseline gate on new findings"; fi
if $RG scan tests/fixtures/trap-npm --baseline "$g2" --baseline-min-severity high $L >/dev/null 2>&1; then echo "PASS baseline gate quiet on the same tree"; else echo "FAIL baseline gate on unchanged tree"; fail=1; fi
if err=$($RG scan tests/fixtures/trap-npm --baseline /nonexistent.json $L 2>&1 >/dev/null); then echo "FAIL baseline missing file"; fail=1
elif grep -q "baseline /nonexistent.json" <<<"$err"; then echo "PASS baseline missing file rejected"; else echo "FAIL baseline missing file message"; fail=1; fi
# export: SARIF must be structurally valid, reference declared rules, and use unique fingerprints.
g4=$(mktemp)
$RG export "$g2" --format sarif -o "$g4" 2>/dev/null || fail=1
python3 - "$g4" <<'PY' || fail=1
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as ex:
    print("FAIL SARIF export: unreadable:", ex); sys.exit(1)
run = (d.get("runs") or [{}])[0]
res = run.get("results") or []
ids = {r.get("id") for r in (run.get("tool", {}).get("driver", {}).get("rules") or [])}
ok = (d.get("version") == "2.1.0" and str(d.get("$schema", "")).endswith("sarif-2.1.0.json")
      and bool(res) and bool(ids)
      and all(r.get("ruleId") in ids and r.get("level") in ("error", "warning", "note")
              and r.get("message", {}).get("text") for r in res)
      and len({r["partialFingerprints"]["repobeagle/v1"] for r in res}) == len(res)
      and all(not r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("/") for r in res))
print("PASS SARIF export" if ok else "FAIL SARIF export")
sys.exit(0 if ok else 1)
PY
if $RG export "$g2" --format markdown 2>/dev/null | grep -q '^## RepoBeagle: '; then echo "PASS markdown export"; else echo "FAIL markdown export"; fail=1; fi
rm -f "$g4" "$g1" "$g2" "$g3" /tmp/rb-diff.txt /tmp/rb-diff2.txt
# MCP: initialize, tools/list, a real scan, an unknown tool and ping over stdio.
printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}' \
 '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
 '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"scan_repo","arguments":{"target":"tests/fixtures/trap-npm","network":false}}}' \
 '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"nope","arguments":{}}}' \
 '{"jsonrpc":"2.0","id":5,"method":"ping"}' \
 | $RG mcp 2>/dev/null > /tmp/rb-mcp.jsonl || { echo "FAIL MCP server (exit)"; fail=1; }
python3 - /tmp/rb-mcp.jsonl <<'PY' || fail=1
import json, sys
msgs = {}
try:
    for line in open(sys.argv[1]):
        m = json.loads(line); msgs[m.get("id")] = m
    init = msgs[1]["result"]; tl = msgs[2]["result"]["tools"]
    call = json.loads(msgs[3]["result"]["content"][0]["text"])
    ok = (init["serverInfo"]["name"] == "repobeagle" and init.get("protocolVersion")
          and sorted(t["name"] for t in tl) == ["explain_report", "scan_repo", "verify_badge"]
          and all("inputSchema" in t for t in tl)
          and call["verdict"] == "RED" and call["counts"]["critical"] > 0 and call["findings_total"] > 0
          and msgs[4]["result"].get("isError") is True and msgs[5]["result"] == {})
except Exception as ex:
    print("FAIL MCP server:", ex); sys.exit(1)
print("PASS MCP server" if ok else "FAIL MCP server")
sys.exit(0 if ok else 1)
PY
rm -f /tmp/rb-mcp.jsonl
# capability map: hosts, secret paths and install hooks must be visible without a verdict change.
if out=$($RG map tests/fixtures/trap-npm 2>/dev/null) \
   && grep -q "network hosts" <<<"$out" && grep -q "evil.example.invalid" <<<"$out" \
   && grep -q "filesystem / secret paths" <<<"$out" && grep -q "id_rsa" <<<"$out" \
   && grep -q "install hooks" <<<"$out" && grep -q "postinstall" <<<"$out"; then
  echo "PASS capability map"; else echo "FAIL capability map"; fail=1; fi
# web audit: fetch a local page once, classify it, never execute JS.
w=$(mktemp)
$RG web "file://$PWD/tests/fixtures/trap-privacy/web/index.html" --no-color --json "$w" >/dev/null 2>&1; wrc=$?
python3 - "$w" "$wrc" <<'PY' || fail=1
import json, sys
try:
    d = json.load(open(sys.argv[1])); rc = int(sys.argv[2])
except Exception as ex:
    print("FAIL web audit:", ex); sys.exit(1)
m = d.get("meta") or {}
rules = {f["title"].split(":")[0].split(" (")[0] for f in d.get("findings") or []}
ok = (rc == 1 and m.get("mode", "").startswith("web") and m.get("privacy_mode") == "only"
      and m.get("url", "").endswith("index.html") and m.get("fetched", {}).get("page_bytes", 0) > 0
      and d.get("verdict") == "YELLOW"
      and {"third-party-stylesheet", "third-party-script"} & rules
      and not ({f["tool"] for f in d["findings"]} & {"gitleaks", "semgrep", "guarddog", "bandit"} - {"semgrep"}))
print("PASS web audit" if ok else "FAIL web audit")
sys.exit(0 if ok else 1)
PY
rm -f "$w"
# coverage: accounting must be consistent and present in every report.
cv=$(mktemp)
$RG scan tests/fixtures/trap-privacy --no-color --json "$cv" $L >/dev/null 2>&1 || true
python3 - "$cv" <<'PY' || fail=1
import json, sys
d = json.load(open(sys.argv[1])); c = (d.get("meta") or {}).get("coverage") or {}
ok = (c.get("files_total", 0) >= 10 and 0 < c.get("files_scanned", 0) <= c.get("files_total", 0)
      and 0 <= c.get("bytes_scanned_pct", -1) <= 100 and isinstance(c.get("skipped"), dict)
      and c.get("bytes_scanned", 0) <= c.get("bytes_total", 0))
print("PASS coverage accounting" if ok else "FAIL coverage accounting")
sys.exit(0 if ok else 1)
PY
rm -f "$cv"
# coverage-low must fire when most source bytes are uninspectable
ld=$(mktemp -d); for i in $(seq 1 20); do printf 'x = %s\n' "$i" > "$ld/f$i.py"; done
head -c 2000000 /dev/zero | tr '\0' 'a' > "$ld/big.md"
$RG scan "$ld" --no-color --json "$ld.json" $L >/dev/null 2>&1 || true
python3 - "$ld.json" <<'PY' || fail=1
import json, sys
d = json.load(open(sys.argv[1])); c = (d.get("meta") or {}).get("coverage") or {}
hit = [f for f in d.get("findings") or [] if f.get("title", "").startswith("Coverage-low")]
ok = bool(hit) and c.get("bytes_scanned_pct", 100) < 60 and c.get("skipped", {}).get("oversize") == 1
print("PASS coverage-low finding" if ok else "FAIL coverage-low finding")
sys.exit(0 if ok else 1)
PY
rm -rf "$ld" "$ld.json"
# --ref needs a git URL; a local directory is copied as-is
if err=$($RG scan tests/fixtures/trap-npm --ref HEAD 2>&1 >/dev/null); then echo "FAIL ref on local dir"; fail=1
elif grep -q "needs a git URL" <<<"$err"; then echo "PASS ref on local dir rejected"; else echo "FAIL ref error message"; fail=1; fi
if err=$($RG scan tests/fixtures/trap-npm --since HEAD 2>&1 >/dev/null); then echo "FAIL since on local dir"; fail=1
elif grep -q "needs a git URL" <<<"$err"; then echo "PASS since on local dir rejected"; else echo "FAIL since error message"; fail=1; fi
# remediation: well-understood rules must carry a concrete next action, in JSON and in the report
rm2=$(mktemp)
$RG scan tests/fixtures/trap-npm --no-color --json "$rm2" $L >/tmp/rb-rem.txt 2>&1 || true
python3 - "$rm2" <<'PY' || fail=1
import json, sys
d = json.load(open(sys.argv[1]))
hits = [f for f in d.get("findings") or [] if f.get("remediation")]
ok = len(hits) >= 2 and any("checksum" in f["remediation"] for f in hits)
print("PASS remediation in JSON" if ok else "FAIL remediation in JSON")
sys.exit(0 if ok else 1)
PY
if grep -q "fix: " /tmp/rb-rem.txt; then echo "PASS remediation printed"; else echo "FAIL remediation printed"; fail=1; fi
rm -f "$rm2" /tmp/rb-rem.txt
# offline OSV: status is offline-safe, and scans record the database provenance
if dbout=$($RG db 2>/dev/null) && grep -q "OSV offline database:" <<<"$dbout"; then echo "PASS db status"; else echo "FAIL db status"; fail=1; fi
oj=$(mktemp)
$RG scan tests/fixtures/trap-privacy --no-color --json "$oj" --offline-vulnerabilities --no-trust >/dev/null 2>&1 || true
python3 - "$oj" <<'PY' || fail=1
import json, sys
d = json.load(open(sys.argv[1])); m = d.get("meta") or {}
ok = (m.get("offline_vulnerabilities") is True and isinstance(m.get("osv_db"), dict)
      and "path" in m["osv_db"] and "updated" in m["osv_db"])
print("PASS offline OSV wiring" if ok else "FAIL offline OSV wiring")
sys.exit(0 if ok else 1)
PY
rm -f "$oj"
if [[ "${1:-}" != "--offline" ]]; then
  check https://github.com/psf/requests                              "GREEN|YELLOW"
  check https://github.com/tj/commander.js                           "GREEN|YELLOW"
  check https://github.com/invariantlabs-ai/mcp-injection-experiments RED      # MCP tool poisoning
  check https://github.com/juice-shop/juice-shop                     YELLOW   # control: vulnerable, not malicious
  check https://github.com/DataDog/malicious-software-packages-dataset "YELLOW|RED" --no-osv  # zips listed via ls-tree, never downloaded
  # pinned ref: a tag must resolve to its commit and be recorded in the report
  r=$(mktemp)
  $RG scan https://github.com/psf/requests --ref v2.32.3 --no-osv --no-trust --json "$r" >/dev/null 2>&1 || true
  python3 - "$r" <<'PY' || fail=1
import json, sys
try:
    d = json.load(open(sys.argv[1])); m = d.get("meta") or {}
    ok = (m.get("ref") == "v2.32.3" and len(m.get("commit") or "") == 40
          and "archives/binaries" in (m.get("fetched_via") or ""))
except Exception as ex:
    print("FAIL --ref scan:", ex); sys.exit(1)
print("PASS --ref scan" if ok else "FAIL --ref scan")
sys.exit(0 if ok else 1)
PY
  rm -f "$r"
  # changed-files scope: only the diff is materialized, and the report says so
  s=$(mktemp)
  $RG scan https://github.com/psf/requests --ref v2.32.3 --since v2.32.2 --no-osv --no-trust --json "$s" >/dev/null 2>&1 || true
  python3 - "$s" <<'PY' || fail=1
import json, sys
try:
    d = json.load(open(sys.argv[1])); m = d.get("meta") or {}; sc = m.get("scope") or {}
    ok = (sc.get("scope") == "changed" and sc.get("since") == "v2.32.2" and sc.get("changed_files", 0) > 0
          and 0 < sc.get("checked_out", 0) < sc.get("listed_files", 0) and m.get("commit"))
except Exception as ex:
    print("FAIL --since scope:", ex); sys.exit(1)
print("PASS --since scope" if ok else "FAIL --since scope")
sys.exit(0 if ok else 1)
PY
  rm -f "$s"
fi
exit $fail
