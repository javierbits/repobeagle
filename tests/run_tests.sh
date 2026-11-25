#!/usr/bin/env bash
# Regression tests. Shallow clone only; nothing is executed or extracted.
# Usage: tests/run_tests.sh [--offline]   (offline = local fixtures only)
cd "$(dirname "$0")/.." || exit 1
RG=./repobeagle; fail=0
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
RULES="telemetry-session-replay telemetry-analytics telemetry-crash telemetry-apm" \
  check tests/fixtures/trap-telemetry "YELLOW|RED" $L
RULES="third-party-cdn insecure-endpoint cookie-write browser-storage consent-manager android-permission extension-permission cookie-flags fingerprint pii-log pii-email pii-phone pii-address import-time-network ip-logging tracking-params privacy-doc browser-capability macos-entitlement client-id ios-tracking ios-tracking-domain ios-data-type dnt-respect consent-order data-retention upload-surface upload-limit store-disclosure referrer-policy permissions-policy tracking-cookie pii-ssn pii-card ios-purpose-string third-party-embed third-party-form third-party-script cookie-lifetime iframe-allow extension-resource undisclosed-vendor telemetry-crash telemetry-analytics telemetry-session-replay" \
  check tests/fixtures/trap-privacy "YELLOW|RED" $L
j=$(mktemp); $RG scan tests/fixtures/trap-privacy --no-color --json "$j" $L >/dev/null 2>&1
python3 -c "import json,sys;d=json.load(open('$j'));s=d.get('privacy_summary') or {};ok=bool(s.get('trackers',{}).get('session-replay')) and bool(s.get('pii'));print('PASS privacy summary' if ok else 'FAIL privacy summary');sys.exit(0 if ok else 1)" || fail=1
python3 -c "import json,sys;d=json.load(open('$j'));e=[x for x in d['findings'] if x['title'].startswith('pii-email')];ok=bool(e) and 's***@widget.dev' in e[0]['snippet'] and 's***@widget.dev' in e[0]['title'];print('PASS PII redacted in snippets' if ok else 'FAIL PII redaction');sys.exit(0 if ok else 1)" || fail=1
python3 tools/make_badge.py "$j" --endpoint "$j.badge" >/dev/null 2>&1
python3 -c "import json,sys;d=json.load(open('$j.badge'));ok=bool(d.get('privacy',{}).get('trackers'));print('PASS badge privacy counts' if ok else 'FAIL badge privacy counts');sys.exit(0 if ok else 1)" || fail=1
rm -f "$j.badge"
python3 -c "import json,sys;d=json.load(open('$j'));e=[f for f in d['findings'] if f['title'].startswith('pii-email')];m=[f for f in d['findings'] if f['title'].startswith('pii-log')];ok=bool(e) and all(f['severity']=='info' for f in e) and any(f['severity']=='info' for f in m);print('PASS role email + masked log are info' if ok else 'FAIL severity refinement');sys.exit(0 if ok else 1)" || fail=1
rm -f "$j"
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
python3 tests/test_trust.py || fail=1
python3 tests/test_banner.py || fail=1
tests/test_cleanup.sh || fail=1
if [[ "${1:-}" != "--offline" ]]; then
  check https://github.com/psf/requests                              "GREEN|YELLOW"
  check https://github.com/tj/commander.js                           "GREEN|YELLOW"
  check https://github.com/invariantlabs-ai/mcp-injection-experiments RED      # MCP tool poisoning
  check https://github.com/juice-shop/juice-shop                     YELLOW   # control: vulnerable, not malicious
  check https://github.com/DataDog/malicious-software-packages-dataset "YELLOW|RED" --no-osv  # zips listed via ls-tree, never downloaded
fi
exit $fail
