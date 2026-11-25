#!/usr/bin/env python3
"""Bounded property tests for the parsers that eat adversarial text. Skips when hypothesis is absent.

Run: pip install -r requirements-dev.txt && python3 tests/test_fuzz.py
Nothing here touches the network, the filesystem or a scan: the targets are pure functions.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import repobeagle as rb

try:
    from hypothesis import HealthCheck, given, settings
    from hypothesis import strategies as st
except ImportError:
    print("SKIP fuzz: hypothesis not installed (pip install -r requirements-dev.txt)")
    sys.exit(0)

FAIL = 0
def check(name, ok):
    global FAIL
    print(("PASS " if ok else "FAIL ") + name)
    if not ok:
        FAIL = 1

FUZZ_ROOT = Path("/fuzz-root")
MD = FUZZ_ROOT / "doc.md"
PY = FUZZ_ROOT / "mod.py"
SETTINGS = settings(max_examples=100, deadline=2000, derandomize=True,
                    suppress_health_check=[HealthCheck.too_slow])
NASTY = st.sampled_from(["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u202e", "\u2066", "\u00ad",
                          "\u0000", "<!--", "-->", "```", "|", "\n", "\r", "agent", "@", " ", "4111"])
mixed = st.one_of(st.text(max_size=600),
                  st.builds("".join, st.lists(NASTY, max_size=40)))

def assert_finding_shape(findings):
    for f in findings:
        if not (isinstance(f, dict) and f.get("severity") in rb.SEV_ORDER and isinstance(f.get("title"), str)
                and f.get("title") and isinstance(f.get("file"), str) and isinstance(f.get("line"), int)
                and f["line"] >= 1):
            raise AssertionError(f"malformed finding: {f!r}")

@SETTINGS
@given(mixed)
def fuzz_decode_tags(s):
    decoded = rb.decode_tags(s)
    assert isinstance(decoded, str)
    assert all(0x20 <= ord(c) < 0x7F for c in decoded)      # only printable ASCII survives
    assert rb.decode_tags(decoded) == decoded              # idempotent

@SETTINGS
@given(mixed)
def fuzz_redact_pii(s):
    out = rb.redact_pii(s)
    assert isinstance(out, str)
    assert rb.redact_pii(out) == out                       # a redacted line stays redacted

@SETTINGS
@given(mixed)
def fuzz_check_unicode(s):
    findings = []
    rb.check_unicode(FUZZ_ROOT, MD, s, findings)
    assert_finding_shape(findings)

@SETTINGS
@given(mixed)
def fuzz_check_markdown_hidden(s):
    findings = []
    rb.check_markdown_hidden(FUZZ_ROOT, MD, s, findings)
    assert_finding_shape(findings)
    # a non-markdown path must be a no-op
    other = []
    rb.check_markdown_hidden(FUZZ_ROOT, PY, s, other)
    assert other == []

for name, fn in (("decode_tags", fuzz_decode_tags), ("redact_pii", fuzz_redact_pii),
                 ("check_unicode", fuzz_check_unicode), ("check_markdown_hidden", fuzz_check_markdown_hidden)):
    try:
        fn()
        check(f"fuzz {name}", True)
    except Exception as ex:
        check(f"fuzz {name}: {type(ex).__name__}: {str(ex)[:300]}", False)

sys.exit(FAIL)
