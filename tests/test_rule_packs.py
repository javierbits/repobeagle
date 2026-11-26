"""Rule packs: lint anchoring/backtracking/schema, fixture tests, and scan integration."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import repobeagle as rb

PACK = ROOT / "tests/fixtures/rule-pack/.repobeagle/rules"
FLAGS = ["--no-docker", "--no-osv", "--no-trust", "--no-color", "--no-cache"]


def run(args):
    return subprocess.run([sys.executable, "repobeagle.py", *args], cwd=ROOT, capture_output=True,
                          text=True, timeout=300, env=dict(os.environ, XDG_CACHE_HOME=tempfile.mkdtemp()))


def pack_file(td, text):
    base = Path(td) / ".repobeagle" / "rules"
    base.mkdir(parents=True, exist_ok=True)
    p = base / "pack.yml"
    p.write_text(text, encoding="utf-8")
    return p


def rule_block(extra=""):
    return ("  - id: test-rule\n    paths: ['src/**/*.js']\n    regex: '^x'\n    severity: low\n"
            "    meaning: 'x on a line'\n    remediation: 'drop the x'\n"
            "    fixtures:\n      positive: ['x here']\n      negative: ['y here']\n" + extra)


def test_lint_and_schema():
    r = run(["rules", "lint", str(PACK)])
    assert r.returncode == 0 and "2 rule(s)" in r.stdout, (r.returncode, r.stdout, r.stderr)
    cases = {
        "unanchored": ("version: 1\nrules:\n" + rule_block().replace("regex: '^x'", "regex: 'x'"),
                       "unanchored"),
        "catastrophic": ("version: 1\nrules:\n" + rule_block().replace("regex: '^x'", "regex: '^(a+)+$'"),
                         "catastrophic backtracking"),
        "version": ("rules:\n" + rule_block(), "version must be 1"),
        "severity": ("version: 1\nrules:\n" + rule_block().replace("severity: low", "severity: loud"),
                     "severity must be one of"),
        "regex": ("version: 1\nrules:\n" + rule_block().replace("regex: '^x'", "regex: '^('"),
                  "does not compile"),
        "positive": ("version: 1\nrules:\n" + rule_block().replace("positive: ['x here']", "positive: []"),
                     "fixtures.positive must be a non-empty list"),
        "remediation": ("version: 1\nrules:\n" + rule_block().replace("remediation: 'drop the x'", "remediation: ''"),
                        "remediation must name the fix"),
        "duplicate": ("version: 1\nrules:\n" + rule_block() + rule_block(), "duplicate id"),
    }
    with tempfile.TemporaryDirectory() as td:
        for name, (text, needle) in cases.items():
            pack_file(td, text)
            r = run(["rules", "lint", str(Path(td) / ".repobeagle" / "rules")])
            assert r.returncode == 1 and needle in r.stderr, (name, r.stderr[-400:])
    print("PASS lint: unanchored and catastrophic regexes and schema errors fail loudly")


def test_fixture_runner():
    r = run(["rules", "test", str(PACK)])
    assert r.returncode == 0 and "every positive fixture fired" in r.stdout, (r.returncode, r.stdout, r.stderr)
    bad_positive = ("version: 1\nrules:\n" + rule_block().replace("positive: ['x here']", "positive: ['nope']"))
    bad_negative = ("version: 1\nrules:\n" + rule_block().replace("negative: ['y here']", "negative: ['x nope']"))
    with tempfile.TemporaryDirectory() as td:
        for name, text, needle in (("positive", bad_positive, "positive[0]: did not fire"),
                                   ("negative", bad_negative, "negative[0]: fired")):
            base = pack_file(Path(td) / name, text)
            r = run(["rules", "test", str(base.parent)])
            assert r.returncode == 1 and needle in r.stderr, (name, r.stderr[-400:])
    print("PASS fixture runner: a positive must fire its exact rule id, a negative must not")


def test_scan_integration():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        out = Path(fh.name)
    try:
        r = run(["scan", "tests/fixtures/rule-pack", *FLAGS, "--json", str(out)])
        assert r.returncode in (1, 2), (r.returncode, r.stderr[-300:])
        d = json.loads(out.read_text(encoding="utf-8"))
        assert d["meta"]["rule_packs"]["rules"] == 2, d["meta"].get("rule_packs")
        pack = [f for f in d["findings"] if f["tool"] == "rules"]
        got = {(f["rule"], f["file"], f["line"]): f for f in pack}
        assert ("no-console-log", "src/main.js", 2) in got, got
        assert ("no-todo-fix", "src/main.js", 3) in got, got
        assert got[("no-console-log", "src/main.js", 2)]["severity"] == "low"
        assert got[("no-todo-fix", "src/main.js", 3)]["severity"] == "medium"
        assert got[("no-todo-fix", "src/main.js", 3)]["remediation"] == "resolve or re-file the TODO"
        assert not any(f["file"].startswith("lib/") for f in pack)
        # the same lines are reported exactly once
        assert len(pack) == 2, pack
        again = json.loads(out.read_text(encoding="utf-8"))
        r2 = run(["scan", "tests/fixtures/rule-pack", *FLAGS, "--json", str(out)])
        d2 = json.loads(out.read_text(encoding="utf-8"))
        assert [(f["rule"], f["file"], f["line"]) for f in d2["findings"] if f["tool"] == "rules"] == \
               [(f["rule"], f["file"], f["line"]) for f in pack]
    finally:
        out.unlink(missing_ok=True)
    # an invalid pack in a scanned repository is a loud error, not a silent skip
    with tempfile.TemporaryDirectory() as td:
        base = pack_file(td, "version: 1\nrules:\n" + rule_block().replace("regex: '^x'", "regex: 'x'"))
        (Path(td) / "src").mkdir()
        (Path(td) / "src" / "a.js").write_text("x here\n", encoding="utf-8")
        r = run(["scan", td, *FLAGS])
        assert r.returncode == 1 and "unanchored" in r.stderr, r.stderr[-300:]
    print("PASS scan auto-loads packs, fires the exact ids and refuses an invalid pack")


def test_head_loads_packs():
    with tempfile.TemporaryDirectory() as td:
        base = pack_file(td, "version: 1\nrules:\n" + rule_block())
        (Path(td) / "package.json").write_text('{"name": "x", "version": "1.0.0"}', encoding="utf-8")
        out = Path(td) / "h.json"
        r = run(["head", td, "--no-color", "--no-cache", "--json", str(out)])
        assert r.returncode in (0, 1, 2), r.stderr[-300:]
        d = json.loads(out.read_text(encoding="utf-8"))
        assert d["meta"]["rule_packs"]["rules"] == 1, d["meta"].get("rule_packs")
    print("PASS head fetches and validates .repobeagle/rules packs")


if __name__ == "__main__":
    test_lint_and_schema()
    test_fixture_runner()
    test_scan_integration()
    test_head_loads_packs()
    print("rule pack tests passed")
