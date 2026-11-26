"""`.repobeagle.yml` policy config: profile, rule overrides, host allowlist, custom checks, loud errors."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import repobeagle as rb

BASE_FLAGS = ["--no-docker", "--no-osv", "--no-trust", "--no-color"]   # fresh temp cache per scan
FIXTURE = ROOT / "tests/fixtures/config-policy"


def run(args, cache):
    env = dict(os.environ, XDG_CACHE_HOME=str(cache))
    return subprocess.run([sys.executable, "repobeagle.py", *args], cwd=ROOT, capture_output=True,
                          text=True, timeout=300, env=env)


def scan(target, *extra, cache=None):
    cache = cache or tempfile.mkdtemp()
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        out = Path(fh.name)
    try:
        r = run(["scan", str(target), *BASE_FLAGS, *extra, "--json", str(out)], cache)
        doc = json.loads(out.read_text(encoding="utf-8")) if out.exists() else None
        return doc, r
    finally:
        out.unlink(missing_ok=True)


def copy_fixture(td, config=None, name="repo"):
    dst = Path(td) / name
    import shutil
    shutil.copytree(FIXTURE, dst)
    if config is not None:
        (dst / ".repobeagle.yml").write_text(config, encoding="utf-8")
    return dst


def test_yaml_subset():
    doc = rb.parse_yaml_subset(
        "# policy\n"
        "profile: strict   # inline comment\n"
        "rules:\n"
        "  telemetry-devtool: info\n"
        "hosts:\n"
        "  - cdn.widget.dev\n"
        "  - 'api.widget.dev'\n"
        "custom_checks:\n"
        "  - paths: ['src/**/*.py', \"scripts/**\"]\n"
        "    pattern: \"\\\\bprint\\\\s*\\\\ (\"\n"
        "    severity: medium\n"
        "    meaning: \"debug print\"\n")
    assert doc["profile"] == "strict" and doc["rules"] == {"telemetry-devtool": "info"}, doc
    assert doc["hosts"] == ["cdn.widget.dev", "api.widget.dev"], doc
    assert doc["custom_checks"][0]["paths"] == ["src/**/*.py", "scripts/**"], doc
    try:
        rb.parse_yaml_subset("a:\n\tb: 1\n")
    except ValueError as ex:
        assert "tabs" in str(ex)
    else:
        raise AssertionError("tabs accepted")
    print("PASS YAML subset parser (comments, nesting, inline lists, tabs rejected)")


def test_acceptance_override_flips_verdict():
    with tempfile.TemporaryDirectory() as td:
        plain, _ = scan(FIXTURE, "--strict")
        assert plain["verdict"] == "YELLOW" and plain["counts"]["low"] == 1, (plain["verdict"], plain["counts"])
        repo = copy_fixture(td, "profile: strict\nrules:\n  telemetry-devtool: info\n")
        configured, _ = scan(repo)
        assert configured["verdict"] == "GREEN", (configured["verdict"], configured["counts"])
        assert configured["meta"]["config"]["profile"] == "strict"
        assert configured["meta"]["config"]["rules"] == {"telemetry-devtool": "info"}
        dev = [f for f in configured["findings"] if f["rule"] == "telemetry-devtool"]
        assert dev and dev[0]["severity"] == "info", dev
    print("PASS overriding telemetry-devtool to info flips the fixture YELLOW -> GREEN")


def test_loud_errors():
    with tempfile.TemporaryDirectory() as td:
        cache = Path(td) / "cache"
        cases = {
            "typo": ("rules:\n  telemetry-devtool-typo: info\n", "unknown rule id 'telemetry-devtool-typo'"),
            "severity": ("rules:\n  telemetry-devtool: loud\n", "unknown severity 'loud'"),
            "profile": ("profile: paranoid\n", "unknown profile 'paranoid'"),
            "regex": ("custom_checks:\n  - paths: ['src/*.py']\n    pattern: '[unclosed'\n"
                      "    severity: low\n    meaning: 'x'\n", "does not compile"),
            "meaning": ("custom_checks:\n  - paths: ['src/*.py']\n    pattern: 'x'\n    severity: low\n",
                        "meaning must be a one-sentence reason"),
        }
        for name, (config, needle) in cases.items():
            repo = copy_fixture(td, config, name=f"repo-{name}")
            out = Path(td, f"{name}.json")
            r = run(["scan", str(repo), *BASE_FLAGS, "--json", str(out)], cache)
            assert r.returncode == 1 and needle in r.stderr, (name, r.returncode, r.stderr[-400:])
            assert not out.exists(), name
    print("PASS unknown rule id/severity/profile and bad custom checks are loud errors")


def test_profile_precedence_and_json_config():
    with tempfile.TemporaryDirectory() as td:
        repo = copy_fixture(td, "profile: strict\n")
        configured, _ = scan(repo)
        assert configured["verdict"] == "YELLOW", configured["verdict"]   # config profile applies
        cli, _ = scan(repo, "--balanced")
        assert cli["verdict"] == "GREEN", cli["verdict"]                  # an explicit CLI profile wins
        (repo / ".repobeagle.yml").write_text(json.dumps({"profile": "strict",
                                                         "rules": {"telemetry-devtool": "info"}}), encoding="utf-8")
        js, _ = scan(repo)
        assert js["verdict"] == "GREEN" and js["meta"]["config"]["rules"] == {"telemetry-devtool": "info"}, js["verdict"]
    print("PASS config profile applies, CLI profile wins, JSON config accepted")


def test_host_allowlist_and_custom_checks():
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td) / "repo"
        (repo / "src").mkdir(parents=True)
        (repo / "index.html").write_text('<script src="https://cdn.widget.dev/lib.js"></script>\n', encoding="utf-8")
        (repo / "src" / "main.py").write_text("def main():\n    print('debug')\n", encoding="utf-8")
        plain, _ = scan(repo)
        rules = {f["rule"] for f in plain["findings"]}
        assert "third-party-script" in rules, rules
        assert "custom-check" not in rules
        (repo / ".repobeagle.yml").write_text(
            "hosts:\n  - cdn.widget.dev\n"
            "custom_checks:\n"
            "  - id: no-print\n"
            "    paths: ['src/**/*.py']\n"
            "    pattern: '\\bprint\\('\n"
            "    severity: medium\n"
            "    meaning: 'debug print in library code'\n", encoding="utf-8")
        configured, _ = scan(repo)
        by = {f["title"]: f for f in configured["findings"]}
        assert not any(f["rule"] == "third-party-script" for f in configured["findings"]), configured["findings"]
        custom = [f for f in configured["findings"] if f["rule"] == "custom-check"]
        assert len(custom) == 1, custom
        assert custom[0]["severity"] == "medium" and custom[0]["file"] == "src/main.py", custom[0]
        assert custom[0]["line"] == 2 and "no-print" in custom[0]["title"], custom[0]
        assert custom[0]["snippet"].strip() == "print('debug')", custom[0]["snippet"]
        assert custom[0]["meaning"] == "debug print in library code"
        assert configured["verdict"] == "YELLOW", configured["verdict"]
    print("PASS host allowlist reclassifies a third party and custom checks report file:line")


def test_cache_ignores_stale_policy():
    with tempfile.TemporaryDirectory() as td:
        cache = Path(td) / "cache"
        repo = copy_fixture(td)
        first, _ = scan(repo, cache=cache)
        assert first["meta"]["cache"] == "miss"
        second, _ = scan(repo, cache=cache)
        assert second["meta"]["cache"] == "hit", second["meta"]["cache"]
        (repo / ".repobeagle.yml").write_text("rules:\n  telemetry-devtool: info\n", encoding="utf-8")
        changed, _ = scan(repo, cache=cache)
        assert changed["meta"]["cache"] == "miss", changed["meta"]["cache"]   # policy is part of the key
    print("PASS changing the policy invalidates the analysis cache")


def test_rule_registry_covers_rule_ids():
    known = rb.known_rule_ids()
    fired: set[str] = set()
    for fixture in ("trap-gha", "trap-skill", "trap-markdown", "trap-build", "trap-telemetry",
                    "trap-supply", "trap-privacy", "config-policy"):
        doc, _ = scan(ROOT / "tests" / "fixtures" / fixture)
        assert doc is not None, fixture
        fired |= {f["rule"] for f in doc["findings"]}
    missing = sorted(fired - known)
    assert not missing, f"config validation would reject these real rule ids: {missing}"
    print(f"PASS rule registry covers all {len(fired)} rule ids fired by the fixtures")


def test_head_validates_config():
    with tempfile.TemporaryDirectory() as td:
        Path(td, "package.json").write_text('{"name": "x", "version": "1.0.0"}', encoding="utf-8")
        Path(td, ".repobeagle.yml").write_text("rules:\n  telemetry-devtool-typo: low\n", encoding="utf-8")
        r = run(["head", td, "--no-color"], Path(td) / "cache")
        assert r.returncode == 1 and "unknown rule id" in r.stderr, (r.returncode, r.stderr[-300:])
        Path(td, ".repobeagle.yml").write_text("profile: strict\n", encoding="utf-8")
        r = run(["head", td, "--no-color", "--json", str(Path(td, "h.json"))], Path(td) / "cache")
        assert r.returncode in (0, 1, 2), r.stderr[-300:]
        d = json.loads(Path(td, "h.json").read_text(encoding="utf-8"))
        assert d["meta"]["config"]["profile"] == "strict", d["meta"].get("config")
    print("PASS head validates the config and applies its profile")


if __name__ == "__main__":
    test_yaml_subset()
    test_acceptance_override_flips_verdict()
    test_loud_errors()
    test_profile_precedence_and_json_config()
    test_host_allowlist_and_custom_checks()
    test_cache_ignores_stale_policy()
    test_rule_registry_covers_rule_ids()
    test_head_validates_config()
    print("config tests passed")
