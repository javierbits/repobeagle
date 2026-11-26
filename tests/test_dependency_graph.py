"""Dependency attribution: a transitive OSV finding carries its path; direct deps are depth 1."""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import repobeagle as rb

NPM = ROOT / "tests" / "fixtures" / "osv-graph"
PIP = NPM / "pip-compile"
CARGO = NPM / "cargo"


class _RunResult:
    def __init__(self, stdout):
        self.stdout = stdout
        self.stderr = ""


def osv_payload(src, name, version):
    return json.dumps({"results": [{"source": {"path": str(src)},
                                     "packages": [{"package": {"name": name, "version": version},
                                                   "vulnerabilities": [{"id": "GHSA-test-0001"}], "groups": []}]}]})


def finding(title):
    return rb.finding("osv-scanner", "high", "package-lock.json", 0, title, "GHSA-test-0001", "1 known advisory")


def test_npm_graph():
    g = rb.dependency_graph(NPM)
    assert g["source"] == "package-lock.json" and g["root"] == "app"
    assert g["direct"] == ["left-pad"], g["direct"]
    path, note = rb.dependency_attribution(g, "left-pad")           # direct: depth 1
    assert path == ["app", "left-pad"], (path, note)
    path, note = rb.dependency_attribution(g, "trim")               # transitive: path to the manifest
    assert path == ["app", "left-pad", "trim"], (path, note)
    assert len(path) - 1 == 2
    path, note = rb.dependency_attribution(g, "not-installed")
    assert path is None and "not found" in note, (path, note)
    assert json.dumps(g, sort_keys=True) == json.dumps(rb.dependency_graph(NPM), sort_keys=True)
    print("PASS npm graph: direct depth 1, transitive path app -> left-pad -> trim")


def test_pip_compile_graph():
    g = rb.dependency_graph(PIP)
    assert g["source"] == "requirements.txt" and g["direct"] == ["flask"], g
    assert rb.dependency_attribution(g, "flask")[0] == ["app", "flask"]
    assert rb.dependency_attribution(g, "werkzeug")[0] == ["app", "flask", "werkzeug"]
    with tempfile.TemporaryDirectory() as td:
        Path(td, "requirements.txt").write_text("flask==2.0.0\nwerkzeug==2.0.0\n", encoding="utf-8")
        g = rb.dependency_graph(td)
        assert rb.dependency_attribution(g, "werkzeug")[0] == ["app", "werkzeug"]   # plain pins are direct
    print("PASS pip-compile graph and plain requirements fallback")


def test_cargo_fallback():
    g = rb.dependency_graph(CARGO)
    assert g["source"] == "Cargo.lock" and g["edges"] == {}
    assert rb.dependency_attribution(g, "serde")[0] == ["app", "serde"]             # Cargo.toml direct
    path, note = rb.dependency_attribution(g, "time")
    assert path is None and "Cargo.lock" in note and "no dependency edges" in note, (path, note)
    print("PASS Cargo fallback: direct from Cargo.toml, depth said unknown instead of guessed")


def test_attachment_and_scan_osv():
    findings = [finding("Vulnerable dependency: trim@1.0.1"),
                finding("Vulnerable dependency: left-pad@1.3.0"),
                finding("Vulnerable dependency: absent@9.9.9"),
                rb.finding("agent-checks", "high", "x", 0, "not-osv", "", "")]
    rb.attach_dependency_paths(NPM, findings)
    assert findings[0]["dependency_path"] == ["app", "left-pad", "trim"]
    assert findings[0]["dependency_depth"] == 2 and findings[0]["dependency_source"] == "package-lock.json"
    assert findings[1]["dependency_depth"] == 2 - 1
    assert findings[2]["dependency_depth"] is None and findings[2]["dependency_note"]
    assert "dependency_path" not in findings[3], findings[3]

    orig = rb._run
    try:
        rb._run = lambda *args, **kwargs: _RunResult(osv_payload(NPM, "trim", "1.0.1"))
        fs, note = rb.scan_osv(NPM)
    finally:
        rb._run = orig
    assert fs and fs[0]["dependency_path"] == ["app", "left-pad", "trim"], fs
    assert fs[0]["dependency_depth"] == 2, fs[0]
    print("PASS OSV findings carry dependency_path/depth; non-OSV findings untouched")


if __name__ == "__main__":
    test_npm_graph()
    test_pip_compile_graph()
    test_cargo_fallback()
    test_attachment_and_scan_osv()
    print("dependency attribution tests passed")
