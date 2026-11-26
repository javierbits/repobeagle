"""CycloneDX 1.6 SBOM export: npm/pip/cargo fixtures validate against the vendored schema."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import repobeagle as rb

try:
    import jsonschema
except ImportError:  # dev-only dependency, same policy as the SARIF schema test
    print("SKIP sbom schema: jsonschema not installed (pip install -r requirements-dev.txt)")
    sys.exit(0)

SCHEMA = json.loads((ROOT / "tests" / "schema" / "bom-1.6.schema.json").read_text(encoding="utf-8"))
VALIDATOR = jsonschema.validators.validator_for(SCHEMA)(SCHEMA)

FIXTURES = {
    "npm": ("tests/fixtures/sbom-npm", "pkg:npm/lodash@4.17.21"),
    "pip": ("tests/fixtures/sbom-pip", "pkg:pypi/flask@2.0.0"),
    "cargo": ("tests/fixtures/sbom-cargo", "pkg:cargo/time@0.1.45"),
}
META = {"target": "sbom-fixture", "commit": "a" * 40, "profile": "balanced", "ruleset": "0123456789ab"}


def errors(doc):
    return sorted(VALIDATOR.iter_errors(doc), key=lambda e: list(e.path))


def report(findings=()):
    return {"verdict": "YELLOW", "counts": {"high": 1, "low": 2}, "meta": META, "findings": list(findings)}


def test_schema_and_purls():
    for eco, (dirpath, want) in FIXTURES.items():
        doc = rb.sbom_report(ROOT / dirpath, report())
        assert not errors(doc), (eco, errors(doc))
        assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.6"
        purls = [c["purl"] for c in doc["components"]]
        assert want in purls, (eco, purls)
        assert purls == sorted(purls), eco
        assert len(purls) == len(set(purls)), ("duplicate purls", eco)
        assert not any(c["name"] == "" or c["name"] == "sbom-fixture" for c in doc["components"]), \
            ("the project itself is metadata.component, not a library component", eco)
        assert all(c["bom-ref"] == c["purl"] and c["type"] == "library" for c in doc["components"]), eco
        assert doc["serialNumber"].startswith("urn:uuid:"), eco
        assert doc["metadata"]["component"] == {"type": "application", "name": "sbom-fixture", "version": META["commit"]}
        props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
        assert props["repobeagle:verdict"] == "YELLOW" and props["repobeagle:profile"] == "balanced"
        assert props["repobeagle:counts.high"] == "1" and props["repobeagle:commit"] == META["commit"]
        assert doc["vulnerabilities"] == []
        print(f"PASS sbom schema+purls {eco}")


def test_osv_findings_become_vulnerabilities():
    doc = rb.sbom_report(ROOT / FIXTURES["npm"][0], report([
        {"tool": "osv-scanner", "severity": "high", "title": "Vulnerable dependency: lodash@4.17.21",
         "snippet": "GHSA-aaaa-bbbb-cccc, CVE-2021-23337", "remediation": "Upgrade lodash to 4.17.21+."},
        {"tool": "osv-scanner", "severity": "low", "title": "Vulnerable dependency: not-in-the-lockfile@9.9.9",
         "snippet": "GHSA-unknown"},
        {"tool": "osv-scanner", "severity": "critical", "suppressed": True,
         "title": "Vulnerable dependency: lodash@4.17.21", "snippet": "GHSA-suppressed"},
    ]))
    assert not errors(doc), errors(doc)
    by_id = {v["id"]: v for v in doc["vulnerabilities"]}
    assert set(by_id) == {"GHSA-aaaa-bbbb-cccc", "CVE-2021-23337"}, by_id
    for v in by_id.values():
        assert v["affects"] == [{"ref": "pkg:npm/lodash@4.17.21"}], v
        assert v["ratings"][0]["severity"] == "high" and v["ratings"][0]["source"]["name"] == "OSV", v
        assert v["recommendation"] == "Upgrade lodash to 4.17.21+.", v
    assert not any("not-in-the-lockfile" in json.dumps(v) for v in by_id.values())
    assert not any(v["id"] == "GHSA-suppressed" for v in doc["vulnerabilities"])
    assert [v["id"] for v in doc["vulnerabilities"]] == sorted(by_id)
    print("PASS sbom OSV findings -> vulnerabilities")


def test_deterministic_and_malformed():
    a = rb.sbom_report(ROOT / FIXTURES["pip"][0], report())
    b = rb.sbom_report(ROOT / FIXTURES["pip"][0], report())
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    with tempfile.TemporaryDirectory() as td:
        Path(td, "package-lock.json").write_text("{not json", encoding="utf-8")
        Path(td, "requirements.txt").write_text("flask==2.0.0\n", encoding="utf-8")
        doc = rb.sbom_report(td, report())
        assert not errors(doc), errors(doc)
        assert [c["purl"] for c in doc["components"]] == ["pkg:pypi/flask@2.0.0"]
        props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
        assert props["repobeagle:unparsed-manifests"] == "package-lock.json", props
    print("PASS sbom deterministic + malformed lockfile recorded")


def test_cli_writes_sbom():
    with tempfile.TemporaryDirectory() as td:
        out = Path(td, "sbom.json")
        proc = subprocess.run(
            [sys.executable, "repobeagle.py", "scan", FIXTURES["cargo"][0], "--no-color", "--no-docker",
             "--no-osv", "--no-trust", "--sbom", str(out), "--json", str(Path(td, "r.json"))],
            cwd=ROOT, capture_output=True, text=True, timeout=300,
        )
        assert proc.returncode == 0, (proc.returncode, proc.stdout[-800:], proc.stderr[-800:])
        doc = json.loads(out.read_text(encoding="utf-8"))
        assert not errors(doc), errors(doc)
        assert [c["purl"] for c in doc["components"]] == \
            ["pkg:cargo/serde@1.0.210", "pkg:cargo/time@0.1.45"], doc["components"]
        assert doc["metadata"]["component"]["name"] == "tests/fixtures/sbom-cargo", doc["metadata"]["component"]
    print("PASS sbom --sbom CLI export")


if __name__ == "__main__":
    test_schema_and_purls()
    test_osv_findings_become_vulnerabilities()
    test_deterministic_and_malformed()
    test_cli_writes_sbom()
    print("sbom tests passed")
