"""Workspace/monorepo awareness: package detection, per-package first-party inference, attribution."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import repobeagle as rb

FIXTURE = ROOT / "tests/fixtures/workspace-two"
FLAGS = ["--no-docker", "--no-osv", "--no-trust", "--no-cache", "--no-color"]


def scan(target):
    cache = tempfile.mkdtemp()
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        out = Path(fh.name)
    try:
        r = subprocess.run([sys.executable, "repobeagle.py", "scan", str(target), *FLAGS, "--json", str(out)],
                           cwd=ROOT, capture_output=True, text=True, timeout=600,
                           env=dict(os.environ, XDG_CACHE_HOME=cache))
        return (json.loads(out.read_text(encoding="utf-8")) if out.stat().st_size else None), r
    finally:
        out.unlink(missing_ok=True)


def write(root, files):
    for rel, text in files.items():
        p = Path(root, rel)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def test_string_root_is_accepted():
    # The container entrypoint passes argv strings; package attribution must not do str/str.
    findings, n = rb.run_agent_checks(str(FIXTURE))
    assert isinstance(findings, list) and n > 0, (findings[:2], n)


def test_detection_kinds():
    packages, dropped = rb.workspace_packages(FIXTURE)
    assert [(p["path"], p["name"], p["kind"]) for p in packages] == [
        ("packages/a", "@acme/a", "npm"), ("packages/b", "@acme/b", "npm")], packages
    assert dropped == []
    original = rb.MAX_WORKSPACE_PACKAGES
    try:
        rb.MAX_WORKSPACE_PACKAGES = 1
        packages, dropped = rb.workspace_packages(FIXTURE)
        assert len(packages) == 1 and len(dropped) == 1, (packages, dropped)
    finally:
        rb.MAX_WORKSPACE_PACKAGES = original
    with tempfile.TemporaryDirectory() as td:
        write(td, {
            "pnpm-workspace.yaml": "packages:\n  - 'apps/*'\n",
            "apps/web/package.json": '{"name": "web"}',
            "Cargo.toml": '[workspace]\nmembers = ["crates/core"]\n',
            "crates/core/Cargo.toml": '[package]\nname = "core"\n',
            "go.work": "go 1.22\n\nuse (\n\t./services/api\n)\n",
            "services/api/go.mod": "module example.com/api\n\ngo 1.22\n",
            "libs/py/pyproject.toml": '[project]\nname = "pylib"\n',
        })
        packages, _ = rb.workspace_packages(td)
        got = {(p["path"], p["kind"]) for p in packages}
        assert ("apps/web", "npm") in got, got
        assert ("crates/core", "cargo") in got, got
        assert ("services/api", "go") in got, got
        assert ("libs/py", "python") in got, got
    print("PASS npm/pnpm/Cargo/go.work/Python workspace detection and the package cap")


def test_per_package_inference_and_attribution():
    doc, r = scan(FIXTURE)
    assert doc is not None, r.stderr[-400:]
    ws = doc["meta"]["workspace"]
    assert [p["name"] for p in ws["packages"]] == ["@acme/a", "@acme/b"], ws
    third = [(f["rule"], f["file"], f.get("package")) for f in doc["findings"]
             if f["rule"] == "third-party-script"]
    assert third == [("third-party-script", "packages/b/index.html", "@acme/b")], third
    assert any(f["rule"] == "first-party-endpoint" and f["file"] == "packages/a/index.html"
               and f.get("package") == "@acme/a" for f in doc["findings"]), "A's CNAME was not applied to A"
    for f in doc["findings"]:
        if f["file"].startswith("packages/"):
            assert f.get("package") in ("@acme/a", "@acme/b"), f
    total = {sev: sum(ws["counts"][name][sev] for name in ws["counts"]) for sev in rb.SEV_ORDER}
    assert total == doc["counts"], (total, doc["counts"])
    again, _ = scan(FIXTURE)
    assert again["meta"]["workspace"] == ws and again["counts"] == doc["counts"]
    print("PASS package A's CNAME does not leak to package B; per-package counts sum to the total")


def test_root_domains_do_not_leak_into_packages():
    with tempfile.TemporaryDirectory() as td:
        write(td, {
            "package.json": '{"name": "root", "workspaces": ["pkg"]}',
            "CNAME": "root.example.com",
            "pkg/package.json": '{"name": "pkg"}',
            "pkg/index.html": '<script src="https://root.example.com/x.js"></script>\n',
        })
        doc, _ = scan(td)
        rules = {(f["rule"], f["file"]) for f in doc["findings"]}
        assert ("third-party-script", "pkg/index.html") in rules, rules
        assert doc["meta"]["workspace"]["counts"]["pkg"]["low"] == 1, doc["meta"]["workspace"]
    print("PASS root first-party domains do not leak into a package")


def test_single_project_has_no_workspace_meta():
    doc, _ = scan(ROOT / "tests/fixtures/control-clean")
    assert "workspace" not in doc["meta"], doc["meta"].get("workspace")
    print("PASS a single project does not grow a workspace section")


if __name__ == "__main__":
    test_detection_kinds()
    test_per_package_inference_and_attribution()
    test_root_domains_do_not_leak_into_packages()
    test_single_project_has_no_workspace_meta()
    print("workspace tests passed")
