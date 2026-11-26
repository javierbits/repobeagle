"""Supply-chain rules: submodules, Dockerfile base pinning, dependency-confusion."""
import collections
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import repobeagle as rb

SUPPLY_RULES = {"submodule-unpinned", "submodule-host", "submodule-uninspected",
                "dockerfile-base-unpinned", "dependency-confusion"}


def scan(target):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        out = Path(fh.name)
    try:
        r = subprocess.run([sys.executable, "repobeagle.py", "scan", str(target), "--no-color", "--no-docker",
                            "--no-osv", "--no-trust", "--json", str(out)],
                           cwd=ROOT, capture_output=True, text=True, timeout=300)
        assert r.returncode in (0, 1, 2), (r.returncode, r.stderr[-400:])
        return json.loads(out.read_text(encoding="utf-8"))
    finally:
        out.unlink(missing_ok=True)


def supply_findings(doc):
    return [f for f in doc["findings"] if f.get("rule") in SUPPLY_RULES]


def write(root, files):
    for rel, text in files.items():
        p = Path(root, rel)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def test_fixture_rules_exactly_once():
    d = scan(ROOT / "tests/fixtures/trap-supply")
    counts = collections.Counter(f["rule"] for f in supply_findings(d))
    assert counts["submodule-unpinned"] == 1, counts
    assert counts["dockerfile-base-unpinned"] == 1, counts
    assert counts["submodule-uninspected"] == 1, counts
    assert counts["dependency-confusion"] == 3, counts
    assert counts["submodule-host"] == 0, counts      # no origin remote in a plain fixture
    titles = {f["title"].split(":")[0] for f in supply_findings(d)}
    assert titles == SUPPLY_RULES - {"submodule-host"}, titles
    assert d["verdict"] == "YELLOW" and d["counts"]["medium"] == 2, d["counts"]
    again = scan(ROOT / "tests/fixtures/trap-supply")
    assert collections.Counter(f["rule"] for f in supply_findings(again)) == counts, "non-deterministic"
    print("PASS fixture yields both required rules exactly once (and is deterministic)")


def test_control_clean_has_no_supply_findings():
    d = scan(ROOT / "tests/fixtures/control-clean")
    assert [f["title"] for f in supply_findings(d)] == [], supply_findings(d)
    print("PASS control-clean has no supply-chain false positives")


def test_submodule_host_needs_origin():
    with tempfile.TemporaryDirectory() as td:
        write(td, {".git/config": '[remote "origin"]\n\turl = https://github.com/acme/widget.git\n',
                   ".gitmodules": '[submodule "a"]\n\tpath = a\n\turl = https://gitlab.com/other/a.git\n'
                                  '\tbranch = main\n'
                                  '[submodule "b"]\n\tpath = b\n\turl = git@github.com:acme/b.git\n'
                                  '[submodule "c"]\n\tpath = c\n\turl = https://github.com/acme/c.git\n'})
        findings = []
        rb.check_supply_chain(td, findings)
        hosts = [f for f in findings if f["title"].startswith("submodule-host")]
        assert len(hosts) == 1 and "gitlab.com" in hosts[0]["title"], hosts
        assert not any("github.com" in f["title"] for f in hosts), hosts
        unpinned = [f for f in findings if f["title"].startswith("submodule-unpinned")]
        assert len(unpinned) == 1 and "tracks branch 'main'" in unpinned[0]["title"], unpinned
    print("PASS submodule-host flags only the other-host submodule")


def test_submodule_unpinned_and_inspected_notes():
    with tempfile.TemporaryDirectory() as td:
        write(td, {".gitmodules": '[submodule "a"]\n\tpath = a\n\turl = https://github.com/acme/a.git\n\tbranch = main\n'})
        findings = []
        rb.check_supply_chain(td, findings)
        assert sum(f["title"].startswith("submodule-unpinned") for f in findings) == 1, findings
        assert sum(f["title"].startswith("submodule-uninspected") for f in findings) == 1, findings
        assert all(f["severity"] in ("low", "info", "medium") for f in findings)
    print("PASS branch-ref submodule is unpinned and reported uninspected exactly once")


def test_dockerfile_pinning_variants():
    with tempfile.TemporaryDirectory() as td:
        write(td, {"Dockerfile": "\n".join([
            "FROM --platform=linux/amd64 ubuntu",                                  # 1: unpinned
            "FROM ghcr.io/acme/base:1.2.3 AS builder",                             # pinned tag, alias
            "FROM ghcr.io/acme/base@sha256:" + "0" * 64,                           # digest: pinned
            "FROM builder",                                                        # stage alias: skip
            "FROM scratch",                                                        # skip
            "FROM ${BASE_IMAGE}",                                                  # build arg: skip
            "FROM node:latest",                                                    # floating: flag
        ])})
        findings = []
        rb.check_supply_chain(td, findings)
        froms = [f for f in findings if f["title"].startswith("dockerfile-base-unpinned")]
        assert len(froms) == 2, froms
        assert all(f["severity"] == "low" for f in froms), froms
        assert froms[0]["line"] < froms[1]["line"]
        assert "ubuntu" in froms[0]["title"] and "node:latest" in froms[1]["title"], froms
    print("PASS Dockerfile pinning: unpinned/floating flagged, digest/tag/stage/scratch/arg skipped")


def test_dependency_confusion_variants():
    with tempfile.TemporaryDirectory() as td:
        write(td, {"requirements-dev.txt": "--extra-index-url https://pypi.example.com/simple\nflask==2.0.0\n",
                   ".npmrc": "registry=http://registry.example.com/\n",
                   "sub/package.json": json.dumps({
                       "name": "x", "dependencies": {"a": "http://x.example.com/a.tgz", "b": "https://x.example.com/b.tgz"},
                       "overrides": {"a": "1.0.0"}})})
        findings = []
        rb.check_supply_chain(td, findings)
        titles = [f["title"] for f in findings if f["title"].startswith("dependency-confusion")]
        assert len(titles) == 4, titles        # extra-index, plaintext registry, http tarball, overrides
        assert sum("http tarball" in t for t in titles) == 1, titles
        assert sum("overrides" in t or "resolutions" in t for t in titles) == 1, titles
        assert all(f["severity"] in ("medium", "low") for f in findings)
    print("PASS dependency-confusion: extra index, plaintext registry/tarball, overrides (https tarball ignored)")


if __name__ == "__main__":
    test_fixture_rules_exactly_once()
    test_control_clean_has_no_supply_findings()
    test_submodule_host_needs_origin()
    test_submodule_unpinned_and_inspected_notes()
    test_dockerfile_pinning_variants()
    test_dependency_confusion_variants()
    print("supply-chain tests passed")
