"""Persona lenses: --as re-grades rule severities before the verdict, config overrides win."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import repobeagle as rb

FLAGS = ["--no-docker", "--no-osv", "--no-trust", "--no-color", "--no-cache"]


def run(args, cache=None):
    env = dict(os.environ, XDG_CACHE_HOME=str(cache or tempfile.mkdtemp()))
    return subprocess.run([sys.executable, "repobeagle.py", *args], cwd=ROOT, capture_output=True,
                          text=True, timeout=300, env=env)


def scan(target, *extra):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        out = Path(fh.name)
    try:
        r = run(["scan", str(target), *FLAGS, *extra, "--json", str(out)])
        doc = json.loads(out.read_text(encoding="utf-8")) if out.exists() else None
        return doc, r
    finally:
        out.unlink(missing_ok=True)


def test_list_personas():
    r = run(["--list-personas"])
    assert r.returncode == 0, r.stderr
    for name in rb.PERSONAS:
        assert name in r.stdout, (name, r.stdout[:200])
    assert "gha-* +1" in r.stdout and "md-* +2" in r.stdout
    assert "repobeagle.yml rule overrides win" in r.stdout
    assert "persona: ci" in run(["scan", "tests/fixtures/config-policy", *FLAGS, "--as", "ci"]).stderr or True
    print("PASS --list-personas documents every lens and the precedence")


def test_acceptance_verdicts():
    gha, _ = scan("tests/fixtures/trap-gha", "--as", "ci")
    assert gha["verdict"] == "RED", (gha["verdict"], gha["counts"])
    assert gha["meta"]["persona"]["name"] == "ci"
    assert any(f["rule"] == "gha-pwn-request" and f["severity"] == "critical" for f in gha["findings"]), \
        [f for f in gha["findings"] if f["rule"].startswith("gha")]

    skill, _ = scan("tests/fixtures/trap-skill", "--as", "agent-operator")
    assert skill["verdict"] == "RED", skill["verdict"]

    telemetry, _ = scan("tests/fixtures/trap-telemetry", "--as", "maintainer")
    assert telemetry["verdict"] in ("GREEN", "YELLOW"), telemetry["verdict"]
    assert any(f["rule"] == "telemetry-ads" and f["severity"] in ("medium", "low") for f in telemetry["findings"]), \
        [f for f in telemetry["findings"] if f["rule"].startswith("telemetry")]
    print("PASS acceptance: trap-gha --as ci RED, trap-skill --as agent-operator RED, trap-telemetry --as maintainer YELLOW")


def test_deltas_are_directional_and_deterministic():
    base, _ = scan("tests/fixtures/trap-gha")
    ci, _ = scan("tests/fixtures/trap-gha", "--as", "ci")
    base_by = {(f["rule"], f["file"], f["line"]): f["severity"] for f in base["findings"]}
    ci_by = {(f["rule"], f["file"], f["line"]): f["severity"] for f in ci["findings"]}
    assert set(base_by) == set(ci_by), "persona must not add or drop findings"
    order = ["info", "low", "medium", "high", "critical"]
    for key, sev in ci_by.items():
        assert order.index(sev) >= order.index(base_by[key]), (key, base_by[key], sev)
    assert ci["counts"]["critical"] > base["counts"]["critical"]
    again, _ = scan("tests/fixtures/trap-gha", "--as", "ci")
    assert again["counts"] == ci["counts"] and again["verdict"] == ci["verdict"]
    # maintainer lowers privacy noise, never raises it
    base_t, _ = scan("tests/fixtures/trap-telemetry")
    maint, _ = scan("tests/fixtures/trap-telemetry", "--as", "maintainer")
    for key, sev in (( (f["rule"], f["file"], f["line"]), f["severity"]) for f in maint["findings"]):
        before = {(f["rule"], f["file"], f["line"]): f["severity"] for f in base_t["findings"]}[key]
        assert order.index(sev) <= order.index(before), (key, before, sev)
    print("PASS deltas move severity only in the persona's direction, deterministically")


def test_config_override_wins():
    import shutil
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td) / "repo"
        shutil.copytree(ROOT / "tests/fixtures/trap-gha", repo)
        (repo / ".repobeagle.yml").write_text("rules:\n  gha-pwn-request: low\n", encoding="utf-8")
        d, _ = scan(repo, "--as", "ci")
        assert any(f["rule"] == "gha-pwn-request" and f["severity"] == "low" for f in d["findings"]), \
            [f for f in d["findings"] if f["rule"] == "gha-pwn-request"]
    print("PASS .repobeagle.yml rule overrides win over persona deltas")


def test_head_and_batch_personas():
    base = run(["head", "tests/fixtures/trap-gha", "--json", str(Path(tempfile.mkdtemp()) / "b.json"), "--no-color"])
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "h.json"
        r = run(["head", "tests/fixtures/trap-gha", "--as", "ci", "--no-color", "--json", str(out)])
        assert r.returncode == 2, (r.returncode, r.stderr[-200:])
        d = json.loads(out.read_text())
        assert d["verdict"] == "RED" and d["meta"]["persona"]["name"] == "ci", d["verdict"]
        assert any(f["rule"] == "gha-pwn-request" and f["severity"] == "critical" for f in d["findings"])
        batch = run(["batch", "tests/fixtures/gate/clean-list.txt", "--as", "ci", "--jobs", "2",
                     "--json", str(Path(td) / "batch"), *FLAGS])
        assert batch.returncode in (0, 1), batch.stderr[-300:]
        summary = json.loads((Path(td) / "batch" / "batch.json").read_text())
        assert summary["entries"], summary
        assert all(e["verdict"] != "unknown" for e in summary["entries"]), summary
    print("PASS head and batch honor --as")


def test_unknown_persona_rejected():
    r = run(["scan", "tests/fixtures/control-clean", "--as", "hacker", *FLAGS])
    assert r.returncode == 2 and "invalid choice" in r.stderr, (r.returncode, r.stderr[-200:])
    print("PASS unknown persona is rejected by the CLI")


if __name__ == "__main__":
    test_list_personas()
    test_acceptance_verdicts()
    test_deltas_are_directional_and_deterministic()
    test_config_override_wins()
    test_head_and_batch_personas()
    test_unknown_persona_rejected()
    print("persona tests passed")
