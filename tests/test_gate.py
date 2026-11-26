"""Registry/marketplace gate: batch per-entry verdicts, unknown never GREEN, baseline-only new RED."""
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import repobeagle as rb

LIST = "tests/fixtures/gate/list.txt"


def gate(*args, timeout=300):
    return subprocess.run([sys.executable, "repobeagle.py", "gate", *args, "--no-color"],
                          cwd=ROOT, capture_output=True, text=True, timeout=timeout)


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def test_entries_parsing():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td, "list.txt")
        p.write_text("# catalog\n\nowner/one\nhttps://github.com/owner/two.git   # comment\nowner/one\n", encoding="utf-8")
        assert rb.load_gate_entries(p) == ["owner/one", "https://github.com/owner/two.git"]
        p.write_text('["a/b", {"target": "c/d"}]', encoding="utf-8")
        assert rb.load_gate_entries(p) == ["a/b", "c/d"]
        p.write_text('{"entries": ["a/b"]}', encoding="utf-8")
        assert rb.load_gate_entries(p) == ["a/b"]
        p.write_text("{not json", encoding="utf-8")
        try:
            rb.load_gate_entries(p)
        except ValueError as ex:
            assert "not valid JSON" in str(ex)
        else:
            raise AssertionError("invalid JSON accepted")
        p.write_text("# only comments\n", encoding="utf-8")
        assert rb.load_gate_entries(p) == []
    print("PASS gate entries parsing (text + JSON + comments + duplicates)")


def test_cli_mixed_list_and_baseline():
    with tempfile.TemporaryDirectory() as td:
        out = Path(td, "gate.json")
        r = gate(LIST, "--strict", "--no-cache", "--json", str(out))
        assert r.returncode == 1, (r.returncode, r.stdout[-500:], r.stderr[-500:])
        d = read(out)
        assert d["kind"] == "gate" and d["verdict"] == "RED", d["verdict"]
        by = {e["target"]: e for e in d["entries"]}
        assert len(by) == 4, list(by)
        assert by["tests/fixtures/trap-gha"]["verdict"] == "RED"
        assert by["tests/fixtures/control-clean"]["verdict"] == "GREEN"
        for unknown in ("tests/fixtures/gate/no-metadata", "tests/fixtures/gate/does-not-exist"):
            assert by[unknown]["verdict"] == "unknown", by[unknown]
            assert by[unknown]["why"], by[unknown]
        assert d["new_red"] == ["tests/fixtures/trap-gha"], d["new_red"]
        assert d["unknown"] == ["tests/fixtures/gate/no-metadata", "tests/fixtures/gate/does-not-exist"]
        assert d["counts"] == {"GREEN": 1, "YELLOW": 0, "RED": 1, "unknown": 2}, d["counts"]

        md = gate(LIST, "--strict", "--no-cache", "--markdown")
        assert md.returncode == 1
        assert "| `tests/fixtures/trap-gha` | RED |" in md.stdout, md.stdout[:300]
        assert "| `tests/fixtures/gate/no-metadata` | unknown |" in md.stdout
        assert "| Entry | Verdict |" in md.stdout

        # baseline that already knew the RED entry -> no new RED -> success
        base = json.loads(json.dumps(d))
        for e in base["entries"]:
            if e["target"] == "tests/fixtures/trap-gha":
                e["verdict"] = "RED"
        bp = Path(td, "base-red.json")
        bp.write_text(json.dumps(base), encoding="utf-8")
        r = gate(LIST, "--strict", "--no-cache", "--json", str(out), "--baseline", str(bp))
        assert r.returncode == 0, r.stderr[-400:]
        assert read(out)["new_red"] == []
        # baseline where the entry was GREEN -> RED is new -> failure
        for e in base["entries"]:
            if e["target"] == "tests/fixtures/trap-gha":
                e["verdict"] = "GREEN"
        gp = Path(td, "base-green.json")
        gp.write_text(json.dumps(base), encoding="utf-8")
        r = gate(LIST, "--strict", "--no-cache", "--json", str(out), "--baseline", str(gp))
        assert r.returncode == 1 and read(out)["new_red"] == ["tests/fixtures/trap-gha"]
        # a non-gate JSON baseline is rejected, not silently ignored
        bad = Path(td, "bad.json")
        bad.write_text('{"verdict": "GREEN"}', encoding="utf-8")
        r = gate(LIST, "--strict", "--no-cache", "--baseline", str(bad))
        assert r.returncode == 1 and "not a gate report" in r.stderr, r.stderr[-300:]
        # dashboard mode never fails the job
        r = gate(LIST, "--strict", "--no-cache", "--report-only")
        assert r.returncode == 0, r.returncode
    print("PASS gate mixed listing, markdown, baseline new-RED and dashboard mode")


def test_200_entries_offline():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        for i in range(200):
            shutil.copytree(ROOT / "tests/fixtures/gate/stub", root / f"e{i}")
        (root / "list.txt").write_text("\n".join(str(root / f"e{i}") for i in range(200)), encoding="utf-8")
        t0 = time.time()
        r = gate(str(root / "list.txt"), "--json", str(root / "g.json"), "--jobs", "4")
        took = time.time() - t0
        assert r.returncode == 0, r.stderr[-400:]
        d = read(root / "g.json")
        assert len(d["entries"]) == 200 and d["counts"]["GREEN"] == 200, d["counts"]
        assert d["unknown"] == [] and not d["new_red"], d
        assert took < 120, f"200 entries took {took:.1f}s"
        r1 = gate(str(root / "list.txt"), "--json", str(root / "g1.json"))
        d1 = read(root / "g1.json")
        assert [(e["target"], e["verdict"]) for e in d["entries"]] == \
               [(e["target"], e["verdict"]) for e in d1["entries"]], "jobs=4 changed the result"
    print(f"PASS gate 200-entry offline list ({took:.1f}s, jobs=4 deterministic)")


def test_input_errors():
    with tempfile.TemporaryDirectory() as td:
        empty = Path(td, "empty.txt")
        empty.write_text("# nothing here\n", encoding="utf-8")
        r = gate(str(empty))
        assert r.returncode == 1 and "no entries" in r.stderr, r.stderr
        r = gate(str(Path(td, "missing.txt")))
        assert r.returncode == 1 and "cannot read entries" in r.stderr, r.stderr
    print("PASS gate input errors")


if __name__ == "__main__":
    test_entries_parsing()
    test_cli_mixed_list_and_baseline()
    test_200_entries_offline()
    test_input_errors()
    print("gate tests passed")
