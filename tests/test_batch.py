"""Batch scanning: one report per target, identical to sequential scans minus timings, bounded concurrency."""
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import repobeagle as rb

FLAGS = ["--no-docker", "--no-osv", "--no-trust", "--no-color", "--no-cache"]
TARGETS = ["tests/fixtures/trap-privacy", "tests/fixtures/trap-gha", "tests/fixtures/trap-supply"]


def strip_seconds(o):
    if isinstance(o, dict):
        return {k: strip_seconds(v) for k, v in o.items() if k not in ("seconds", "cache")}
    if isinstance(o, list):
        return [strip_seconds(x) for x in o]
    return o


def run(args, cwd=ROOT):
    return subprocess.run([sys.executable, "repobeagle.py", *args], cwd=cwd,
                          capture_output=True, text=True, timeout=900)


def test_batch_matches_sequential_and_parallelises():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        listing = td / "targets.txt"
        listing.write_text("# batch fixture\n" + "\n".join(TARGETS) + "\n", encoding="utf-8")
        outdir = td / "reports"
        t0 = time.time()
        r = run(["batch", str(listing), "--jobs", "3", "--json", str(outdir), *FLAGS])
        batch_wall = time.time() - t0
        assert r.returncode == 1, (r.returncode, r.stdout[-400:], r.stderr[-400:])   # worst verdict YELLOW
        summary = json.loads((outdir / "batch.json").read_text(encoding="utf-8"))
        assert summary["kind"] == "batch" and summary["meta"]["targets"] == 3
        assert [e["target"] for e in summary["entries"]] == TARGETS
        assert summary["counts"]["YELLOW"] == 3 and summary["verdict"] == "YELLOW", summary["counts"]

        seq_wall = 0.0
        for i, target in enumerate(TARGETS):
            seq_out = td / f"seq-{i}.json"
            t0 = time.time()
            s = run(["scan", target, "--jobs", "1", "--json", str(seq_out), *FLAGS])
            seq_wall += time.time() - t0
            assert s.returncode in (0, 1, 2), s.stderr[-400:]
            per = Path(summary["entries"][i]["json"])
            assert per.exists(), per
            assert strip_seconds(json.loads(per.read_text())) == strip_seconds(json.loads(seq_out.read_text())), \
                f"batch report for {target} differs from a sequential scan (minus timings)"
        ratio = batch_wall / seq_wall
        print(f"PASS batch == sequential reports minus seconds; wall {batch_wall:.2f}s vs {seq_wall:.2f}s ({ratio:.0%})")
        # process startup dominates sub-second scans on loaded CI runners; the deterministic concurrency proof
        # is the sleeping-scanner test below. Here: a batch must not be slower than sequential.
        assert ratio < 1.1, f"batch was slower than sequential ({ratio:.0%})"
        # a target that cannot be scanned becomes unknown, the batch continues and the exit code is 1
        listing.write_text(f"{TARGETS[0]}\ntests/fixtures/gate/does-not-exist\n", encoding="utf-8")
        r = run(["batch", str(listing), "--jobs", "2", "--json", str(td / "mixed"), *FLAGS])
        mixed = json.loads((td / "mixed" / "batch.json").read_text())
        assert r.returncode == 1, r.returncode
        assert mixed["counts"]["unknown"] == 1 and mixed["counts"]["YELLOW"] == 1, mixed["counts"]
        unknown = [e for e in mixed["entries"] if e["verdict"] == "unknown"]
        assert unknown and unknown[0]["error"], unknown
    print("PASS batch unknown target does not abort the run")


def test_scanner_concurrency_deterministic():
    orig = {n: getattr(rb, n) for n in ("scan_gitleaks", "scan_semgrep", "scan_guarddog", "scan_bandit")}
    try:
        for name in orig:
            def slow(src, out, _name=name):
                time.sleep(0.3)
                return [], None
            setattr(rb, name, slow)
        timings = {}
        results = {}
        for jobs in (1, 4):
            out = Path(tempfile.mkdtemp())
            t0 = time.time()
            res = rb.inner(ROOT / "tests/fixtures/gate/stub", out, jobs=jobs)
            timings[jobs] = time.time() - t0
            results[jobs] = res
        assert list(results[1]["tools"]) == ["gitleaks", "semgrep", "guarddog", "bandit", "agent-checks"], results[1]["tools"]
        assert list(results[4]["tools"]) == list(results[1]["tools"]), results[4]["tools"]
        assert results[1]["findings"] == results[4]["findings"]
        assert timings[4] < timings[1] * 0.6, timings
        print(f"PASS scanners run concurrently and deterministically ({timings[1]:.2f}s -> {timings[4]:.2f}s)")
    finally:
        for name, fn in orig.items():
            setattr(rb, name, fn)


def test_batch_input_errors():
    with tempfile.TemporaryDirectory() as td:
        empty = Path(td, "empty.txt")
        empty.write_text("# nothing\n", encoding="utf-8")
        r = run(["batch", str(empty)])
        assert r.returncode == 1 and "no targets" in r.stderr, r.stderr
        listing = Path(td, "l.txt")
        listing.write_text("tests/fixtures/control-clean\n", encoding="utf-8")
        for bad in ("0", "17"):
            r = run(["batch", str(listing), "--jobs", bad, "--json", str(Path(td, "o"))])
            assert r.returncode == 1 and "between 1 and 16" in r.stderr, r.stderr
    print("PASS batch input errors")


if __name__ == "__main__":
    test_batch_matches_sequential_and_parallelises()
    test_scanner_concurrency_deterministic()
    test_batch_input_errors()
    print("batch tests passed")
