"""Content-addressed analysis cache: hit/miss, re-filtering, image and tree keys, corrupt entries."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import repobeagle as rb

FLAGS = ["--no-docker", "--no-osv", "--no-trust", "--no-color"]
FIXTURE = "tests/fixtures/trap-privacy"


def scan(cache, fixture=FIXTURE, *extra, env=None):
    out = Path(cache).parent / "report.json"
    e = dict(os.environ, XDG_CACHE_HOME=str(cache))
    if env:
        e.update(env)
    r = subprocess.run([sys.executable, "repobeagle.py", "scan", str(fixture), *FLAGS, *extra, "--json", str(out)],
                       cwd=ROOT, capture_output=True, text=True, timeout=600, env=e)
    doc = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
    out.unlink(missing_ok=True)
    return doc, r


def cache_files(cache):
    return sorted((Path(cache) / "repobeagle" / "results").glob("*.json"))


def test_disabled_and_hit():
    with tempfile.TemporaryDirectory() as td:
        cache = Path(td) / "cache"
        d, r = scan(cache, FIXTURE, "--no-cache")
        assert d["meta"]["cache"] == "disabled", d["meta"].get("cache")
        assert cache_files(cache) == [], "disabled cache must not write"
        d1, r1 = scan(cache)
        assert d1["meta"]["cache"] == "miss", d1["meta"].get("cache")
        files = cache_files(cache)
        assert len(files) == 1 and oct(files[0].stat().st_mode & 0o777) == "0o600", files
        d2, r2 = scan(cache)
        assert d2["meta"]["cache"] == "hit", d2["meta"].get("cache")
        assert "analysis cache hit" in " ".join(d2["notes"]), d2["notes"]
        for key in ("verdict", "findings", "counts", "tools"):
            if key == "tools":
                continue        # per-run seconds differ; key order is asserted below
            assert d1[key] == d2[key], key
        assert list(d1["meta"]["tools"]) == list(d2["meta"]["tools"])
        assert r1.returncode == r2.returncode == 1, (r1.returncode, r2.returncode)
    print("PASS cache disabled / miss / hit, 0600 entry, same report")


def test_profile_refilters_on_hit():
    with tempfile.TemporaryDirectory() as td:
        cache = Path(td) / "cache"
        balanced, _ = scan(cache)
        strict, _ = scan(cache, FIXTURE, "--strict")
        assert balanced["meta"]["cache"] == "miss" and strict["meta"]["cache"] == "hit", \
            (balanced["meta"].get("cache"), strict["meta"].get("cache"))
        assert sorted(f["title"] for f in balanced["findings"]) == sorted(f["title"] for f in strict["findings"]), \
            "the cache stores raw findings; the profile must only change the verdict"
        assert balanced["verdict"] == "YELLOW" and strict["verdict"] == "RED", (balanced["verdict"], strict["verdict"])
        assert balanced["counts"] == strict["counts"], (balanced["counts"], strict["counts"])
    print("PASS --profile re-filters cached raw findings (YELLOW -> RED without rescanning)")


def test_image_and_tree_keys():
    with tempfile.TemporaryDirectory() as td:
        cache = Path(td) / "cache"
        scan(cache)
        other, _ = scan(cache, FIXTURE, env={"BEAGLE_IMAGE": "ghcr.io/example/other:test"})
        assert other["meta"]["cache"] == "miss", other["meta"].get("cache")
        # an upgraded/re-pulled image digest must not serve the old entry
        orig = rb._local_image_digest
        try:
            rb._local_image_digest = lambda image: "sha256:" + "a" * 64
            k1 = rb.analysis_cache_key(ROOT / "tests/fixtures/gate/stub", "", False, None)
            rb._local_image_digest = lambda image: "sha256:" + "b" * 64
            k2 = rb.analysis_cache_key(ROOT / "tests/fixtures/gate/stub", "", False, None)
        finally:
            rb._local_image_digest = orig
        assert k1 != k2, "cache key ignores the image digest"
        # a changed tree must not hit
        copy = Path(td) / "tree"
        shutil.copytree(ROOT / "tests/fixtures/gate/stub", copy)
        first, _ = scan(cache, copy)
        assert first["meta"]["cache"] == "miss", first["meta"].get("cache")
        (copy / "package.json").write_text('{"name": "stub", "version": "2.0.0"}', encoding="utf-8")
        changed, _ = scan(cache, copy)
        assert changed["meta"]["cache"] == "miss", changed["meta"].get("cache")
    print("PASS cache key follows image digest and tree content")


def test_corrupt_entry_recovers():
    with tempfile.TemporaryDirectory() as td:
        cache = Path(td) / "cache"
        scan(cache)
        files = cache_files(cache)
        assert len(files) == 1
        files[0].write_text("{not json", encoding="utf-8")
        d, r = scan(cache)
        assert d["meta"]["cache"] == "miss", d["meta"].get("cache")
        json.loads(cache_files(cache)[0].read_text(encoding="utf-8"))     # rewritten valid
        d2, _ = scan(cache)
        assert d2["meta"]["cache"] == "hit"
    print("PASS corrupt cache entry is a miss and gets repaired")


if __name__ == "__main__":
    test_disabled_and_hit()
    test_profile_refilters_on_hit()
    test_image_and_tree_keys()
    test_corrupt_entry_recovers()
    print("cache tests passed")
