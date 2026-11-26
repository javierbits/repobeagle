"""Fixed-version availability: explicit OSV `fixed` events become `fixed_in`, otherwise say so."""
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import repobeagle as rb

os.environ["XDG_CACHE_HOME"] = tempfile.mkdtemp()
FIXED = (ROOT / "tests/fixtures/osv-fixed/fixed.json").read_text()
UNFIXED = (ROOT / "tests/fixtures/osv-fixed/unfixed.json").read_text()


class _Run:
    def __init__(self, stdout):
        self.stdout = stdout
        self.stderr = ""


def scan_osv(payload, latest=None, calls=None):
    orig_run, orig_fetch = rb._run, rb._registry_fetch
    lookups = calls if calls is not None else []

    def fake_fetch(url):
        lookups.append(url)
        if latest is None:
            raise AssertionError(f"unexpected registry lookup {url}")
        return latest

    try:
        rb._run = lambda *a, **k: _Run(payload)
        rb._registry_fetch = fake_fetch
        return rb.scan_osv(ROOT / "tests/fixtures/osv-fixed")
    finally:
        rb._run, rb._registry_fetch = orig_run, orig_fetch


def test_fixed_event_yields_fixed_in():
    lookups = []
    fs, note = scan_osv(FIXED, latest=None, calls=lookups)
    assert not lookups, "no registry lookup when OSV lists a fixed version"
    f = fs[0]
    assert f["fixed_in"] == ["4.17.21"], f
    assert f["remediation"] == "upgrade lodash to 4.17.21", f
    assert "fixed in 4.17.21" in f["meaning"], f["meaning"]
    print("PASS an explicit fixed event yields fixed_in and a remediation without extra network")


def test_unfixed_event_states_it_and_uses_one_lookup():
    lookups = []
    fs, note = scan_osv(UNFIXED, latest={"dist-tags": {"latest": "9.9.9"}}, calls=lookups)
    assert len(lookups) == 1, lookups
    f = fs[0]
    assert f["fixed_in"] == [], f
    assert f["fixed_note"] == "no fixed version listed by OSV; latest published left-pad is 9.9.9", f
    assert f["latest_version"] == "9.9.9"
    assert f["remediation"] == "no fixed version listed by OSV; latest published left-pad is 9.9.9"
    assert "no fixed version listed" in f["meaning"]
    print("PASS an advisory without a fixed event says so explicitly (one registry lookup)")


def test_lookup_cap_and_unrelated_affected_packages():
    doc = json.loads(UNFIXED)
    doc["results"][0]["packages"].append(json.loads(json.dumps(doc["results"][0]["packages"][0])))
    doc["results"][0]["packages"][0]["package"]["name"] = "cap-one"
    doc["results"][0]["packages"][1]["package"]["name"] = "cap-two"
    for vuln in doc["results"][0]["packages"][1]["vulnerabilities"]:
        for aff in vuln["affected"]:
            aff["package"]["name"] = "cap-two"
    orig = rb.FIX_LOOKUPS_MAX
    old_cache = os.environ.get("XDG_CACHE_HOME")
    os.environ["XDG_CACHE_HOME"] = tempfile.mkdtemp()      # cold cache: the cap counts real fetches
    lookups = []
    try:
        rb.FIX_LOOKUPS_MAX = 1
        fs, _ = scan_osv(json.dumps(doc), latest={"dist-tags": {"latest": "2.0.0"}}, calls=lookups)
    finally:
        rb.FIX_LOOKUPS_MAX = orig
        if old_cache is None:
            os.environ.pop("XDG_CACHE_HOME", None)
        else:
            os.environ["XDG_CACHE_HOME"] = old_cache
    assert len(lookups) == 1, lookups
    notes = [f["fixed_note"] for f in fs]
    assert any("latest published" in n for n in notes), notes
    assert any("lookup skipped" in n for n in notes), notes
    unrelated = [{"id": "X", "affected": [{"package": {"name": "other"}, "ranges": [
        {"events": [{"fixed": "1.0.0"}]}]}]}]
    assert rb.osv_fixed_versions(unrelated, "lodash") == [], "unrelated affected package must not leak"
    multi = [{"affected": [{"package": {"name": "lodash"}, "ranges": [
        {"events": [{"fixed": "4.17.21"}]}, {"events": [{"fixed": "4.9.0"}]}]}]}]
    assert rb.osv_fixed_versions(multi, "lodash") == ["4.9.0", "4.17.21"], "fixed versions sorted numerically"
    print("PASS lookup caps, unrelated affected packages ignored, versions sorted numerically")


if __name__ == "__main__":
    test_fixed_event_yields_fixed_in()
    test_unfixed_event_states_it_and_uses_one_lookup()
    test_lookup_cap_and_unrelated_affected_packages()
    print("fix availability tests passed")
