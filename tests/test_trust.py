#!/usr/bin/env python3
"""Offline unit tests for trust signals (no network)."""
import datetime as D, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import repobeagle as rb

NOW = D.datetime(2026, 10, 14, tzinfo=D.timezone.utc)
ago = lambda d: (NOW - D.timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%SZ")
rules = lambda fs: {f["title"].split(":")[0] for f in fs}
fail = 0
def check(name, got, want, absent=()):
    global fail
    ok = want <= got and not (set(absent) & got)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  got={sorted(got)}"))
    fail |= not ok

sus = rb.trust_findings("evil/tool", {"full_name": "newowner/tool", "created_at": ago(10), "stargazers_count": 900, "forks_count": 1},
                        {"created_at": ago(20)}, 1, NOW)
check("suspicious repo", rules(sus), {"trust-signals", "repo-moved", "young-repo", "young-owner", "star-spike", "single-contributor"})
check("trust is LOW/INFO only", {f["severity"] for f in sus}, set(), absent={"medium", "high", "critical"})
v, _, _ = rb.verdict(sus, "strict", None)
check("never RED alone (strict)", {v}, {"YELLOW"})
ok = rb.trust_findings("psf/requests", {"full_name": "psf/requests", "created_at": ago(5000), "stargazers_count": 52000, "forks_count": 9000},
                       {"created_at": ago(6000)}, 700, NOW)
check("established repo", rules(ok), {"trust-signals"}, absent={"repo-moved", "young-repo", "young-owner", "star-spike", "single-contributor"})
check("non-github target skipped", {str(rb.trust_signals("/tmp/x"))}, {"([], None)"})
# provenance payloads (mocked; no network)
payloads = {
    "repos/acme/tool/commits/main": {"commit": {"verification": {"verified": False, "reason": "unsigned"}}, "author": None},
    "repos/acme/tool/tags?per_page=1": [{"name": "v1.0.0", "commit": {"sha": "deadbeef"}}],
    "repos/acme/tool/commits/deadbeef": {"commit": {"verification": {"verified": False, "reason": "unsigned"}}},
    "repos/acme/tool/releases/latest": {"tag_name": "v1.0.0", "immutable": False},
    "repos/upstream/tool/compare/main...acme:main": {"ahead_by": 3, "files": [{"filename": "a"}, {"filename": "b"}]},
}
def fake_get(path):
    if path not in payloads:
        raise RuntimeError(f"404 {path}")
    return payloads[path]
repo_fork = {"full_name": "acme/tool", "created_at": ago(500), "stargazers_count": 20, "forks_count": 2,
             "fork": True, "default_branch": "main", "owner": {"login": "acme"},
             "parent": {"full_name": "upstream/tool", "default_branch": "main"}}
prov = rb.trust_provenance("acme/tool", repo_fork, fake_get)
check("provenance payloads parsed",
      {bool(prov.get(k)) for k in ("commit", "tag", "release", "fork")}, {True})
fs = rb.trust_findings("acme/tool", repo_fork, {"created_at": ago(900)}, 5, NOW, provenance=prov)
check("unsigned/unassociated/mutable/fork-drift signals",
      rules(fs), {"commit-unsigned", "commit-unassociated", "tag-unsigned", "release-mutable", "fork-drift"})
check("provenance signals are LOW/INFO only", {f["severity"] for f in fs}, set(), absent={"medium", "high", "critical"})
v, _, _ = rb.verdict(fs, "strict", None)
check("provenance never turns a trusted repo RED", {v}, {"YELLOW"})
signed = {"commit": {"verified": True, "reason": "valid", "author": "acme"},
          "tag": {"name": "v1.0.0", "verified": True, "reason": "valid"},
          "release": {"tag": "v1.0.0", "immutable": True},
          "fork": {"upstream": "upstream/tool", "ahead": 0, "files": 0}}
fs = rb.trust_findings("acme/tool", repo_fork, {"created_at": ago(900)}, 5, NOW, provenance=signed)
check("signed/immutable/synced are info",
      rules(fs), {"release-immutable", "fork-synced"}, absent={"commit-unsigned", "commit-unassociated", "release-mutable"})
check("missing provenance data is silent",
      set(f for f in rules(rb.trust_findings("psf/requests", repo_fork, None, 7, NOW, provenance={}))),
      set(), absent={"commit-unsigned", "commit-unassociated", "tag-unsigned", "release-mutable", "fork-drift"})
check("an API failure yields a partial provenance, never an exception",
      {bool(rb.trust_provenance("acme/tool", repo_fork, lambda path: (_ for _ in ()).throw(RuntimeError("404"))))}, {False})
import os; os.environ["BEAGLE_GITHUB_API"] = "http://127.0.0.1:9"
fs, note = rb.trust_signals("https://github.com/a/b")
check("offline is graceful", {bool(note), len(fs)}, {True, 0})
sys.exit(fail)
