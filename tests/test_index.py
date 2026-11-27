#!/usr/bin/env python3
"""index: static signed results/pages, SHA refresh skip, --repos parsing, cap, failure isolation."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCANNER = ROOT / "repobeagle.py"
FIXTURES = ROOT / "tests" / "fixtures"
fail = 0


def check(name, ok, detail=""):
    global fail
    print(("PASS " if ok else "FAIL ") + name + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        fail = 1


def run(*args, timeout=900):
    return subprocess.run([sys.executable, str(SCANNER), "index", *map(str, args)],
                          cwd=ROOT, capture_output=True, text=True, timeout=timeout,
                          env=dict(os.environ, XDG_CACHE_HOME=tempfile.mkdtemp(),
                                   BEAGLE_NO_UPDATE_CHECK="1", COSIGN_PASSWORD=""))


def build(out, *entries, summary=None, extra=()):
    args = [*entries, "--out", out, "--jobs", "2", "--no-docker", "--no-osv", "--no-trust", *extra]
    if summary:
        args += ["--json", summary]
    r = run(*args)
    doc = json.loads(Path(summary).read_text(encoding="utf-8")) if summary and Path(summary).exists() else {}
    return r, doc


def result_files(out):
    return sorted((Path(out) / "results").glob("*/*@*.json"))


with tempfile.TemporaryDirectory() as td:
    tdp = Path(td)
    inputs = tdp / "input"
    shutil.copytree(FIXTURES / "control-clean", inputs / "clean")
    shutil.copytree(FIXTURES / "trap-gha", inputs / "gha")
    clean, gha = inputs / "clean", inputs / "gha"

    out1, summary1 = tdp / "public1", tdp / "summary1.json"
    r, doc = build(out1, clean, gha, summary=summary1)
    check("a curated local set builds signed-report results and pages", r.returncode == 0
          and doc.get("scanned") == 2 and len(result_files(out1)) == 2,
          (r.stderr or r.stdout)[-500:])
    index = (out1 / "index.html").read_text(encoding="utf-8")
    check("the index is searchable and lists both repositories",
          "<input id=\"q\"" in index and "local/clean" in index and "local/gha" in index
          and "Filter by repository or verdict" in index, index[:300])
    page = (out1 / "repo" / "local" / "clean.html").read_text(encoding="utf-8")
    check("a repository page links its report and the index",
          "results/local/clean@" in page and "../../index.html" in page and "RepoBeagle" in page,
          page[-300:])
    check("an unsigned local build says so", "built without signing" in index, index[:200])

    # SHA refresh skip: unchanged trees are not rescanned and the pages are regenerated.
    r2, doc2 = build(out1, clean, gha, summary=tdp / "summary2.json")
    check("unchanged HEAD SHA is skipped", r2.returncode == 0 and doc2.get("skipped") == 2
          and doc2.get("scanned") == 0, json.dumps(doc2)[:300])

    time.sleep(1.1)
    (clean / "README.md").open("a").write("\nchanged\n")
    r3, doc3 = build(out1, clean, gha, summary=tdp / "summary3.json")
    shas = sorted(p.name.split("@")[1][:-5] for p in result_files(out1))
    check("only the changed tree is rescanned and history accumulates",
          r3.returncode == 0 and doc3.get("scanned") == 1 and doc3.get("skipped") == 1
          and len(result_files(out1)) == 3, json.dumps(doc3)[:300])
    index3 = (out1 / "index.html").read_text(encoding="utf-8")
    check("the index points at the newest report for the changed repository",
          shas[-1][:12] in index3 and "local/clean" in index3, shas[-1])

    # --repos FILE parsing, comments, dedupe, and a bad entry that must not abort the run.
    repos = tdp / "repos.txt"
    repos.write_text(f"# curated\n{clean}\n\n{gha}\n{clean}\nnot-a-repo\n", encoding="utf-8")
    out2, summary4 = tdp / "public2", tdp / "summary4.json"
    r4, doc4 = build(out2, "--repos", repos, summary=summary4)
    check("--repos parses comments/dedupe and isolates a bad entry",
          r4.returncode == 0 and doc4.get("scanned") == 2 and doc4.get("failed") == 1,
          json.dumps(doc4)[:400])

    # Cap limits scans per run.
    out3, summary5 = tdp / "public3", tdp / "summary5.json"
    r5, doc5 = build(out3, clean, gha, summary=summary5, extra=("--cap", "1"))
    check("--cap bounds the entries scanned in one run",
          r5.returncode == 0 and doc5.get("scanned") == 1 and len(result_files(out3)) == 1,
          json.dumps(doc5)[:300])

    # Signing path: local cosign key (CI without cosign skips this block).
    if shutil.which("cosign"):
        keys = tdp / "keys"
        keys.mkdir()
        gen = subprocess.run(["cosign", "generate-key-pair"], cwd=keys, capture_output=True, text=True,
                             env=dict(os.environ, COSIGN_PASSWORD=""))
        check("cosign key pair generated", gen.returncode == 0 and (keys / "cosign.key").is_file(),
              gen.stderr[-300:])
        out4 = tdp / "public4"
        r6, doc6 = build(out4, clean, "--sign", "--key", keys / "cosign.key",
                         summary=tdp / "summary6.json")
        reports = [p for p in result_files(out4) if not p.name.endswith(".sigstore.json")]
        bundles = [p for p in result_files(out4) if p.name.endswith(".sigstore.json")]
        check("--sign publishes the bundle next to the report", r6.returncode == 0
              and len(reports) == 1 and len(bundles) == 1 and doc6.get("scanned") == 1,
              json.dumps(doc6)[:300])
        ver = subprocess.run([sys.executable, str(SCANNER), "verify", "--report", str(reports[0]),
                              "--bundle", str(bundles[0]), "--key", str(keys / "cosign.pub")],
                             cwd=ROOT, capture_output=True, text=True, timeout=120,
                             env=dict(os.environ, XDG_CACHE_HOME=str(tdp / "verify"),
                                      BEAGLE_NO_UPDATE_CHECK="1"))
        check("a published page's signed report verifies", ver.returncode == 0,
              (ver.stdout + ver.stderr)[-400:])
        index4 = (out4 / "index.html").read_text(encoding="utf-8")
        page4 = (out4 / "repo" / "local" / "clean.html").read_text(encoding="utf-8")
        check("a signed build advertises signature and bundle",
              "Sigstore-signed" in index4 and "Sigstore bundle" in page4, index4[:200])
    else:
        print("SKIP index signing (cosign is not installed)")

sys.exit(fail)
