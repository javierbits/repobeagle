#!/usr/bin/env python3
"""serve: immutable per-(repo, sha) reports, 429 budgets, permalink pages, hostile paths; no network."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
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


class Server:
    def __init__(self, cache, *extra, root=None):
        self.proc = subprocess.Popen(
            [sys.executable, str(SCANNER), "serve", "--port", "0", "--cache", str(cache),
             "--root", str(root or FIXTURES), "--no-docker", "--no-osv", "--no-trust", *extra],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            env=dict(os.environ, XDG_CACHE_HOME=str(cache), BEAGLE_NO_UPDATE_CHECK="1", COSIGN_PASSWORD=""))
        self.port = None
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                break
            m = re.search(r"http://[^:]+:(\d+)", line)
            if m:
                self.port = int(m.group(1))
                break
        if self.port is None:
            self.proc.kill()
            self.log = self.proc.stdout.read() if self.proc.stdout else ""
            raise AssertionError(f"serve did not start:\n{self.log}")

    @property
    def base(self):
        return f"http://127.0.0.1:{self.port}"

    def get(self, path, timeout=300):
        try:
            with urllib.request.urlopen(self.base + path, timeout=timeout) as r:
                return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
        except urllib.error.HTTPError as ex:
            return ex.code, {k.lower(): v for k, v in ex.headers.items()}, ex.read()

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.proc.kill()


with tempfile.TemporaryDirectory() as td:
    cache = Path(td) / "cache"
    server = Server(cache, "--ip-budget", "50", "--repo-budget", "50")
    try:
        s, h, b = server.get("/healthz")
        health = json.loads(b)
        check("healthz reports the service and signing state",
              s == 200 and health.get("service") == "repobeagle" and health.get("signing") == "off", str(health))

        s, h, b = server.get("/v1/scan/local/control-clean")
        report = json.loads(b) if s == 200 else {}
        check("scan endpoint returns the GREEN report", s == 200 and report.get("verdict") == "GREEN", str(s))
        check("service stamps provenance verify needs",
              (report.get("meta") or {}).get("scanned_repo") == "local/control-clean"
              and re.fullmatch(r"[0-9a-f]{40}", str((report.get("meta") or {}).get("scanned_sha") or ""))
              and (report.get("meta") or {}).get("service", {}).get("signed") is False,
              json.dumps((report.get("meta") or {}).get("service")))
        check("first request is a cache miss", h.get("x-repobeagle-cache") == "miss", str(h.get("x-repobeagle-cache")))
        first = b

        s, h, b = server.get("/v1/scan/local/control-clean")
        check("a repeated scan is served from the immutable cache",
              s == 200 and h.get("x-repobeagle-cache") == "hit" and b == first,
              f"{s} {h.get('x-repobeagle-cache')} identical={b == first}")
        check("unsigned reports advertise no signature", h.get("x-repobeagle-signed") == "false",
              str(h.get("x-repobeagle-signed")))

        s, h, b = server.get("/o/local/control-clean")
        check("permalink renders the self-contained HTML report",
              s == 200 and h.get("content-type", "").startswith("text/html")
              and b"RepoBeagle" in b and b"/v1/scan/local/control-clean" in b,
              f"{s} {h.get('content-type')}")

        # Cache self-heals when the stored bytes are corrupt (immutable means "written once", not "trusted").
        meta = (report.get("meta") or {})
        cached = cache / "local" / "control-clean" / str(meta.get("scanned_sha")) / "report.json"
        check("cache file exists per (repo, sha)", cached.is_file(), str(cached))
        cached.write_text("{not json", encoding="utf-8")
        s, h, b = server.get("/v1/scan/local/control-clean")
        check("a corrupt cache entry is a miss and is repaired",
              s == 200 and h.get("x-repobeagle-cache") == "miss" and json.loads(b)["verdict"] == "GREEN",
              f"{s} {h.get('x-repobeagle-cache')}")

        s, h, b = server.get("/v1/scan/local/no-such-dir")
        check("unknown local repository is a 404", s == 404, str(s))
        s, h, b = server.get("/v1/scan/local/..")
        check("a path escaping --root is rejected with 400", s == 400, str(s))
        s, h, b = server.get("/v1/scan/bad!slug/control-clean")
        check("an invalid slug is a 400", s == 400, str(s))
        s, h, b = server.get("/no/such/route")
        check("unknown route is a 404", s == 404, str(s))
        s, h, b = server.get("/v1/scan/local/control-clean/abcdef1/bundle")
        check("unsigned reports have no bundle", s == 404, str(s))
        s, h, b = server.get("/")
        check("index lists the API surface", s == 200 and "/v1/scan/<owner>/<repo>[/<ref>]" in json.loads(b)["endpoints"])
    finally:
        server.stop()

    # Per-IP budget: every request counts, including cache hits, so a hot client sees 429.
    limited = Path(td) / "limited"
    server = Server(limited, "--ip-budget", "1", "--repo-budget", "50")
    try:
        s1, _, _ = server.get("/v1/scan/local/control-clean")
        s2, h2, b2 = server.get("/v1/scan/local/control-clean")
        check("a client over its IP budget gets 429, not a wrong verdict",
              s1 == 200 and s2 == 429 and int(h2.get("retry-after", "0")) >= 1
              and "budget" not in json.loads(b2).get("verdict", ""), f"{s1},{s2} retry={h2.get('retry-after')}")
    finally:
        server.stop()

    # Per-repo budget gates new scans of the same repository; cached results stay served.
    root = Path(td) / "root"
    (root / "repo-a").mkdir(parents=True)
    (root / "repo-a" / "README.md").write_text("# clean\n", encoding="utf-8")
    (root / "repo-b").mkdir(parents=True)
    (root / "repo-b" / "README.md").write_text("# clean\n", encoding="utf-8")
    scans = Path(td) / "scans"
    server = Server(scans, "--ip-budget", "50", "--repo-budget", "1", root=root)
    try:
        a, _, _ = server.get("/v1/scan/local/repo-a")
        (root / "repo-a" / "README.md").write_text("# clean\nchanged\n", encoding="utf-8")
        b, hb, _ = server.get("/v1/scan/local/repo-a")
        c, hc, _ = server.get("/v1/scan/local/repo-a")
        other, _, _ = server.get("/v1/scan/local/repo-b")
        check("the scan budget is per repository: repo-a is 429 while repo-b scans",
              a == 200 and b == 429 and int(hb.get("retry-after", "0")) >= 1 and c == 429
              and other == 200, f"a={a} b={b} retry={hb.get('retry-after')} other={other}")
    finally:
        server.stop()

    # A local cosign key exercises the signature path without OIDC; CI covers keyless.
    # `verify` would download cosign when missing, so stay offline by skipping in that case.
    if shutil.which("cosign"):
        keys = Path(td) / "keys"
        keys.mkdir()
        gen = subprocess.run(["cosign", "generate-key-pair"], cwd=keys, capture_output=True, text=True,
                             env=dict(os.environ, COSIGN_PASSWORD=""))
        check("cosign key pair generated", gen.returncode == 0 and (keys / "cosign.key").is_file(), gen.stderr[-300:])
        signed_cache = Path(td) / "signed-cache"
        server = Server(signed_cache, "--ip-budget", "50", "--repo-budget", "50",
                        "--sign", "--key", str(keys / "cosign.key"))
        try:
            s, h, b = server.get("/v1/scan/local/control-clean")
            report_path = Path(td) / "signed-report.json"
            report_path.write_bytes(b)
            s2, h2, bundle = server.get("/v1/scan/local/control-clean/bundle")
            bundle_path = Path(td) / "signed-report.sigstore.json"
            bundle_path.write_bytes(bundle)
            bundle_doc = json.loads(bundle) if s2 == 200 else {}
            check("a signed report advertises its bundle",
                  s == 200 and h.get("x-repobeagle-signed") == "true" and s2 == 200
                  and isinstance(bundle_doc, dict) and bool(bundle_doc) and "verdict" not in bundle_doc,
                  f"{s} {h.get('x-repobeagle-signed')} {s2} keys={sorted(bundle_doc) if isinstance(bundle_doc, dict) else bundle_doc}")
            ver = subprocess.run([sys.executable, str(SCANNER), "verify", "--report", str(report_path),
                                  "--bundle", str(bundle_path), "--key", str(keys / "cosign.pub")],
                                 cwd=ROOT, capture_output=True, text=True, timeout=120,
                                 env=dict(os.environ, XDG_CACHE_HOME=str(Path(td) / "verify-cache"),
                                          BEAGLE_NO_UPDATE_CHECK="1"))
            check("a service report signed with a local key verifies", ver.returncode == 0,
                  (ver.stdout + ver.stderr)[-400:])
        finally:
            server.stop()
    else:
        print("SKIP local-key signing (cosign is not installed)")

sys.exit(fail)
