#!/usr/bin/env python3
"""Web audit tests: local page, redirects, asset failures as notes, the 2 MB cap, and the privacy-only contract."""
import http.server, json, subprocess, sys, tempfile, threading
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

def web(url, *extra, timeout=600):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        out = Path(fh.name)
    try:
        r = subprocess.run([sys.executable, str(ROOT / "repobeagle.py"), "web", url, "--json", str(out),
                            "--no-color"] + list(extra), capture_output=True, text=True, timeout=timeout)
        try:
            return json.loads(out.read_text(encoding="utf-8")), r
        except ValueError:
            return {}, r
    finally:
        out.unlink(missing_ok=True)

# a real page from the fixtures: web mode, first-party inference, privacy-only findings
page = (ROOT / "tests/fixtures/trap-privacy/web/index.html").resolve()
d, _ = web(f"file://{page}")
meta = d.get("meta") or {}
fetched = meta.get("fetched") or {}
tools = {f.get("tool") for f in d.get("findings") or []}
check("file page audits as web mode with the privacy-only profile",
      meta.get("mode", "").startswith("web") and meta.get("privacy_mode") == "only"
      and meta.get("url") == f"file://{page}")
check("fetch metadata records the final URL and limits",
      fetched.get("page_bytes", 0) > 0 and fetched.get("final_url") == f"file://{page}"
      and fetched.get("redirected") is False and fetched.get("truncated") is False
      and fetched.get("asset_failures") == 0)
check("web mode surfaces no non-privacy scanner output", tools <= {"privacy", "telemetry", "agent-checks", "semgrep"})
check("third-party rules run on the page", any(f["title"].startswith("third-party-") for f in d["findings"]))

# missing assets are notes, never fatal
with tempfile.TemporaryDirectory() as td:
    p = Path(td) / "page.html"
    p.write_text('<html><head><link rel="stylesheet" href="missing.css"></head>'
                 '<body><script src="missing.js"></script>hello</body></html>')
    d, r = web(f"file://{p}", "--assets", "2")
    fetched = (d.get("meta") or {}).get("fetched") or {}
    notes = " ".join(d.get("notes") or [])
    check("asset fetch failures are recorded as notes",
          r.returncode in (0, 1) and fetched.get("asset_failures") == 2 and fetched.get("assets") == 0
          and "asset fetch failed" in notes and fetched.get("truncated") is False)

# the size cap is enforced and marked
with tempfile.TemporaryDirectory() as td:
    p = Path(td) / "big.html"
    p.write_text("<html><body>" + ("a" * 2_000_100) + "</body></html>")
    d, _ = web(f"file://{p}")
    fetched = (d.get("meta") or {}).get("fetched") or {}
    notes = " ".join(d.get("notes") or [])
    check("page size cap is enforced and recorded",
          fetched.get("truncated") is True and fetched.get("page_bytes") == rb.WEB_MAX_BYTES
          and "page truncated at 2000000 bytes" in notes)

# redirects are followed and recorded, with the final URL, offline on localhost
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/start":
            self.send_response(302)
            self.send_header("Location", "/landing")
            self.end_headers()
            return
        body = b"<html><head><title>ok</title></head><body>hello</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
try:
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    d, r = web(f"{base}/start")
    meta = d.get("meta") or {}
    fetched = meta.get("fetched") or {}
    notes = " ".join(d.get("notes") or [])
    check("redirects are followed and recorded", r.returncode in (0, 1)
          and fetched.get("redirected") is True and fetched.get("final_url", "").endswith("/landing")
          and f"redirected to {base}/landing" in notes)
    check("redirected page is audited as the final host", meta.get("url") == f"{base}/start"
          and meta.get("privacy_mode") == "only" and fetched.get("page_bytes", 0) > 0)
finally:
    srv.shutdown()

sys.exit(fail)
