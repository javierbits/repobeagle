#!/usr/bin/env python3
"""app: signed webhooks, one updated comment, one updated check run, no PR code executed; fake GitHub API."""
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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


class FakeGitHub:
    """Records exactly the API calls the App makes; no network, no GitHub."""

    def __init__(self):
        self.lock = threading.Lock()
        self.comments = []
        self.check_runs = []
        self.token_calls = 0
        self.bad_auth = 0
        self.check_updates = 0
        self.comment_updates = 0
        self.server = None

    def start(self):
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):
                pass

            def _body(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                return json.loads(raw) if raw else {}

            def _send(self, code, obj):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _authed(self):
                if not str(self.headers.get("Authorization", "")).startswith("Bearer "):
                    with fake.lock:
                        fake.bad_auth += 1

            def do_GET(self):
                self._authed()
                parts = urllib.parse.urlsplit(self.path).path.strip("/").split("/")
                with fake.lock:
                    if len(parts) == 6 and parts[0] == "repos" and parts[3] == "commits":
                        return self._send(200, {"check_runs": [r for r in fake.check_runs
                                                            if r["head_sha"] == parts[4]]})
                    if len(parts) == 6 and parts[0] == "repos" and parts[3] == "issues" and parts[5] == "comments":
                        return self._send(200, [{"id": c["id"], "body": c["body"]} for c in fake.comments])
                return self._send(404, {"message": "no route"})

            def do_POST(self):
                self._authed()
                parts = urllib.parse.urlsplit(self.path).path.strip("/").split("/")
                body = self._body()
                with fake.lock:
                    if parts[:1] == ["app"] and parts[-1] == "access_tokens":
                        fake.token_calls += 1
                        return self._send(201, {"token": "installation-token",
                                                "expires_at": "2099-01-01T00:00:00Z"})
                    if len(parts) == 6 and parts[0] == "repos" and parts[3] == "issues" and parts[5] == "comments":
                        comment = {"id": len(fake.comments) + 1, "body": body.get("body", "")}
                        fake.comments.append(comment)
                        return self._send(201, comment)
                    if len(parts) == 4 and parts[0] == "repos" and parts[3] == "check-runs":
                        run = {"id": len(fake.check_runs) + 1, "name": body.get("name"),
                               "head_sha": body.get("head_sha"), "status": body.get("status"),
                               "conclusion": body.get("conclusion"), "output": body.get("output") or {}}
                        fake.check_runs.append(run)
                        return self._send(201, run)
                return self._send(404, {"message": "no route"})

            def do_PATCH(self):
                self._authed()
                parts = urllib.parse.urlsplit(self.path).path.strip("/").split("/")
                body = self._body()
                with fake.lock:
                    if len(parts) == 6 and parts[0] == "repos" and parts[4] == "comments":
                        for c in fake.comments:
                            if c["id"] == int(parts[5]):
                                c["body"] = body.get("body", c["body"])
                                fake.comment_updates += 1
                                return self._send(200, c)
                        return self._send(404, {"message": "no comment"})
                    if len(parts) == 5 and parts[0] == "repos" and parts[3] == "check-runs":
                        for r in fake.check_runs:
                            if r["id"] == int(parts[4]):
                                r["conclusion"] = body.get("conclusion", r["conclusion"])
                                r["status"] = body.get("status", r["status"])
                                r["output"] = body.get("output", r["output"])
                                fake.check_updates += 1
                                return self._send(200, r)
                        return self._send(404, {"message": "no check run"})
                return self._send(404, {"message": "no route"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()


class AppServer:
    def __init__(self, root, api, cache="", *extra):
        self.proc = subprocess.Popen(
            [sys.executable, str(SCANNER), "app", "--port", "0", "--host", "127.0.0.1",
             "--api-url", api, "--secret", "s3cret", "--token", "static-installation-token",
             "--root", str(root), "--no-docker", "--no-osv", "--no-trust", *extra],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            env=dict(os.environ, XDG_CACHE_HOME=str(Path(cache) if cache else Path(tempfile.mkdtemp())),
                     BEAGLE_NO_UPDATE_CHECK="1"))
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
            raise AssertionError("app did not start: " + (self.proc.stdout.read() if self.proc.stdout else ""))

    def webhook(self, event, payload, secret="s3cret", delivery="delivery-1"):
        body = json.dumps(payload).encode()
        sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/webhook", data=body, method="POST",
            headers={"Content-Type": "application/json", "X-GitHub-Event": event,
                     "X-GitHub-Delivery": delivery, "X-Hub-Signature-256": sig,
                     "User-Agent": "github-hookshot"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as ex:
            return ex.code, json.loads(ex.read() or b"{}")

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        try:
            self.output = self.proc.stdout.read() if self.proc.stdout else ""
        except ValueError:
            self.output = ""
        if fail:
            print("--- app log ---\n" + self.output[-3000:])


def wait_for(predicate, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return False


def pr_payload(slug, number, head, base, action="opened", installation=1):
    return {"action": action, "number": number, "installation": {"id": installation},
            "repository": {"full_name": slug, "default_branch": "main"},
            "pull_request": {"number": number, "head": {"sha": head}, "base": {"sha": base}}}


def push_payload(slug, sha, ref="refs/heads/main"):
    return {"ref": ref, "after": sha, "installation": {"id": 1},
            "repository": {"full_name": slug, "default_branch": "main"}}


with tempfile.TemporaryDirectory() as td:
    root = Path(td) / "root"
    shutil.copytree(FIXTURES / "trap-gha", root / "repo-a")
    api = FakeGitHub().start()
    app = AppServer(root, api.url, td)
    try:
        s, body = app.webhook("ping", {"zen": "Keep it simple."})
        check("ping is answered without work", s == 200 and body.get("zen") == "Keep it simple.", str(body))

        head1, base = "a" * 40, "b" * 40
        s, body = app.webhook("pull_request", pr_payload("local/repo-a", 7, head1, base), delivery="d1")
        ok = wait_for(lambda: len(api.comments) == 1 and len(api.check_runs) == 1)
        check("a PR webhook produces exactly one comment and one check run", s == 202 and ok,
              f"{s} comments={len(api.comments)} checks={len(api.check_runs)}")
        if ok:
            check("the comment is the App's single collapsing report",
                  api.comments[0]["body"].startswith("<!-- repobeagle:app -->")
                  and "<details>" in api.comments[0]["body"]
                  and "no PR head code was executed" in api.comments[0]["body"],
                  api.comments[0]["body"][:300])
            check("the check run carries the same report and the webhook commit",
                  api.check_runs[0]["head_sha"] == head1
                  and api.check_runs[0]["name"] == "repobeagle"
                  and "RepoBeagle" in (api.check_runs[0]["output"].get("summary") or ""),
                  json.dumps(api.check_runs[0])[:300])
        check("the App never used a tokenless call", api.bad_auth == 0, str(api.bad_auth))

        comment_id, run_id, first_sha = api.comments[0]["id"], api.check_runs[0]["id"], api.check_runs[0]["head_sha"]
        head2 = "c" * 40
        comment_updates = api.comment_updates
        s, _ = app.webhook("pull_request", pr_payload("local/repo-a", 7, head2, base, action="synchronize"),
                           delivery="d2")
        ok = wait_for(lambda: len(api.check_runs) == 2 and api.comment_updates > comment_updates)
        check("a new push updates the same comment and adds a check run for the new commit",
              s == 202 and ok and len(api.comments) == 1 and api.comments[0]["id"] == comment_id
              and api.check_runs[1]["head_sha"] == head2,
              f"comments={len(api.comments)} checks={len(api.check_runs)}")

        # Replaying the same delivery must edit, not duplicate: comment count stays 1 and the
        # check run for head2 is updated in place (same id).
        second_id = api.check_runs[1]["id"]
        updates = api.check_updates
        s, _ = app.webhook("pull_request", pr_payload("local/repo-a", 7, head2, base, action="synchronize"),
                           delivery="d2")
        ok = wait_for(lambda: api.check_updates > updates)
        check("a replayed webhook does not duplicate the comment or the check run",
              len(api.comments) == 1 and len(api.check_runs) == 2
              and api.check_runs[1]["id"] == second_id and ok,
              f"comments={len(api.comments)} checks={len(api.check_runs)}")

        push_sha = "d" * 40
        s, _ = app.webhook("push", push_payload("local/repo-a", push_sha), delivery="d3")
        ok = wait_for(lambda: len(api.check_runs) == 3)
        check("a default-branch push gets a check run but no PR comment",
              s == 202 and ok and len(api.comments) == 1
              and api.check_runs[2]["head_sha"] == push_sha,
              f"comments={len(api.comments)} checks={len(api.check_runs)}")
        runs_after_push = [(r["id"], (r["head_sha"] or "")[:8]) for r in api.check_runs]
        s, _ = app.webhook("push", push_payload("local/repo-a", "e" * 40, ref="refs/heads/topic"), delivery="d4")
        time.sleep(0.5)
        check("a non-default push is ignored", len(api.check_runs) == 3,
              f"{len(api.check_runs)} runs={runs_after_push} -> {[(r['id'], (r['head_sha'] or '')[:8]) for r in api.check_runs]}")

        s, body = app.webhook("pull_request", pr_payload("local/no-such-repo", 8, "f" * 40, base))
        time.sleep(0.5)
        check("an unknown repository is logged, not fatal",
              s == 202 and len(api.comments) == 1 and len(api.check_runs) == 3, str(s))

        before = (len(api.comments), len(api.check_runs))
        s, body = app.webhook("pull_request", pr_payload("local/repo-a", 7, "0" * 40, base),
                              secret="wrong-secret", delivery="d5")
        time.sleep(0.3)
        check("a bad signature is 401 and makes no API calls",
              s == 401 and (len(api.comments), len(api.check_runs)) == before, str(s))
        s, _ = app.webhook("issues", {"action": "opened"}, delivery="d6")
        check("an unrelated event is accepted and ignored", s == 202, str(s))
    finally:
        app.stop()
        api.stop()

    # App JWT path: PyJWT + cryptography are optional for the scanner, exercised when installed.
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import jwt
        sys.path.insert(0, str(ROOT))
        import repobeagle as rb
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption()).decode()
        claims = jwt.decode(rb._app_jwt(123, pem), key.public_key(), algorithms=["RS256"],
                             options={"verify_aud": False})
        check("App JWT carries the app id and a short lifetime",
              claims["iss"] == "123" and 0 < claims["exp"] - claims["iat"] <= 900, str(claims))
    except ImportError:
        print("SKIP App JWT (pyjwt/cryptography not installed)")

sys.exit(fail)
