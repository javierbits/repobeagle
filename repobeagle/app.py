import argparse, base64, concurrent.futures, difflib, hashlib, hmac, json, os, platform, queue, re, shlex, shutil, signal, subprocess, sys, tempfile, threading, time, unicodedata, uuid, zipfile
import urllib.error, urllib.parse, urllib.request
from datetime import date, datetime, timezone
from fnmatch import fnmatchcase
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from pathlib import Path


# --- cross-module imports ---

from .core import SEV_ORDER, VERSION, _rule_of, _trend_epoch
from .scanners import ScanFailure, scan_json_report, tree_digest








# ---------------------------------------------------------------------------
# GitHub App: webhook -> static scan -> one updated comment + one check run
# ---------------------------------------------------------------------------
APP_MARKER = "<!-- repobeagle:app -->"


APP_CHECK_NAME = "repobeagle"


APP_PR_ACTIONS = {"opened", "synchronize", "reopened", "ready_for_review"}


APP_QUEUE_MAX = 100


APP_PERMISSIONS = ("contents: read, metadata: read, pull_requests: write, issues: write, checks: write")


class AppError(Exception):
    """A webhook or GitHub API problem worth logging; never a traceback for the worker."""


def _app_signature_ok(secret, body, header):
    if not header or not header.startswith("sha256="):
        return False
    return hmac.compare_digest("sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest(),
                               header.strip())


def _app_jwt(app_id, private_key):
    """RS256 App JWT. PyJWT is optional for the scanner but required for App auth."""
    try:
        import jwt
    except ImportError as ex:
        raise AppError("PyJWT is required for GitHub App auth (pip install 'pyjwt[crypto]') or use --token") from ex
    key = private_key if "\n" in private_key else Path(private_key).read_text(encoding="utf-8")
    now = int(time.time())
    return jwt.encode({"iat": now - 60, "exp": now + 540, "iss": str(app_id)}, key, algorithm="RS256")


class GitHubAppClient:
    """Minimal GitHub App API client: installation token, one PR comment, one check run per SHA."""

    def __init__(self, api, app_id=None, private_key=None, token=None):
        self.api = api.rstrip("/")
        self.app_id = app_id
        self.private_key = private_key
        self.static_token = token
        self.tokens: dict[str, tuple[str, float]] = {}

    def _installation_token(self, installation_id):
        if self.static_token:
            return self.static_token
        now = time.time()
        cached = self.tokens.get(str(installation_id))
        if cached and cached[1] > now + 30:
            return cached[0]
        data = self.request("POST", f"/app/installations/{installation_id}/access_tokens",
                             token=_app_jwt(self.app_id, self.private_key))
        token = str(data.get("token") or "")
        if not token:
            raise AppError("installation token exchange returned no token")
        self.tokens[str(installation_id)] = (token, _trend_epoch(data.get("expires_at")) or now + 300)
        return token

    def request(self, method, path, token=None, body=None):
        headers = {"User-Agent": "repobeagle", "Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.api + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                raw = resp.read().decode("utf-8", "replace")
                return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as ex:
            detail = ex.read().decode("utf-8", "replace")[:300]
            raise AppError(f"GitHub API {method} {path.split('?')[0]} -> {ex.code}: {detail}") from ex
        except Exception as ex:
            raise AppError(f"GitHub API {method} {path.split('?')[0]} failed: {str(ex)[:160]}") from ex

    def find_comment(self, slug, number, token):
        data = self.request("GET", f"/repos/{slug}/issues/{number}/comments?per_page=100", token=token)
        for comment in data if isinstance(data, list) else []:
            if APP_MARKER in str(comment.get("body") or ""):
                return comment
        return None

    def put_comment(self, slug, number, body, token):
        existing = self.find_comment(slug, number, token)
        if existing:
            return self.request("PATCH", f"/repos/{slug}/issues/comments/{existing['id']}",
                                 token=token, body={"body": body})
        return self.request("POST", f"/repos/{slug}/issues/{number}/comments", token=token, body={"body": body})

    def find_check_run(self, slug, sha, token):
        data = self.request("GET", f"/repos/{slug}/commits/{sha}/check-runs?check_name={APP_CHECK_NAME}", token=token)
        for run in (data.get("check_runs") or []) if isinstance(data, dict) else []:
            if str(run.get("name")) == APP_CHECK_NAME:
                return run
        return None

    def put_check_run(self, slug, sha, conclusion, title, summary, token):
        output = {"title": title[:255], "summary": summary[:65000]}
        existing = self.find_check_run(slug, sha, token)
        if existing:
            return self.request("PATCH", f"/repos/{slug}/check-runs/{existing['id']}", token=token,
                                 body={"status": "completed", "conclusion": conclusion, "output": output})
        return self.request("POST", f"/repos/{slug}/check-runs", token=token,
                             body={"name": APP_CHECK_NAME, "head_sha": sha, "status": "completed",
                                   "conclusion": conclusion, "output": output})


def _md(value, limit=180):
    text = re.sub(r"\s+", " ", str(value or "")).strip().replace("|", "\\|")
    return text[:limit]


def app_report_comment(d, scope):
    """One collapsing PR comment: verdict, counts, top findings, and the no-execution statement."""
    verdict = str(d.get("verdict") or "?")
    counts = d.get("counts") or {}
    meta = d.get("meta") or {}
    sha = str(meta.get("scanned_sha") or meta.get("commit") or "")
    findings = [f for f in (d.get("findings") or [])
                if isinstance(f, dict) and f.get("severity") in SEV_ORDER and not f.get("suppressed")]
    findings.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f.get("file") or "", f.get("line") or 0))
    lines = [APP_MARKER, f"### RepoBeagle: **{verdict}**",
             f"{counts.get('critical', 0)} critical · {counts.get('high', 0)} high · "
             f"{counts.get('medium', 0)} medium · {counts.get('low', 0)} low"
             f" · `{sha[:7] or '?'}` · {scope}"]
    top = findings[:5]
    if top:
        lines += ["", "<details><summary>Top findings</summary>", ""]
        for f in top:
            loc = str(f.get("file") or "?")
            if f.get("line"):
                loc += f":{f['line']}"
            lines.append(f"- **{f['severity']}** `{_md(_rule_of(f), 60)}` — {_md(f.get('title'))} ({_md(loc)})")
        lines += ["", "</details>"]
        if len(findings) > len(top):
            lines.append(f"{len(findings) - len(top)} more finding(s) are in the report.")
    lines += ["", "_Scanned statically; no PR head code was executed._"]
    return "\n".join(lines)[:65000]


class AppState:
    """Webhook queue and worker pool: GitHub must get its 2xx within seconds, scans take minutes."""

    def __init__(self, a):
        secret = getattr(a, "secret", None) or os.environ.get("BEAGLE_APP_WEBHOOK_SECRET") or ""
        if not secret:
            raise AppError("give --secret or set BEAGLE_APP_WEBHOOK_SECRET (the App's webhook secret)")
        self.secret = secret
        token = getattr(a, "token", None) or os.environ.get("BEAGLE_INSTALLATION_TOKEN")
        app_id = getattr(a, "app_id", None) or os.environ.get("BEAGLE_APP_ID")
        private_key = getattr(a, "private_key", None) or os.environ.get("BEAGLE_APP_PRIVATE_KEY")
        if not token and not (app_id and private_key):
            raise AppError("give --app-id + --private-key (App auth), or --token (installation token)")
        api = getattr(a, "api_url", None) or os.environ.get("BEAGLE_GITHUB_API") or "https://api.github.com"
        self.client = GitHubAppClient(api, app_id, private_key, token)
        self.args = a
        self.root = Path(a.root).resolve() if getattr(a, "root", None) else None
        self.queue: queue.Queue = queue.Queue(maxsize=APP_QUEUE_MAX)
        for _ in range(max(1, int(getattr(a, "concurrency", 1) or 1))):
            threading.Thread(target=self._worker, daemon=True).start()

    def submit(self, event, payload, delivery):
        try:
            self.queue.put_nowait((event, payload, delivery))
            return True
        except queue.Full:
            return False

    def _worker(self):
        while True:
            event, payload, delivery = self.queue.get()
            try:
                self.handle(event, payload)
            except Exception as ex:
                print(f"app: {event} {delivery[:8] or '?'}: {type(ex).__name__}: {ex}", file=sys.stderr)
            finally:
                self.queue.task_done()

    def _target(self, slug, ref):
        """(scan target, ref, cache identity, local) for a GitHub slug or a local/<dir> test repo."""
        if self.root is not None and slug.startswith("local/"):
            path = (self.root / slug.split("/", 1)[1]).resolve()
            if path != self.root and self.root not in path.parents:
                raise AppError(f"{slug} escapes --root")
            if not path.is_dir():
                raise AppError(f"local repository {slug} not found")
            # Identity is the webhook commit/tree SHA (like GitHub mode); a local directory is
            # only a substitute for the clone. Fall back to the tree digest for manual calls.
            return str(path), None, ref or tree_digest(path)[:40], True
        return f"https://github.com/{slug}.git", ref, ref, False

    def handle(self, event, payload):
        repo = payload.get("repository") or {}
        slug = str(repo.get("full_name") or "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", slug):
            raise AppError(f"webhook has no usable repository full_name ({slug!r})")
        installation = (payload.get("installation") or {}).get("id")
        if event == "pull_request":
            if payload.get("action") not in APP_PR_ACTIONS:
                return
            pr = payload.get("pull_request") or {}
            head = str((pr.get("head") or {}).get("sha") or "")
            base = str((pr.get("base") or {}).get("sha") or "")
            number = payload.get("number") or pr.get("number")
            if not head or not number:
                raise AppError("pull_request webhook has no head SHA or PR number")
            target, ref, sha, local = self._target(slug, head)
            # Fetch the PR ref, not the bare SHA: it exists for fork PRs too, and the check run
            # still records the real head SHA (`meta.commit` resolves to it).
            scan_ref = ref if local else f"refs/pull/{int(number)}/head"
            self._scan_and_publish(slug, installation, int(number), target, scan_ref, sha,
                                   None if local else (base or None), comment=True)
        elif event == "push":
            if payload.get("ref") != f"refs/heads/{repo.get('default_branch') or ''}":
                return
            sha = str(payload.get("after") or "")
            if not sha or not set(sha) - {"0"}:
                return
            target, ref, sha, local = self._target(slug, sha)
            self._scan_and_publish(slug, installation, None, target, ref, sha, None, comment=False)

    def _scan_and_publish(self, slug, installation, number, target, ref, sha, since, comment):
        a = self.args
        try:
            raw = scan_json_report(target, ref, since=since,
                                   profile=getattr(a, "profile", "balanced"),
                                   no_docker=getattr(a, "no_docker", False),
                                   no_osv=getattr(a, "no_osv", False),
                                   no_trust=getattr(a, "no_trust", False),
                                   privacy_only=getattr(a, "privacy_only", False),
                                   jobs=getattr(a, "jobs", 1), timeout=getattr(a, "timeout", 1800))
            d = json.loads(raw)
            meta = d.get("meta") if isinstance(d.get("meta"), dict) else {}
            meta["scanned_repo"] = slug
            meta["scanned_sha"] = sha
            meta["app"] = {"name": "repobeagle", "version": VERSION}
            d["meta"] = meta
            scope = "changed files only" if meta.get("scope") else "full tree"
            body = app_report_comment(d, scope)
            conclusion = {"RED": "failure", "YELLOW": "neutral", "GREEN": "success"}[str(d.get("verdict"))]
            title = f"RepoBeagle: {d.get('verdict')} ({scope})"
        except ScanFailure as ex:
            body = (f"{APP_MARKER}\n### RepoBeagle: scan failed\n\n{_md(ex)}")
            conclusion, title = "failure", "RepoBeagle: scan failed"
        token = self.client._installation_token(installation)
        if comment and number:
            self.client.put_comment(slug, number, body, token)
        self.client.put_check_run(slug, sha, conclusion, title, body, token)


def _app_handler(state):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = f"repobeagle/{VERSION}"

        def log_message(self, fmt, *args):
            print(f"app: {self.address_string()} - {fmt % args}", file=sys.stderr)

        def _send(self, code, obj):
            body = json.dumps(obj, sort_keys=True).encode() + b"\n"
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if urllib.parse.urlsplit(self.path).path == "/healthz":
                return self._send(200, {"ok": True, "service": "repobeagle-app", "version": VERSION})
            return self._send(404, {"error": "no such route"})

        def do_POST(self):
            if urllib.parse.urlsplit(self.path).path not in ("/", "/webhook"):
                return self._send(404, {"error": "no such route"})
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return self._send(400, {"error": "bad Content-Length"})
            if length <= 0 or length > 10_000_000:
                return self._send(413, {"error": "webhook body must be 1 byte - 10 MB"})
            raw = self.rfile.read(length)
            if not _app_signature_ok(state.secret, raw, self.headers.get("X-Hub-Signature-256", "")):
                return self._send(401, {"error": "invalid X-Hub-Signature-256"})
            try:
                payload = json.loads(raw)
            except ValueError:
                return self._send(400, {"error": "body is not JSON"})
            event = self.headers.get("X-GitHub-Event", "")
            delivery = self.headers.get("X-GitHub-Delivery", "")
            if event == "ping":
                return self._send(200, {"ok": True, "zen": payload.get("zen")})
            if event not in ("pull_request", "push"):
                return self._send(202, {"ok": True, "ignored": event or "unknown"})
            if not state.submit(event, payload, delivery):
                return self._send(503, {"error": "webhook queue is full; retry"})
            return self._send(202, {"ok": True, "event": event, "queued": True})
    return Handler


def cmd_app(a):
    """Runs the GitHub App webhook server: static scan, one updated comment and one check run per commit."""
    try:
        state = AppState(a)
    except AppError as ex:
        print(f"app: {ex}", file=sys.stderr)
        return 1
    try:
        httpd = ThreadingHTTPServer((a.host, a.port), _app_handler(state))
    except OSError as ex:
        print(f"app: cannot listen on {a.host}:{a.port}: {ex}", file=sys.stderr)
        return 1
    httpd.daemon_threads = True
    host, port = str(httpd.server_address[0]), int(httpd.server_address[1])
    shown = f"[{host}]" if ":" in host else host
    print(f"repobeagle app {VERSION}: http://{shown}:{port}/webhook (auth "
          f"{'installation token' if state.client.static_token else 'app credentials'})", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0