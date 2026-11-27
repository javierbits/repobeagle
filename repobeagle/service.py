import argparse, base64, concurrent.futures, difflib, hashlib, hmac, json, os, platform, queue, re, shlex, shutil, signal, subprocess, sys, tempfile, threading, time, unicodedata, uuid, zipfile
import urllib.error, urllib.parse, urllib.request
from datetime import date, datetime, timezone
from fnmatch import fnmatchcase
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from pathlib import Path


# --- cross-module imports ---

from .core import VERSION, _atomic_write
from .fetch import cosign_sign_blob
from .report import html_report
from .scanners import ScanFailure, scan_json_report, tree_digest








# ---------------------------------------------------------------------------
# Hosted attestation service: `repobeagle serve` (scan API + permalinks)
# ---------------------------------------------------------------------------
SERVICE_SCAN_RE = re.compile(r"^/v1/scan/([^/]+)/([^/]+)(?:/([^/]+))?$")


SERVICE_BUNDLE_RE = re.compile(r"^/v1/scan/([^/]+)/([^/]+)(?:/([^/]+))?/bundle$")


SERVICE_PAGE_RE = re.compile(r"^/o/([^/]+)/([^/]+)$")


SERVICE_PART_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")


SERVICE_REF_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")


SERVICE_IP_WINDOW = 3600            # seconds: per-IP request budget window


SERVICE_REPO_WINDOW = 3600          # seconds: per-repository scan budget window


class ServiceError(Exception):
    """An HTTP error answered by `serve`: message plus optional headers."""

    def __init__(self, code, message, headers=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.headers = headers or {}


class WindowBudget:
    """In-memory sliding-window counter. Returns seconds to wait, or None when a slot was taken."""

    def __init__(self, limit, window):
        self.limit = int(limit)
        self.window = float(window)
        self.hits: dict[str, list[float]] = {}
        self.guard = threading.Lock()

    def check(self, key, now=None):
        if self.limit <= 0:
            return None
        now = time.monotonic() if now is None else now
        with self.guard:
            hits = [t for t in self.hits.get(key, []) if now - t < self.window]
            if len(hits) >= self.limit:
                self.hits[key] = hits
                return max(1, int(self.window - (now - hits[0])) + 1)
            hits.append(now)
            self.hits[key] = hits
            if len(self.hits) > 20000:   # bound memory on a busy public endpoint
                self.hits = {k: v for k, v in self.hits.items() if v and now - v[-1] < self.window}
            return None


def _service_slug(owner, repo):
    if not (SERVICE_PART_RE.fullmatch(owner or "") and SERVICE_PART_RE.fullmatch(repo or "")):
        raise ServiceError(400, "owner and repository must match [A-Za-z0-9_.-]{1,100}")
    return f"{owner}/{repo}"


class ServiceState:
    """Cache, budgets and scan execution for the serve command. Reports are immutable per resolved SHA."""

    def __init__(self, a):
        self.args = a
        self.cache = Path(getattr(a, "cache", None) or (
            Path(os.environ.get("XDG_CACHE_HOME") or (Path(os.environ.get("HOME") or "/tmp") / ".cache"))
            / "repobeagle" / "service"))
        self.cache.mkdir(parents=True, exist_ok=True)
        self.sign = bool(getattr(a, "sign", False))
        self.key = getattr(a, "key", None)
        self.root = Path(a.root).resolve() if getattr(a, "root", None) else None
        self.ip_budget = WindowBudget(getattr(a, "ip_budget", 30), SERVICE_IP_WINDOW)
        self.repo_budget = WindowBudget(getattr(a, "repo_budget", 20), SERVICE_REPO_WINDOW)
        self.concurrency = threading.BoundedSemaphore(max(1, int(getattr(a, "concurrency", 1) or 1)))
        self.locks: dict[tuple[str, str], threading.Lock] = {}
        self.locks_guard = threading.Lock()

    def _lock(self, slug, sha):
        with self.locks_guard:
            key = (slug, sha)
            lock = self.locks.get(key)
            if lock is None:
                self.locks[key] = lock = threading.Lock()
            return lock

    def _base(self, slug, sha):
        owner, repo = slug.split("/", 1)
        return self.cache / owner / repo / sha

    def resolve(self, owner, repo, ref):
        """(slug, scan target, resolved ref/cache key). Raises 400/404 with a client-safe reason."""
        slug = _service_slug(owner, repo)
        if owner == "local":
            if self.root is None:
                raise ServiceError(404, "local repositories are not enabled on this service (start with --root DIR)")
            path = (self.root / repo).resolve()
            if path != self.root and self.root not in path.parents:
                raise ServiceError(400, f"local/{repo} escapes --root")
            if not path.is_dir():
                raise ServiceError(404, f"local repository {repo!r} not found")
            return slug, str(path), tree_digest(path)[:40]
        url = f"https://github.com/{slug}.git"
        if ref and SERVICE_REF_RE.fullmatch(ref):
            if len(ref) == 40:
                return slug, url, ref.lower()
            return slug, url, self._resolve_short_sha(slug, ref)
        pattern = ref or "HEAD"
        try:
            r = subprocess.run(["git", "ls-remote", url, pattern], capture_output=True, text=True, timeout=60)
        except Exception as ex:
            raise ServiceError(502, f"cannot reach {slug}: {str(ex)[:120]}")
        if r.returncode != 0 or not r.stdout.strip():
            raise ServiceError(404, f"no ref {pattern!r} in {slug}")
        return slug, url, r.stdout.split()[0].lower()

    def _resolve_short_sha(self, slug, ref):
        """Expand a 7-39 character commit prefix: `git fetch` needs the full SHA."""
        api = os.environ.get("BEAGLE_GITHUB_API", "https://api.github.com").rstrip("/")
        token = os.environ.get("BEAGLE_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
        headers = {"User-Agent": "repobeagle", "Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(f"{api}/repos/{slug}/commits/{urllib.parse.quote(ref, safe='')}",
                                     headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                sha = str(json.loads(resp.read().decode()).get("sha") or "")
        except urllib.error.HTTPError as ex:
            raise ServiceError(404 if ex.code == 404 else 502, f"cannot resolve {ref!r} in {slug}")
        except Exception as ex:
            raise ServiceError(502, f"cannot resolve {ref!r} in {slug}: {str(ex)[:120]}")
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise ServiceError(404, f"cannot resolve {ref!r} in {slug}")
        return sha

    def _cache_read(self, slug, sha):
        base = self._base(slug, sha)
        try:
            data = (base / "report.json").read_bytes()
            d = json.loads(data)
        except (OSError, ValueError):
            return None
        return data if isinstance(d, dict) and d.get("verdict") in ("GREEN", "YELLOW", "RED") else None

    def _bundle(self, slug, sha):
        try:
            return (self._base(slug, sha) / "report.sigstore.json").read_bytes()
        except OSError:
            return None

    def _inject_provenance(self, data, slug, sha, local):
        d = json.loads(data)
        meta = d.get("meta") if isinstance(d.get("meta"), dict) else {}
        meta["scanned_repo"] = slug
        meta["scanned_sha"] = sha
        meta["service"] = {"name": "repobeagle", "version": VERSION,
                           "signed": bool(self.sign), "mode": "local" if local else "github"}
        d["meta"] = meta
        return json.dumps(d, indent=2).encode()

    def _sign(self, base, data, slug, sha):
        """Write the report and try to sign those exact bytes. Returns (bytes, bundle_written)."""
        report = base / "report.json"
        _atomic_write(report, data)
        if not self.sign:
            return data, False
        ok, detail = cosign_sign_blob(report, base / "report.sigstore.json", self.key)
        if not ok:
            print(f"serve: {slug}@{sha[:7]}: signing failed: {detail}", file=sys.stderr)
            d = json.loads(data)
            d["meta"]["service"]["signed"] = False
            data = json.dumps(d, indent=2).encode()
            _atomic_write(report, data)
            return data, False
        return data, True

    def report(self, slug, target, sha, local):
        """Cached bytes for (slug, sha), scanning once on a miss. Returns (bytes, 'hit'|'miss')."""
        with self._lock(slug, sha):
            cached = self._cache_read(slug, sha)
            base = self._base(slug, sha)
            if cached is not None:
                if self.sign and self._bundle(slug, sha) is None:
                    data = self._inject_provenance(cached, slug, sha, local)
                    data, _ = self._sign(base, data, slug, sha)
                    return data, "hit"
                return cached, "hit"
            retry = self.repo_budget.check(slug)
            if retry is not None:
                raise ServiceError(429, f"scan budget for {slug} exhausted",
                                   {"Retry-After": str(retry)})
            with self.concurrency:
                try:
                    data = scan_json_report(target, None if local else sha,
                                             profile=getattr(self.args, "profile", "balanced"),
                                             no_docker=getattr(self.args, "no_docker", False),
                                             no_osv=getattr(self.args, "no_osv", False),
                                             no_trust=getattr(self.args, "no_trust", False),
                                             privacy_only=getattr(self.args, "privacy_only", False),
                                             jobs=getattr(self.args, "jobs", 1),
                                             timeout=getattr(self.args, "timeout", 1800))
                except ScanFailure as ex:
                    raise ServiceError(504 if ex.timed_out else 503, str(ex))
                data = self._inject_provenance(data, slug, sha, local)
            base.mkdir(parents=True, exist_ok=True)
            data, signed = self._sign(base, data, slug, sha)
            if self.sign and not signed:
                print(f"serve: {slug}@{sha[:7]}: report cached unsigned (a later --sign request retries)",
                      file=sys.stderr)
            return data, "miss"

    def bundle(self, slug, target, sha, local):
        data, state = self.report(slug, target, sha, local)
        bundle = self._bundle(slug, sha)
        if bundle is None:
            raise ServiceError(404, f"{slug}@{sha[:7]} is served unsigned")
        return bundle, state


def _service_html(state, owner, repo):
    slug, target, sha = state.resolve(owner, repo, "")
    local = owner == "local"
    data, _ = state.report(slug, target, sha, local)
    try:
        d = json.loads(data)
    except ValueError:
        raise ServiceError(503, f"cached report for {slug}@{sha[:7]} is unreadable")
    page = html_report(d)
    link = f'<p><a href="/v1/scan/{slug}">report.json</a> · commit {sha[:12]}</p>'
    return page.replace("</body>", link + "</body>", 1).encode()


def _service_handler(state):
    """BaseHTTPRequestHandler subclass bound to one ServiceState; stdlib only, one thread per request."""
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = f"repobeagle/{VERSION}"

        def log_message(self, fmt, *args):   # noqa: A003 - stdlib signature
            print(f"serve: {self.address_string()} - {fmt % args}", file=sys.stderr)

        def _send(self, code, body=b"", ctype="application/json", headers=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-store")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code, obj, headers=None):
            self._send(code, json.dumps(obj, sort_keys=True).encode() + b"\n", "application/json", headers)

        def _budget(self, ip):
            retry = state.ip_budget.check(ip)
            if retry is not None:
                raise ServiceError(429, "too many requests from this address", {"Retry-After": str(retry)})

        def _report(self, owner, repo, ref):
            slug, target, sha = state.resolve(owner, repo, ref or "")
            data, hit = state.report(slug, target, sha, owner == "local")
            signed = state._bundle(slug, sha) is not None
            self._send(200, data, "application/json",
                       {"X-Repobeagle-Cache": hit, "X-Repobeagle-Commit": sha,
                        "X-Repobeagle-Signed": "true" if signed else "false",
                        "X-Repobeagle-Verify": f"/o/{slug}"})

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path
            ip = str(self.client_address[0])
            try:
                if path == "/healthz":
                    return self._json(200, {"ok": True, "service": "repobeagle", "version": VERSION,
                                            "signing": "on" if state.sign else "off"})
                if path == "/":
                    return self._json(200, {"service": "repobeagle", "version": VERSION,
                                            "endpoints": ["/v1/scan/<owner>/<repo>[/<ref>]",
                                                          "/v1/scan/<owner>/<repo>/<ref>/bundle",
                                                          "/o/<owner>/<repo>", "/healthz"]})
                self._budget(ip)
                un = urllib.parse.unquote
                m = SERVICE_BUNDLE_RE.match(path)
                if m:
                    owner, repo, ref = un(m.group(1)), un(m.group(2)), un(m.group(3) or "")
                    slug, target, sha = state.resolve(owner, repo, ref)
                    bundle, _ = state.bundle(slug, target, sha, owner == "local")
                    return self._send(200, bundle, "application/json")
                m = SERVICE_SCAN_RE.match(path)
                if m:
                    return self._report(un(m.group(1)), un(m.group(2)), un(m.group(3) or ""))
                m = SERVICE_PAGE_RE.match(path)
                if m:
                    return self._send(200, _service_html(state, un(m.group(1)), un(m.group(2))),
                                      "text/html; charset=utf-8")
                raise ServiceError(404, "no such route; see /")
            except ServiceError as ex:
                self._json(ex.code, {"error": ex.message}, ex.headers)
            except Exception as ex:
                print(f"serve: {type(ex).__name__}: {ex}", file=sys.stderr)
                self._json(500, {"error": f"internal error ({type(ex).__name__})"})
    return Handler


def cmd_serve(a):
    """Runs the hosted attestation API: immutable reports per (repo, sha), budgets, optional Sigstore signing."""
    try:
        state = ServiceState(a)
    except OSError as ex:
        print(f"serve: cannot use cache directory: {ex}", file=sys.stderr)
        return 1
    try:
        httpd = ThreadingHTTPServer((a.host, a.port), _service_handler(state))
    except OSError as ex:
        print(f"serve: cannot listen on {a.host}:{a.port}: {ex}", file=sys.stderr)
        return 1
    httpd.daemon_threads = True
    host, port = str(httpd.server_address[0]), int(httpd.server_address[1])
    shown = f"[{host}]" if ":" in host else host
    print(f"repobeagle serve {VERSION}: http://{shown}:{port} "
          f"(cache {state.cache}, signing {'on' if state.sign else 'off'})", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0