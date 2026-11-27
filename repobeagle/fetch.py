import argparse, base64, concurrent.futures, difflib, hashlib, hmac, json, os, platform, queue, re, shlex, shutil, signal, subprocess, sys, tempfile, threading, time, unicodedata, uuid, zipfile
import urllib.error, urllib.parse, urllib.request
from datetime import date, datetime, timezone
from fnmatch import fnmatchcase
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from pathlib import Path


# --- cross-module imports ---

from .core import ARCHIVE_EXT, BINARY_EXT, IMAGE, VERSION, zip_encrypted












# --- Safe archive extraction: scan archive targets without extracting on the host ---------------
ARCHIVE_MAX_ENTRIES = int(os.environ.get("BEAGLE_ARCHIVE_MAX_ENTRIES", "5000") or 5000)


ARCHIVE_MAX_ENTRY_BYTES = int(os.environ.get("BEAGLE_ARCHIVE_MAX_ENTRY_BYTES", str(64 * 1024 * 1024)))


ARCHIVE_MAX_TOTAL_BYTES = int(os.environ.get("BEAGLE_ARCHIVE_MAX_TOTAL_BYTES", str(512 * 1024 * 1024)))


TAR_EXTS = (".tar", ".tar.gz", ".tgz", ".tar.xz", ".tar.bz2")


SINGLE_COMPRESSION = {".gz": "gzip", ".xz": "xz", ".bz2": "bz2"}


def archive_kind(path):
    """'zip' | 'tar' | 'gzip' | 'xz' | 'bz2' | None (7z/zst/rar stay uninspectable)."""
    name = str(path).lower()
    if name.endswith(".zip"):
        return "zip"
    if name.endswith(TAR_EXTS):
        return "tar"
    for ext, kind in SINGLE_COMPRESSION.items():
        if name.endswith(ext):
            return kind
    return None


def _safe_member_path(name):
    """A `..`-free relative Path for an archive member name, or None (absolute/traversal/empty)."""
    raw = str(name).replace("\\", "/")
    if not raw or raw.startswith("/") or re.match(r"^[A-Za-z]:/", raw):
        return None
    p = Path(raw)
    if not p.parts or any(part == ".." for part in p.parts):
        return None
    return p


def _copy_bounded(reader, out_path, limit):
    """Stream `reader` into out_path without exceeding `limit`; (written, complete)."""
    written = 0
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wb") as out:
        while True:
            chunk = reader.read(256 * 1024)
            if not chunk:
                return written, True
            if written + len(chunk) > limit:
                out.write(chunk[: limit - written])
                return limit, False
            out.write(chunk)
            written += len(chunk)


def safe_extract(archive, dest):
    """Extract one level of a zip/tar (or single-file .gz/.xz/.bz2) into `dest` under strict limits.

    Rejects absolute and `..` members, never creates or follows symlinks (they are recorded), caps the
    entry count, per-entry size and total bytes, and stops cleanly when a cap is hit. Returns a summary;
    the archive itself is never extracted on the host beyond `dest`.
    """
    import bz2, gzip, lzma, stat, tarfile
    archive = Path(archive)
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    kind = archive_kind(archive)
    summary = {"archive": str(archive), "format": kind, "encrypted": False, "entries": 0,
               "extracted": 0, "bytes": 0, "truncated": False, "skipped": []}

    def skip(name, reason):
        if len(summary["skipped"]) < 25:
            summary["skipped"].append({"name": str(name), "reason": reason})

    def room():
        return summary["bytes"] < ARCHIVE_MAX_TOTAL_BYTES and summary["extracted"] < ARCHIVE_MAX_ENTRIES

    if kind == "zip":
        if zip_encrypted(archive):
            summary["encrypted"] = True
            return summary
        with zipfile.ZipFile(archive) as z:
            infos = z.infolist()
            summary["entries"] = len(infos)
            for info in infos:
                name = info.filename
                if not room():
                    summary["truncated"] = True
                    skip(name, "size/entry budget reached")
                    continue
                relp = _safe_member_path(name.rstrip("/")) if info.is_dir() else _safe_member_path(name)
                if relp is None:
                    skip(name, "absolute or '..' path")
                    continue
                mode = (info.external_attr >> 16)
                if stat.S_ISLNK(mode):
                    skip(name, "symlink (recorded, not created)")
                    continue
                if info.is_dir():
                    (dest / relp).mkdir(parents=True, exist_ok=True)
                    continue
                if info.file_size > ARCHIVE_MAX_ENTRY_BYTES:
                    skip(name, f"entry larger than {ARCHIVE_MAX_ENTRY_BYTES} bytes")
                    continue
                remaining = min(ARCHIVE_MAX_ENTRY_BYTES, ARCHIVE_MAX_TOTAL_BYTES - summary["bytes"])
                with z.open(info) as src:
                    written, complete = _copy_bounded(src, dest / relp, remaining)
                summary["bytes"] += written
                summary["extracted"] += 1
                if not complete:
                    summary["truncated"] = True
                    skip(name, "entry truncated at the byte budget")
                if written < info.file_size:
                    summary["truncated"] = True
    elif kind == "tar":
        with tarfile.open(archive, mode="r:*") as tf:
            members = tf.getmembers()
            summary["entries"] = len(members)
            for m in members:
                if not room():
                    summary["truncated"] = True
                    skip(m.name, "size/entry budget reached")
                    continue
                if m.isdir():
                    relp = _safe_member_path(m.name)
                    if relp:
                        (dest / relp).mkdir(parents=True, exist_ok=True)
                    continue
                if m.issym() or m.islnk():
                    skip(m.name, "symlink/hardlink (recorded, not created)")
                    continue
                if not m.isfile():
                    skip(m.name, "special file (not extracted)")
                    continue
                relp = _safe_member_path(m.name)
                if relp is None:
                    skip(m.name, "absolute or '..' path")
                    continue
                if m.size > ARCHIVE_MAX_ENTRY_BYTES:
                    skip(m.name, f"entry larger than {ARCHIVE_MAX_ENTRY_BYTES} bytes")
                    continue
                tsrc = tf.extractfile(m)
                if tsrc is None:
                    skip(m.name, "unreadable member")
                    continue
                remaining = min(ARCHIVE_MAX_ENTRY_BYTES, ARCHIVE_MAX_TOTAL_BYTES - summary["bytes"])
                with tsrc:
                    written, complete = _copy_bounded(tsrc, dest / relp, remaining)
                summary["bytes"] += written
                summary["extracted"] += 1
                if not complete:
                    summary["truncated"] = True
                    skip(m.name, "entry truncated at the byte budget")
    elif kind in SINGLE_COMPRESSION:
        out_name = re.sub(r"\.(gz|xz|bz2)$", "", archive.name)
        try:
            if kind == "gzip":
                csrc = gzip.open(archive, "rb")
            elif kind == "xz":
                csrc = lzma.open(archive, "rb")
            else:
                csrc = bz2.open(archive, "rb")
            with csrc:
                written, complete = _copy_bounded(csrc, dest / out_name, ARCHIVE_MAX_ENTRY_BYTES)
            summary.update({"entries": 1, "extracted": 1, "bytes": written})
            if not complete:
                summary["truncated"] = True
                skip(out_name, "entry truncated at the byte budget")
        except (OSError, EOFError) as ex:
            summary["truncated"] = True
            skip(archive.name, f"unreadable {kind} stream: {ex}")
    return summary




# ----------------------------------------------------------------------------
# Orchestration
# ----------------------------------------------------------------------------
CONTEXT_FILES = ("package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "pyproject.toml", "setup.cfg",
                 "requirements.txt", "poetry.lock", "Pipfile", "Cargo.toml", "Cargo.lock", "go.mod", "go.sum",
                 "composer.json", "pubspec.yaml", "CNAME", ".repobeagleignore")


def fetch_repo(target, work, ref=None, since=None):
    dest = Path(work) / "src"
    if os.path.isfile(target):
        for flag, value in (("--ref", ref), ("--since", since)):
            if value:
                raise SystemExit(f"{flag} {value!r} needs a git URL; an archive target is scanned as-is")
        if not str(target).lower().endswith(ARCHIVE_EXT):
            raise SystemExit(f"refusing target {target!r}: not a directory, archive or git URL")
        summary = safe_extract(target, dest)
        uninspectable = summary["format"] is None or summary["encrypted"]
        if uninspectable:                          # keep the existing findings for what cannot be expanded
            dest.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(target, dest / Path(target).name)
            summary["note"] = ("encrypted zip: contents not inspected" if summary["encrypted"]
                               else f"{summary['format'] or 'unsupported'} archive: contents not inspected")
        summary["archive"] = Path(target).name
        (Path(work) / "archive.json").write_text(json.dumps(summary), encoding="utf-8")
        return dest, f"archive ({summary['format'] or 'uninspectable'}, extracted under limits)", None
    if os.path.isdir(target):
        for flag, value in (("--ref", ref), ("--since", since)):
            if value:
                raise SystemExit(f"{flag} {value!r} needs a git URL; a local directory is copied as-is")
        shutil.copytree(target, dest, symlinks=True, ignore=shutil.ignore_patterns(".git"))
        return dest, "local path (copied)", None
    if not re.match(r"^(https?://|git@|ssh://|file://)", target):
        raise SystemExit(f"refusing target {target!r}: use an https/ssh/file git URL or an existing local directory")
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1", GIT_ALLOW_PROTOCOL="https:http:ssh:file",
               GIT_CONFIG_NOSYSTEM="1", GIT_ASKPASS="/bin/false", SSH_ASKPASS="/bin/false")
    G = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.symlinks=false", "-c", "core.fsmonitor=false",
         "-c", "protocol.file.allow=never", "-c", "credential.helper="]
    tmo = int(os.environ.get("BEAGLE_CLONE_TIMEOUT", "1800"))
    def git(args, cwd=None):
        try:
            r = subprocess.run(G + args, env=env, cwd=cwd, capture_output=True, text=True, timeout=tmo)
        except subprocess.TimeoutExpired:
            raise SystemExit("git timed out (set BEAGLE_CLONE_TIMEOUT to raise the limit)")
        if r.returncode != 0:
            raise SystemExit("git failed: " + r.stderr.strip()[-400:])
        return r.stdout
    def resolve(rev):
        git(["fetch", "--depth", "1", "--filter=blob:none", "--no-tags", "origin", rev], cwd=dest)
        return git(["rev-parse", "--verify", "FETCH_HEAD^{commit}"], cwd=dest).strip()
    # 1) blobless shallow clone: commits + trees only, no file contents yet
    git(["clone", "--depth", "1", "--filter=blob:none", "--no-checkout", "--no-recurse-submodules",
         "--single-branch", "--no-tags", "--", target, str(dest)])
    tip = git(["rev-parse", "HEAD"], cwd=dest).strip()
    if ref:
        # 2a) pin an exact branch/tag/commit: fetch just that object, then work from it
        tip = resolve(ref)
    base = resolve(since) if since else None
    # 3) list files from the tree (no blobs downloaded); archives/binaries are recorded but never fetched
    names = git(["ls-tree", "-r", "--name-only", tip], cwd=dest).splitlines()
    present = set(names)
    binary = lambda n: n.lower().endswith(ARCHIVE_EXT) or Path(n).suffix.lower() in BINARY_EXT
    skipped = [n for n in names if binary(n)]
    if base:
        # 4a) changed-files scope: materialize only what the diff touched, plus root manifests for context.
        # Renames are followed to their new path and counted; deletions have no content but are recorded.
        tokens = [t for t in git(["diff", "--name-status", "-z", "--diff-filter=AMRD", base, tip],
                                  cwd=dest).split("\x00") if t]
        changed, renamed, deleted = [], 0, 0
        i = 0
        while i < len(tokens):
            code = tokens[i]; i += 1
            if code[:1] in ("R", "C"):
                if i + 1 >= len(tokens):
                    break
                new = tokens[i + 1]; i += 2
                renamed += 1
                if new in present:
                    changed.append(new)
            elif code[:1] in ("A", "M", "T"):
                if i >= len(tokens):
                    break
                path = tokens[i]; i += 1
                if path in present:
                    changed.append(path)
            elif code[:1] == "D":
                deleted += 1; i += 1
        changed = list(dict.fromkeys(changed))
        keep = [p for p in dict.fromkeys(changed + [c for c in CONTEXT_FILES if c in present]) if not binary(p)]
        for i in range(0, len(keep), 100):
            git(["checkout", "-q", tip, "--"] + keep[i:i + 100], cwd=dest)
        (Path(work) / "scope.json").write_text(json.dumps(
            {"scope": "changed", "since": since, "changed_files": len(changed), "renamed_files": renamed,
             "deleted_files": deleted, "listed_files": len(names), "checked_out": len(keep)}))
        how = (f"git clone --depth 1 --filter=blob:none @ {ref or 'HEAD'} + diff since {since} "
               f"({len(changed)} changed files, {renamed} renamed, {deleted} deleted, "
               f"{len(skipped)} archives/binaries listed, not downloaded)")
        shutil.rmtree(dest / ".git", ignore_errors=True)
        (Path(work) / "skipped.json").write_text(json.dumps(skipped))
        return dest, how, tip
    # 4b) full scope: sparse checkout that excludes archives/binaries -> only text/source blobs are downloaded
    pats = ["/*"] + [f"!*{e}" for e in ARCHIVE_EXT] + [f"!*{e}" for e in BINARY_EXT]
    git(["sparse-checkout", "set", "--no-cone"] + pats, cwd=dest)
    git(["checkout", "-q", tip], cwd=dest)
    commit = git(["rev-parse", "HEAD"], cwd=dest).strip()
    shutil.rmtree(dest / ".git", ignore_errors=True)
    (Path(work) / "skipped.json").write_text(json.dumps(skipped))
    how = f"git clone --depth 1 --filter=blob:none{f' @ {ref}' if ref else ''} + sparse checkout ({len(skipped)} archives/binaries listed, not downloaded)"
    return dest, how, commit


def docker_ok():
    if not shutil.which("docker"): return False
    try:
        return subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, timeout=30).returncode == 0
    except Exception:
        return False


def run_in_docker(src, out, jobs=1):
    uid = os.getuid() if os.getuid() != 0 else 65534
    gid = os.getgid() if os.getuid() != 0 else 65534
    os.chmod(out, 0o777)
    cmd = ["docker", "run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp:rw,exec,size=1g",
           "--user", f"{uid}:{gid}", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "512",
           "--memory", os.environ.get("BEAGLE_MEMORY", "6g"), "-e", "HOME=/tmp", "-e", f"BEAGLE_JOBS={jobs}",
           "-v", f"{src}:/src:ro", "-v", f"{out}:/out:rw", IMAGE, "/src", "/out"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    try:
        return json.loads((Path(out) / "inner.json").read_text())
    except Exception:
        raise SystemExit("container scan failed: " + (r.stderr or r.stdout)[-600:])










# ----------------------------------------------------------------------------
# Verify a published badge report: repobeagle verify <github-repo>
# ----------------------------------------------------------------------------
VERIFY_IDENTITY = (r"^https://github\.com/javierbits/repobeagle/\.github/workflows/(scan|service|index)\.yml"
                   r"@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+)$")


VERIFY_ISSUER = "https://token.actions.githubusercontent.com"


GITHUB_REPO_RE = re.compile(r"^(?:https?://|git@|ssh://git@)github\.com[/:]([^/]+)/([^/#?]+?)(?:\.git)?/?$")


def _fetch(url, dest):
    req = urllib.request.Request(url, headers={"User-Agent": "repobeagle"})
    with urllib.request.urlopen(req, timeout=30) as resp, open(dest, "wb") as fh:
        fh.write(resp.read())


def _fetch_badge_file(slug, branch, name, dest):
    """Fetch a badge-branch file via the GitHub contents API: no CDN cache, so no
    stale/negative-cached copies right after a push. Falls back to raw on 403 (rate limit)."""
    api = f"https://api.github.com/repos/{slug}/contents/{name}?ref={branch}"
    req = urllib.request.Request(api, headers={"User-Agent": "repobeagle", "Accept": "application/vnd.github.raw"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp, open(dest, "wb") as fh:
            fh.write(resp.read())
        return
    except urllib.error.HTTPError as ex:
        if ex.code != 403:
            raise
    _fetch(f"https://raw.githubusercontent.com/{slug}/{branch}/{name}", dest)


COSIGN_FALLBACK = "3.1.3"   # pinned if the GitHub latest API is unreachable; any v3 works


def _cosign_arch():
    return {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64", "amd64": "amd64"}.get(platform.machine().lower())


def _ensure_cosign():
    """Returns a cosign executable path, installing it to ~/.local/bin on first use."""
    p = shutil.which("cosign")
    if p:
        return p
    dest = os.path.expanduser("~/.local/bin/cosign")
    if os.path.isfile(dest) and os.access(dest, os.X_OK):
        return dest
    arch = _cosign_arch()
    if not arch:
        return None
    v = os.environ.get("BEAGLE_COSIGN_VERSION", COSIGN_FALLBACK)
    url = f"https://github.com/sigstore/cosign/releases/download/v{v}/cosign-linux-{arch}"
    print(f"verify: installing cosign {v} ({arch}) to {dest}", file=sys.stderr)
    try:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        req = urllib.request.Request(url, headers={"User-Agent": "repobeagle"})
        with urllib.request.urlopen(req, timeout=600) as resp, open(dest + ".part", "wb") as fh:
            shutil.copyfileobj(resp, fh)
        os.chmod(dest + ".part", 0o755)
        os.replace(dest + ".part", dest)   # atomic: never leave a half-written binary on PATH
    except Exception as ex:
        print(f"verify: cosign install failed ({str(ex)[:140]})", file=sys.stderr)
        return None
    return dest


def rescan_image(meta):
    """(image, note) for a reproducible re-scan: the report's own image when recorded, else this install's."""
    img = str(meta.get("image_ref") or "")
    if img:
        return img, f"using the report's image {img}"
    return IMAGE, f"the report records no image_ref; using this install's image {IMAGE}, findings may differ"


def cosign_sign_blob(report_path, bundle_path, key=None, timeout=180):
    """Sign exactly the report file's bytes -> Sigstore bundle. (ok, detail); installs cosign on first use."""
    cosign = _ensure_cosign()
    if not cosign:
        return False, "cosign unavailable (install cosign or run ./install.sh)"
    cmd = [cosign, "sign-blob", "--yes", "--bundle", str(bundle_path), str(report_path)]
    if key:
        cmd.extend(["--key", key])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception as ex:
        return False, str(ex)[:160]
    if r.returncode != 0:
        return False, (r.stderr or r.stdout).strip()[-300:]
    return True, ""


def _local_image_digest(image):
    """sha256 digest of an image present locally, or None (never pulls)."""
    if not shutil.which("docker"):
        return None
    try:
        r = subprocess.run(["docker", "image", "inspect", image, "--format", "{{index .RepoDigests 0}}"],
                           capture_output=True, text=True, timeout=30)
    except Exception:
        return None
    out = (r.stdout or "").strip()
    return "sha256:" + out.split("sha256:", 1)[1] if r.returncode == 0 and "sha256:" in out else None

WEB_MAX_BYTES = 2_000_000

WEB_UA = f"repobeagle/{VERSION} (+https://github.com/javierbits/repobeagle)"

def _web_get(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": WEB_UA, "Accept": "text/html,text/css,*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read(WEB_MAX_BYTES + 1), resp.geturl()