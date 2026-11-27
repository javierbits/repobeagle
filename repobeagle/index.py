import argparse, base64, concurrent.futures, difflib, hashlib, hmac, json, os, platform, queue, re, shlex, shutil, signal, subprocess, sys, tempfile, threading, time, unicodedata, uuid, zipfile
import urllib.error, urllib.parse, urllib.request
from datetime import date, datetime, timezone
from fnmatch import fnmatchcase
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from pathlib import Path


# --- cross-module imports ---

from .core import VERSION, _atomic_write
from .fetch import GITHUB_REPO_RE, _ensure_cosign, cosign_sign_blob
from .report import html_report
from .scanners import ScanFailure, scan_json_report, tree_digest








# ---------------------------------------------------------------------------
# Public precomputed index: curated repositories -> signed results + static pages
# ---------------------------------------------------------------------------
INDEX_RESULTS = "results"


INDEX_PAGES = "repo"


INDEX_HTML = "index.html"


INDEX_ENTRY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _index_entries(args):
    lines = list(getattr(args, "entries", []) or [])
    repos = getattr(args, "repos", None)
    if repos:
        try:
            lines.extend(Path(repos).read_text(encoding="utf-8").splitlines())
        except OSError as ex:
            raise SystemExit(f"index: cannot read {repos}: {ex}")
    clean, seen = [], set()
    for line in lines:
        entry = line.split("#", 1)[0].strip()
        if entry and entry not in seen:
            seen.add(entry)
            clean.append(entry)
    return clean


def _index_resolve(entry):
    """(slug, scan target, ref, sha, local) or ValueError. Directories are local/<name>."""
    path = Path(entry)
    if path.is_dir():
        name = re.sub(r"[^A-Za-z0-9_.-]+", "-", path.name).strip("-") or "repo"
        return f"local/{name}", str(path.resolve()), None, tree_digest(path)[:40], True
    m = GITHUB_REPO_RE.match(entry)
    slug = f"{m.group(1)}/{m.group(2)}" if m else (entry if INDEX_ENTRY_RE.fullmatch(entry) else None)
    if not slug:
        raise ValueError("not an existing directory or owner/repo")
    url = f"https://github.com/{slug}.git"
    try:
        r = subprocess.run(["git", "ls-remote", url, "HEAD"], capture_output=True, text=True, timeout=60)
    except Exception as ex:
        raise ValueError(f"cannot resolve HEAD: {str(ex)[:120]}")
    if r.returncode != 0 or not r.stdout.strip():
        raise ValueError("cannot resolve HEAD")
    sha = r.stdout.split()[0].lower()
    return slug, url, sha, sha, False


def _index_paths(out, slug, sha):
    owner, name = slug.split("/", 1)
    results = Path(out) / INDEX_RESULTS / owner
    pages = Path(out) / INDEX_PAGES / owner
    return results / f"{name}@{sha}.json", results / f"{name}@{sha}.sigstore.json", pages / f"{name}.html"


def _index_report(raw, slug, sha, local):
    d = json.loads(raw)
    meta = d.get("meta") if isinstance(d.get("meta"), dict) else {}
    meta["scanned_repo"] = slug
    meta["scanned_sha"] = sha
    meta["index"] = {"name": "repobeagle", "version": VERSION, "mode": "local" if local else "github"}
    d["meta"] = meta
    return d, json.dumps(d, indent=2).encode()


def _index_scan(entry, out, args):
    """Resolve, scan, sign and cache one entry. Returns a result row; never raises."""
    try:
        slug, target, ref, sha, local = _index_resolve(entry)
    except ValueError as ex:
        return {"entry": entry, "status": "failed", "reason": str(ex)}
    report, bundle, _page = _index_paths(out, slug, sha)
    if report.is_file() and (not getattr(args, "sign", False) or bundle.is_file()):
        return {"entry": entry, "status": "skipped", "slug": slug, "sha": sha}
    try:
        raw = scan_json_report(target, ref,
                               profile=getattr(args, "profile", "balanced"),
                               no_docker=getattr(args, "no_docker", False),
                               no_osv=getattr(args, "no_osv", False),
                               no_trust=getattr(args, "no_trust", False),
                               privacy_only=getattr(args, "privacy_only", False),
                               jobs=1, timeout=getattr(args, "timeout", 1800))
        d, data = _index_report(raw, slug, sha, local)
    except ScanFailure as ex:
        return {"entry": entry, "status": "failed", "reason": str(ex)[:300]}
    report.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(report, data)
    if getattr(args, "sign", False):
        ok, detail = cosign_sign_blob(report, bundle, getattr(args, "key", None))
        if not ok:
            report.unlink(missing_ok=True)
            bundle.unlink(missing_ok=True)
            return {"entry": entry, "status": "failed", "slug": slug, "sha": sha,
                    "reason": f"signing failed: {detail}"}
    return {"entry": entry, "status": "scanned", "slug": slug, "sha": sha,
            "verdict": d.get("verdict"), "counts": d.get("counts")}


def _index_collect(out):
    """Latest valid report per slug from results/<owner>/<repo>@<sha>.json (all runs accumulate)."""
    latest: dict[str, dict[str, Any]] = {}
    for report in sorted((Path(out) / INDEX_RESULTS).glob("*/*@*.json")):
        if report.name.endswith(".sigstore.json"):
            continue
        try:
            d = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(d, dict) or d.get("verdict") not in ("GREEN", "YELLOW", "RED"):
            continue
        owner = report.parent.name
        name, _, sha = report.name[:-len(".json")].partition("@")
        if not name or not sha:
            continue
        meta: dict[str, Any] = d["meta"] if isinstance(d.get("meta"), dict) else {}
        key: tuple[str, str] = (str(meta.get("scanned_at") or ""), sha)
        slug = f"{owner}/{name}"
        previous = latest.get(slug)
        if previous is None or key > previous["key"]:
            latest[slug] = {"slug": slug, "name": name, "owner": owner, "sha": sha, "key": key,
                            "report": report, "data": d,
                            "bundle": report.with_name(report.name[:-len(".json")] + ".sigstore.json")}
    return latest


def _index_repo_page(out, entry):
    slug, sha, d = entry["slug"], entry["sha"], entry["data"]
    page = html_report(d)
    rel = f"../../{INDEX_RESULTS}/{entry['owner']}/{entry['name']}@{sha}.json"
    signed = entry["bundle"].is_file()
    links = f'<p><a href="{rel}">{"signed report.json" if signed else "report.json"}</a>'
    if signed:
        links += f' · <a href="{rel.replace(".json", ".sigstore.json")}">Sigstore bundle</a>'
    if not slug.startswith("local/"):
        links += f' · <a href="https://github.com/{slug}">repository</a>'
    links += f' · <a href="../../{INDEX_HTML}">all results</a></p>'
    return page.replace("</body>", links + "</body>", 1).encode()


def _index_page_entries(entries):
    signed = any(entry["bundle"].is_file() for entry in entries.values())
    rows = []
    for slug in sorted(entries):
        entry = entries[slug]
        counts = entry["data"].get("counts") or {}
        verdict = str(entry["data"].get("verdict"))
        rows.append(
            f'<tr><td><a href="{INDEX_PAGES}/{slug}.html">{slug}</a></td>'
            f'<td class="{verdict}">{verdict}</td>'
            f'<td>{counts.get("critical", 0)}</td><td>{counts.get("high", 0)}</td>'
            f'<td>{counts.get("medium", 0)}</td><td>{counts.get("low", 0)}</td>'
            f'<td><code>{entry["sha"][:12]}</code></td></tr>')
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RepoBeagle index: popular repository verdicts</title>
<style>
:root {{ color-scheme: light dark; font-family: system-ui, sans-serif; }}
body {{ max-width: 64rem; margin: 2rem auto; padding: 0 1rem; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ padding: .35rem .5rem; border-bottom: 1px solid #8884; text-align: left; }}
td.GREEN {{ color: #1a7f37; font-weight: 600; }}
td.YELLOW {{ color: #9a6700; font-weight: 600; }}
td.RED {{ color: #cf222e; font-weight: 600; }}
input {{ width: 100%; padding: .5rem; margin: 1rem 0; font: inherit; }}
</style></head><body>
<h1>RepoBeagle index</h1>
<p>Static verdicts for a curated set of repositories.
{"Every linked report is Sigstore-signed by the official RepoBeagle index workflow; verify it with <code>repobeagle verify</code>." if signed else "This index was built without signing (local build)."}</p>
<label for="q">Filter by repository or verdict</label>
<input id="q" placeholder="e.g. flask, RED, owner/" autocomplete="off">
<table><thead><tr><th>repository</th><th>verdict</th><th>critical</th><th>high</th>
<th>medium</th><th>low</th><th>scanned</th></tr></thead>
<tbody>
{chr(10).join(rows)}
</tbody></table>
<p><small>Generated by RepoBeagle {VERSION}. Static analysis only; no repository code is executed.</small></p>
<script>
document.getElementById('q').addEventListener('input', function () {{
  const q = this.value.toLowerCase();
  document.querySelectorAll('tbody tr').forEach(function (tr) {{
    tr.style.display = tr.textContent.toLowerCase().includes(q) ? '' : 'none';
  }});
}});
</script>
</body></html>
"""


def cmd_index(a):
    """Builds the signed public index from a curated list: never executes repository code."""
    out = Path(a.out)
    try:
        out.mkdir(parents=True, exist_ok=True)
    except OSError as ex:
        print(f"index: cannot create {out}: {ex}", file=sys.stderr)
        return 1
    entries = _index_entries(a)
    if not entries:
        print("index: no entries (give owner/repo, directories, or --repos FILE)", file=sys.stderr)
        return 1
    if a.sign and not _ensure_cosign():
        print("index: --sign needs cosign; install it or run ./install.sh", file=sys.stderr)
        return 1
    limit = entries[:int(a.cap)] if int(a.cap) > 0 else entries
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, int(a.jobs))) as pool:
        futures = {pool.submit(_index_scan, entry, out, a): entry for entry in limit}
        for future in concurrent.futures.as_completed(futures):
            try:
                row = future.result()
            except Exception as ex:
                row = {"entry": futures[future], "status": "failed", "reason": f"{type(ex).__name__}: {ex}"}
            results.append(row)
            label = row.get("slug") or row["entry"]
            print(f"index: {row['status']} {label}" + (f" ({row['reason']})" if row.get("reason") else ""),
                  file=sys.stderr)
    latest = _index_collect(out)
    for entry in latest.values():
        page = Path(out) / INDEX_PAGES / entry["owner"] / f"{entry['name']}.html"
        page.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(page, _index_repo_page(out, entry))
    _atomic_write(out / INDEX_HTML, _index_page_entries(latest).encode())
    scanned = sum(1 for r in results if r["status"] == "scanned")
    skipped = sum(1 for r in results if r["status"] == "skipped")
    failed = sum(1 for r in results if r["status"] == "failed")
    print(f"index: {scanned} scanned, {skipped} skipped (unchanged SHA), {failed} failed; "
          f"{len(latest)} published page(s) in {out}")
    if a.json:
        Path(a.json).write_text(json.dumps({"scanned": scanned, "skipped": skipped, "failed": failed,
                                            "results": sorted(results, key=lambda r: r.get("entry", "")),
                                            "published": sorted(latest)}, indent=2))
        print(f"[repobeagle] JSON written to {a.json}", file=sys.stderr)
    return 0 if latest else 1