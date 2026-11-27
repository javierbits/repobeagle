import argparse, base64, concurrent.futures, difflib, hashlib, hmac, json, os, platform, queue, re, shlex, shutil, signal, subprocess, sys, tempfile, threading, time, unicodedata, uuid, zipfile
import urllib.error, urllib.parse, urllib.request
from datetime import date, datetime, timezone
from fnmatch import fnmatchcase
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from pathlib import Path


# --- cross-module imports ---

from .app import cmd_app
from .core import ARCHIVE_EXT, CONFIG_FILE, ConfigError, IMAGE, PERSONAS, PROFILES, RELEASE, SEV_ORDER, SUPPRESS_FILE, ScanDeadline, VERSION, _deadline_left, _explain_rule, _rule_of, _scan_alarm, _trend_epoch, apply_persona, apply_suppressions, cmd_rules, entry_command, explain_report, finding, gate_findings, load_repo_config, load_rule_packs, load_suppressions, parse_suppression, print_personas, privacy_mode_consistent, privacy_profile, privacy_summary, privacy_summary_consistent, redact_pii, remediation_for, report_fingerprint, rescan_difference, run_custom_checks, run_rule_packs, suppression_meta, suppression_notes, toolchain_drift, toolchain_pins, verdict, verdict_consistent
from .fetch import GITHUB_REPO_RE, VERIFY_IDENTITY, VERIFY_ISSUER, WEB_MAX_BYTES, WEB_UA, _ensure_cosign, _fetch_badge_file, _local_image_digest, _web_get, docker_ok, fetch_repo, rescan_image, run_in_docker
from .index import cmd_index
from .release import cmd_release
from .report import ACTIONS, _WORKDIRS, _install_cleanup, banner, collapse, color_enabled, dedupe, html_report, markdown_report, render_capabilities, render_report, sarif_report, sbom_report
from .rules.agent import run_agent_checks, trust_signals
from .rules.privacy import RULESET
from .scanners import REGISTRY_TTL, _cache_root, _registry_cache_path, _registry_fetch, _run, ai_review, analysis_cache_key, cache_load, cache_store, inner, osv_db_info, osv_db_warning, run_trace, scan_capabilities, scan_coverage, scan_osv, scan_release_assets, tool_version, verify_deps
from .service import cmd_serve










# --- Feedback loop: prefilled, re-redacted GitHub issue ------------------------------
FEEDBACK_REPO = "javierbits/repobeagle"


FEEDBACK_URL_MAX = 7500   # GitHub rejects very long issue URLs; keep the body inside this budget


FEEDBACK_SNIPPET_CHARS = 600


FEEDBACK_TITLE_CHARS = 160


def _finding_rule(f):
    return str(f.get("rule") or str(f.get("title") or "").split(":", 1)[0]).strip()


def _finding_ref(f):
    return f"{f.get('file')}:{f.get('line')}"


def select_finding(report, rule=None, file=None):
    """(finding, error) for `--rule`/`--file`: exactly one finding or a message naming the candidates."""
    findings = [f for f in report.get("findings") or [] if isinstance(f, dict) and not f.get("suppressed")]
    if rule:
        findings = [f for f in findings if _finding_rule(f) == rule]
    if file:
        findings = [f for f in findings if _finding_ref(f) == file or str(f.get("file")) == file]
    if not findings:
        rules_found = sorted({_finding_rule(f) for f in (report.get("findings") or []) if isinstance(f, dict)})[:40]
        what = (f"rule {rule!r}" + (f" at {file!r}" if file else "")) if rule else "the selection"
        return None, f"no finding for {what}; rules in this report: {', '.join(rules_found) or '(none)'}"
    if len(findings) > 1:
        refs = ", ".join(sorted({_finding_ref(f) for f in findings})[:20])
        what = f"rule {rule!r}" if rule else "the selection"
        return None, f"{len(findings)} findings for {what}; pick one with --file ({refs})"
    return findings[0], ""


def _feedback_title(finding, kind):
    rule = _finding_rule(finding)
    label = "false positive" if kind == "false-positive" else "miss"
    short = redact_pii(str(finding.get("title") or "")).strip()
    if short.startswith(rule + ":"):
        short = short[len(rule) + 1:].strip()
    return f"[{label}] {rule}" + (f": {short}" if short else "")[:FEEDBACK_TITLE_CHARS]


def _feedback_body(report, finding, kind, snippet, attach, cut):
    meta = report.get("meta") or {}
    rule = _finding_rule(finding)
    kind_label = "false positive" if kind == "false-positive" else "missed finding"
    title = redact_pii(str(finding.get("title") or ""))[:FEEDBACK_TITLE_CHARS]
    lines = [f"**Kind**: {kind_label}",
             f"**Rule**: `{rule}`",
             f"**Location**: `{_finding_ref(finding)}`",
             f"**Severity**: {finding.get('severity')}"]
    if title:
        lines += ["", "**Finding title** (re-redacted):", "", "> " + title.replace("\n", " ")]
    meaning = redact_pii(str(finding.get("meaning") or ""))[:400]
    if meaning:
        lines += ["", "**What the rule says**: " + meaning.replace("\n", " ")]
    lines += ["", "**Snippet** (re-redacted):", "", "```text", snippet or "(no snippet)", "```"]
    if cut:
        lines += ["_Snippet truncated to keep the issue URL under GitHub's limit._"]
    scan = (f"repobeagle {VERSION} \u00b7 profile {meta.get('profile')} \u00b7 ruleset `{meta.get('ruleset')}`"
            f" \u00b7 target `{meta.get('target')}`")
    if meta.get("commit"):
        scan += f" \u00b7 commit `{meta.get('commit')}`"
    if meta.get("ref"):
        scan += f" \u00b7 ref `{meta.get('ref')}`"
    lines += ["", "**Scan**: " + scan + f" \u00b7 image `{IMAGE}`",
              f"**PII**: report scan redacted snippets: {'yes' if meta.get('pii_redacted', True) else 'no'}"
              " \u2014 re-redacted here by `repobeagle feedback` regardless.", "",
              "**Why this is wrong**:", ""]
    if attach:
        doc = json.dumps(report, indent=1, sort_keys=True)
        lines += ["<details><summary>Full report (attached with --attach)</summary>", "", "```json", doc, "```", "", "</details>"]
    return "\n".join(lines)


def feedback_url(report, finding, kind, repo=FEEDBACK_REPO, attach=False):
    """(url, notes): prefilled new-issue URL whose body is always re-redacted and fits GitHub's URL budget."""
    raw_snippet = redact_pii(str(finding.get("snippet") or ""))
    snippet = raw_snippet[:FEEDBACK_SNIPPET_CHARS]
    cut = len(raw_snippet) > len(snippet)
    title = _feedback_title(finding, kind)
    base = f"https://github.com/{repo}/issues/new"
    notes = ["snippet truncated to keep the issue URL under GitHub's limit"] if cut else []
    def build(snip, with_attach, truncated):
        body = _feedback_body(report, finding, kind, snip, with_attach, truncated)
        return f"{base}?{urllib.parse.urlencode({'title': title[:200], 'body': body, 'labels': 'bug'})}"
    url = build(snippet, attach, cut)
    if len(url) > FEEDBACK_URL_MAX and attach:
        url = build(snippet, False, cut)
        notes.append("full report dropped from the issue body (too long); the URL stays under GitHub's limit")
    while len(url) > FEEDBACK_URL_MAX and len(snippet) > 40:
        snippet = snippet[:max(40, len(snippet) * 2 // 3)]
        cut = True
        url = build(snippet, False, cut)
    if len(url) > FEEDBACK_URL_MAX:
        overflow = len(url) - FEEDBACK_URL_MAX
        body = _feedback_body(report, finding, kind, snippet, False, cut)
        body = body[:max(200, len(body) - overflow - 40)].rstrip() + "\n\n\u2026 (truncated to fit the issue URL)"
        url = f"{base}?{urllib.parse.urlencode({'title': title[:200], 'body': body, 'labels': 'bug'})}"
        notes.append("body truncated to fit the issue URL")
    return url, notes


def cmd_feedback(a):
    """Opens (or prints) a prefilled GitHub issue for one finding. Reads a stored report; never scans, never needs the network."""
    try:
        d = json.loads(Path(a.report).read_text())
    except OSError as ex:
        print(f"feedback: cannot read {a.report}: {ex}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as ex:
        print(f"feedback: {a.report} is not valid JSON: {ex}", file=sys.stderr)
        return 1
    if not isinstance(d, dict):
        print("feedback: report root is not an object", file=sys.stderr)
        return 1
    finding, err = select_finding(d, a.rule, a.file)
    if err:
        print(f"feedback: {err}", file=sys.stderr)
        return 1
    kind = "false-positive" if a.false_positive else "miss"
    url, notes = feedback_url(d, finding, kind, repo=a.repo, attach=a.attach)
    print(url)
    for note in notes:
        print(f"feedback: {note}", file=sys.stderr)
    if not a.no_open:
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception:
            pass
        print("feedback: opened the prefilled issue in your browser (--no-open only prints the URL)", file=sys.stderr)
    return 0


def cmd_explain(a):
    """Prints how a stored report's verdict follows from the profile thresholds, and simulates accepting rules. No scan, no network."""
    if getattr(a, "write", False) and not (getattr(a, "accept", None) or getattr(a, "target", None)):
        print("explain: --write needs --accept or --target (nothing selected)", file=sys.stderr)
        return 1
    try:
        d = json.loads(Path(a.report).read_text())
    except OSError as ex:
        print(f"explain: cannot read {a.report}: {ex}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as ex:
        print(f"explain: {a.report} is not valid JSON: {ex}", file=sys.stderr)
        return 1
    if not isinstance(d, dict):
        print("explain: report root is not an object", file=sys.stderr)
        return 1
    return explain_report(d, accept=getattr(a, "accept", None) or (), target=getattr(a, "target", None),
                          write=getattr(a, "write", False), ignore_file=getattr(a, "ignore_file", None),
                          reason=getattr(a, "reason", ""))


# --- repobeagle fix: mechanical rewrites only (unpinned actions, write-all) -----------
FIX_RULES = ("gha-unpinned-action", "gha-write-permissions")


GH_USES_RE = re.compile(r"^(\s*-?\s*uses:\s*)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([^\s#]+)(.*)$")


GH_WRITE_ALL_RE = re.compile(r"^(\s*)permissions:\s*write-all\s*(#.*)?$")


def load_action_pins(path):
    """{owner/repo@ref: sha} overrides for `fix` (airgapped runs and tests); invalid entries are ignored."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as ex:
        raise SystemExit(f"fix: cannot read pins {path}: {ex}")
    return {str(k): str(v) for k, v in (data or {}).items() if re.fullmatch(r"[0-9a-f]{40}", str(v))}


def resolve_action_pin(slug, ref, pins=None, timeout=15):
    """40-character commit SHA for owner/repo@ref: explicit pins first, then the GitHub API (network)."""
    if re.fullmatch(r"[0-9a-f]{40}", ref):
        return ref
    key = f"{slug}@{ref}"
    if pins and key in pins:
        return pins[key]
    try:
        req = urllib.request.Request(f"https://api.github.com/repos/{slug}/commits/{ref}",
                                     headers={"User-Agent": WEB_UA, "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            sha = json.loads(resp.read().decode()).get("sha", "")
    except Exception:
        return None
    return sha if re.fullmatch(r"[0-9a-f]{40}", sha) else None


def cmd_fix(a):
    """Rewrites the mechanical findings in a local checkout (unpinned actions, write-all permissions). Never executes repo code."""
    target = a.target
    if not os.path.isdir(target):
        print(f"fix: {target} is not a directory; fix edits a checkout (clone the URL first)", file=sys.stderr)
        return 1
    pins = load_action_pins(a.pins) if a.pins else {}
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        report_path = Path(fh.name)
    try:
        r = _mcp_exec(["scan", target, "--json", str(report_path), "--no-color", "--no-docker",
                       "--no-osv", "--no-trust"])
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except ValueError:
            print("fix: scan produced no report: " + ((r.stderr or r.stdout or "")[-600:]), file=sys.stderr)
            return 1
    finally:
        report_path.unlink(missing_ok=True)
    findings = [f for f in report.get("findings") or []
                if isinstance(f, dict) and not f.get("suppressed")
                and _rule_of(f) in FIX_RULES]
    by_file: dict[str, list[dict]] = {}
    for f in findings:
        by_file.setdefault(str(f.get("file") or ""), []).append(f)
    fixed, skipped, changed_files, diffs = [], [], [], []
    for relpath, fs in sorted(by_file.items()):
        p = Path(target) / relpath
        try:
            original = p.read_text(encoding="utf-8")
        except OSError as ex:
            skipped.append({"file": relpath, "rule": "?", "reason": f"unreadable: {ex}"})
            continue
        lines = original.splitlines(keepends=True)
        changed = False
        for f in fs:
            rule = _rule_of(f)
            line_no = int(f.get("line") or 0)
            if line_no < 1 or line_no > len(lines):
                skipped.append({"file": relpath, "rule": rule, "reason": "line out of range"})
                continue
            line = lines[line_no - 1]
            if rule == "gha-unpinned-action":
                m = GH_USES_RE.match(line.rstrip("\n"))
                if not m:
                    skipped.append({"file": relpath, "rule": rule, "reason": "no owner/repo@ref on the line"})
                    continue
                slug, ref = m.group(2), m.group(3)
                sha = pins.get(f"{slug}@{ref}") if a.no_network else resolve_action_pin(slug, ref, pins)
                if not sha:
                    skipped.append({"file": relpath, "rule": rule, "reason": f"cannot resolve {slug}@{ref}"})
                    continue
                new = f"{m.group(1)}{slug}@{sha}{m.group(4)}" + ("\n" if line.endswith("\n") else "")
                if new != line:
                    fixed.append({"file": relpath, "line": line_no, "rule": rule,
                                  "action": f"{slug}@{ref} -> @{sha}"})
                    lines[line_no - 1] = new
                    changed = True
                continue
            # write-all is the broadest setting and therefore mechanical; scope-level `: write`
            # stays untouched because the job may genuinely need it.
            m = GH_WRITE_ALL_RE.match(line.rstrip("\n"))
            if m:
                indent = m.group(1)
                lines[line_no - 1] = f"{indent}permissions:\n{indent}  contents: read" + ("\n" if line.endswith("\n") else "")
                fixed.append({"file": relpath, "line": line_no, "rule": rule,
                              "action": "permissions: write-all -> contents: read"})
                changed = True
            else:
                skipped.append({"file": relpath, "rule": rule,
                                "reason": "scope-level write; the job may need it, review by hand"})
        if changed:
            updated = "".join(lines)
            diff = "".join(difflib.unified_diff(original.splitlines(keepends=True), updated.splitlines(keepends=True),
                                               fromfile=f"a/{relpath}", tofile=f"b/{relpath}"))
            diffs.append(diff)
            changed_files.append(relpath)
            if not a.dry_run:
                p.write_text(updated, encoding="utf-8")
    for diff in diffs:
        sys.stdout.write(diff)
    out = {"dry_run": bool(a.dry_run), "changed_files": changed_files, "fixed": fixed, "skipped": skipped}
    if a.json:
        Path(a.json).write_text(json.dumps(out, indent=2))
        print(f"[repobeagle] fix JSON written to {a.json}", file=sys.stderr)
    verb = "would fix" if a.dry_run else "fixed"
    print(f"{verb} {len(fixed)} issue(s) in {len(changed_files)} file(s)"
          + (f"; skipped {len(skipped)} (see --json)" if skipped else ""))
    return 0


def cmd_diff(a):
    """Compares two stored reports and fails when the change added findings at/above --min-severity. Never scans."""
    try:
        old = json.loads(Path(a.old).read_text())
        new = json.loads(Path(a.new).read_text())
    except OSError as ex:
        print(f"diff: cannot read report: {ex}", file=sys.stderr); return 1
    except json.JSONDecodeError as ex:
        print(f"diff: a report is not valid JSON: {ex}", file=sys.stderr); return 1
    if not isinstance(old, dict) or not isinstance(new, dict):
        print("diff: report roots must be JSON objects", file=sys.stderr); return 1
    mo, mn = old.get("meta") or {}, new.get("meta") or {}
    if mo.get("profile") and mn.get("profile") and mo["profile"] != mn["profile"]:
        print(f"diff: reports were produced with different profiles ({mo['profile']} vs {mn['profile']}); "
              "findings may differ because of the thresholds, not the code", file=sys.stderr)
    if mo.get("ruleset") and mn.get("ruleset") and mo["ruleset"] != mn["ruleset"]:
        print(f"diff: reports were produced by different rulesets ({mo['ruleset']} vs {mn['ruleset']}); "
              "added/removed may include rule changes", file=sys.stderr)
    gated, added, removed, old_n, new_n = gate_findings(old, new, a.min_severity)
    C = (lambda code, s: f"\033[{code}m{s}\033[0m") if (color_enabled() and not a.no_color) else (lambda code, s: s)
    vc = {"RED": "1;41;97", "YELLOW": "1;43;30", "GREEN": "1;42;30"}
    show = lambda v: C(vc[v], v) if v in vc else (v or "?")
    print(f"baseline: {show(old.get('verdict'))}  profile {mo.get('profile', '?')}  findings {old_n}  ({a.old})")
    print(f"current:  {show(new.get('verdict'))}  profile {mn.get('profile', '?')}  findings {new_n}  ({a.new})")
    print(f"added {len(added)}, removed {len(removed)} (matching on rule + file; line moves are not changes)")
    sc = {"critical": "1;91", "high": "91", "medium": "93", "low": "96", "info": "37"}
    for label, items in (("added", added), ("removed", removed)):
        for f in items[:50]:
            loc = f"{f['file']}:{f['line']}" if f.get("line") else f"{f.get('file')}"
            print(f"  {label:<7} {C(sc[f['severity']], f['severity'].upper().ljust(8))} {f['title']}  [{loc}]")
        if len(items) > 50:
            print(f"  {label:<7} ... {len(items) - 50} more")
    if a.json:
        Path(a.json).write_text(json.dumps({
            "old": {"verdict": old.get("verdict"), "profile": mo.get("profile"), "ruleset": mo.get("ruleset"), "findings": old_n},
            "new": {"verdict": new.get("verdict"), "profile": mn.get("profile"), "ruleset": mn.get("ruleset"), "findings": new_n},
            "added": added, "removed": removed,
            "gate": {"min_severity": a.min_severity, "added": len(gated)}}, indent=2))
        print(f"[repobeagle] diff JSON written to {a.json}", file=sys.stderr)
    if gated:
        print(C("1;91", f"gate: {len(gated)} new finding(s) at/above {a.min_severity}"))
        return 1
    print(f"gate: no new findings at/above {a.min_severity}")
    return 0


def cmd_export(a):
    """Converts a stored report to SARIF, Markdown or normalized JSON. Never scans, never touches the network."""
    try:
        d = json.loads(Path(a.report).read_text())
    except OSError as ex:
        print(f"export: cannot read {a.report}: {ex}", file=sys.stderr); return 1
    except json.JSONDecodeError as ex:
        print(f"export: {a.report} is not valid JSON: {ex}", file=sys.stderr); return 1
    if not isinstance(d, dict):
        print("export: report root must be a JSON object", file=sys.stderr); return 1
    if a.format == "sarif":
        text = json.dumps(sarif_report(d), indent=2)
    elif a.format == "markdown":
        text = markdown_report(d)
    elif a.format == "html":
        text = html_report(d)
    else:
        text = json.dumps(d, indent=2)
    if not text.endswith("\n"):
        text += "\n"
    if a.out:
        Path(a.out).write_text(text)
        print(f"[repobeagle] {a.format} written to {a.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


# ---------------------------------------------------------------------------
# Trend: verdict/rule history from the per-SHA reports on a badge branch
# ---------------------------------------------------------------------------
TREND_COMMIT_RE = re.compile(r"repobeagle:\s+(?:GREEN|YELLOW|RED)\s+for\s+([0-9a-f]{40})\b")


TREND_VERDICTS = ("GREEN", "YELLOW", "RED")


TREND_LETTER = {"GREEN": "G", "YELLOW": "Y", "RED": "R"}


def _trend_headers(accept="application/vnd.github+json"):
    token = os.environ.get("BEAGLE_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    headers = {"User-Agent": "repobeagle", "Accept": accept}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _trend_get(url, accept="application/vnd.github+json", timeout=30):
    req = urllib.request.Request(url, headers=_trend_headers(accept))
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _trend_iso(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _trend_count(value):
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _trend_entry(raw, label, fallback_epoch=None):
    """One report file -> (entry, None), or (None, reason). Hostile input never raises."""
    try:
        d = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None, "not valid JSON"
    if not isinstance(d, dict):
        return None, "JSON root is not an object"
    verdict = d.get("verdict")
    if verdict not in TREND_VERDICTS:
        return None, "no GREEN/YELLOW/RED verdict"
    meta: dict[str, Any] = d["meta"] if isinstance(d.get("meta"), dict) else {}
    counts: dict[str, Any] = d["counts"] if isinstance(d.get("counts"), dict) else {}
    epoch = _trend_epoch(meta.get("scanned_at")) if meta.get("scanned_at") else None
    if epoch is None:
        epoch = fallback_epoch
    if epoch is None:
        return None, "no timestamp (meta.scanned_at or file time)"
    try:
        at = _trend_iso(epoch)
    except (OverflowError, OSError, ValueError):
        return None, "timestamp out of range"
    rules = sorted({_rule_of(f) for f in (d.get("findings") or [])
                    if isinstance(f, dict) and not f.get("suppressed") and f.get("severity") in SEV_ORDER})
    return {
        "at": at, "epoch": epoch, "file": label,
        "sha": str(meta.get("scanned_sha") or meta.get("commit") or ""),
        "verdict": verdict,
        "counts": {k: _trend_count(counts.get(k)) for k in ("critical", "high", "medium", "low")},
        "rules": rules,
        "ruleset": str(meta.get("ruleset") or ""), "version": str(d.get("version") or ""),
    }, None


def _trend_published(slug, branch, limit):
    """Read the report-<sha>.json files a badge branch's own commits name, oldest first.

    Ordering and timestamps come from the badge-branch commits (the workflow message names
    the full scanned SHA); a SHA scanned twice keeps its newest report.
    """
    api = os.environ.get("BEAGLE_GITHUB_API", "https://api.github.com").rstrip("/")
    ref = urllib.parse.quote(branch, safe="")
    picks: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    page = 1
    while len(picks) < limit and page <= 20:
        batch = json.loads(_trend_get(f"{api}/repos/{slug}/commits?sha={ref}&per_page=100&page={page}") or b"[]")
        if not isinstance(batch, list) or not batch:
            break
        for c in batch:
            if len(picks) >= limit:
                break
            commit = c.get("commit") if isinstance(c, dict) else None
            msg = ((commit or {}).get("message") or "").splitlines()[0] if isinstance(commit, dict) else ""
            m = TREND_COMMIT_RE.search(msg)
            if not m:
                continue
            name = f"report-{m.group(1)[:7]}.json"
            if name in seen:
                continue
            seen.add(name)
            at = (((commit or {}).get("committer") or {}).get("date") or "") if isinstance(commit, dict) else ""
            picks.append((at, m.group(1), name))
        if len(batch) < 100:
            break
        page += 1
    entries, skipped = [], []
    for at, sha, name in reversed(picks):
        try:
            if os.environ.get("BEAGLE_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN"):
                raw = _trend_get(f"{api}/repos/{slug}/contents/{name}?ref={ref}", accept="application/vnd.github.raw")
            else:
                try:
                    raw = _trend_get(f"https://raw.githubusercontent.com/{slug}/{ref}/{name}")
                except urllib.error.HTTPError as ex:
                    if ex.code != 404:
                        raise
                    raw = _trend_get(f"{api}/repos/{slug}/contents/{name}?ref={ref}", accept="application/vnd.github.raw")
        except Exception as ex:
            skipped.append({"file": name, "reason": f"fetch failed: {str(ex)[:140]}"})
            continue
        entry, reason = _trend_entry(raw, name, _trend_epoch(at))
        if entry is None:
            skipped.append({"file": name, "reason": reason})
            continue
        entry["sha"] = entry["sha"] or sha
        entries.append(entry)
    return entries, skipped


def _trend_local(files):
    """Read local report files; ordering falls back to file mtime when meta.scanned_at is absent."""
    entries, skipped = [], []
    for p in files:
        try:
            raw = p.read_bytes()
            fallback = p.stat().st_mtime
        except OSError as ex:
            skipped.append({"file": str(p), "reason": f"unreadable: {ex}"})
            continue
        entry, reason = _trend_entry(raw, str(p), fallback)
        if entry is None:
            skipped.append({"file": str(p), "reason": reason})
            continue
        entries.append(entry)
    return entries, skipped


def trend_series(entries, skipped):
    """Ordered verdict/rule series plus first RED, per-rule regressions and the current streak.

    Reports from another ruleset/version than the newest report are skipped: their rule ids
    are not comparable, and a ruleset change legitimately resets the series.
    """
    entries.sort(key=lambda e: (e["epoch"], e["sha"], e["file"]))
    if not entries:
        return {"reports": [], "skipped": skipped, "series": [], "first_red": None,
                "current": None, "regressions": []}
    ref = entries[-1]
    kept = []
    for e in entries:
        changed = [k for k in ("ruleset", "version")
                   if ref[k] and e[k] and e[k] != ref[k]]
        if changed:
            skipped.append({"file": e["file"], "reason": f"different {' and '.join(changed)} "
                                                       f"({e['ruleset'] or e['version']} vs {ref['ruleset'] or ref['version']})"})
            continue
        kept.append(e)
    kept.sort(key=lambda e: (e["epoch"], e["sha"], e["file"]))
    series = [{"at": e["at"], "sha": e["sha"], "verdict": e["verdict"],
               "rules": len(e["rules"]), "file": e["file"]} for e in kept]
    first_red = next((e for e in kept if e["verdict"] == "RED"), None)
    tail = kept[-1]["verdict"] if kept else None
    streak = 0
    since = None
    for e in reversed(kept):
        if e["verdict"] != tail:
            break
        streak += 1
        since = e
    seen = set(kept[0]["rules"]) if kept else set()
    regressions = []
    for e in kept[1:]:
        for rule in e["rules"]:
            if rule not in seen:
                regressions.append({"rule": rule, "at": e["at"], "sha": e["sha"], "file": e["file"]})
        seen.update(e["rules"])
    if regressions:
        counts: dict[str, int] = {}
        for e in kept:
            for rule in e["rules"]:
                counts[rule] = counts.get(rule, 0) + 1
        for r in regressions:
            r["reports"] = counts.get(r["rule"], 1)
    return {
        "reports": kept, "skipped": skipped,
        "series": series,
        "first_red": ({"at": first_red["at"], "sha": first_red["sha"], "file": first_red["file"]}
                      if first_red else None),
        "current": ({"verdict": tail, "streak": streak,
                     "since": since["at"] if since else None,
                     "sha": since["sha"] if since else ""} if kept else None),
        "regressions": regressions,
    }


def cmd_trend(a):
    """Reads the reports already published on a badge branch (or local report files); never scans."""
    targets = list(a.target)
    paths = [Path(t) for t in targets]
    slug = None
    if all(p.exists() for p in paths):
        files = []
        for p in paths:
            if p.is_dir():
                found = sorted(p.glob("report-*.json"))
                if not found:
                    print(f"trend: no report-*.json in {p}", file=sys.stderr)
                    return 1
                files.extend(found)
            else:
                files.append(p)
        entries, skipped = _trend_local(files)
        label = str(paths[0]) if len(paths) == 1 else f"{targets[0]} … ({len(files)} reports)"
    elif len(targets) == 1:
        m = GITHUB_REPO_RE.match(targets[0])
        slug = f"{m.group(1)}/{m.group(2)}" if m else (
            targets[0] if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", targets[0]) else None)
        if not slug:
            print(f"trend: {targets[0]!r} is neither a local path nor a github repo", file=sys.stderr)
            return 1
        try:
            entries, skipped = _trend_published(slug, a.branch, max(1, a.limit))
        except urllib.error.HTTPError as ex:
            hint = " (no badge branch, or no reports pushed yet)" if ex.code == 404 else ""
            print(f"trend: cannot read {slug}@{a.branch}: HTTP {ex.code}{hint}", file=sys.stderr)
            return 1
        except Exception as ex:
            print(f"trend: cannot read {slug}@{a.branch}: {str(ex)[:160]}", file=sys.stderr)
            return 1
        label = f"{slug} (branch {a.branch})"
    else:
        print("trend: give one github repo, or local report files/directories (not both)", file=sys.stderr)
        return 1
    data = trend_series(entries, skipped)
    kept = data["reports"]
    if not kept:
        print(f"trend: no usable reports ({len(data['skipped'])} skipped)", file=sys.stderr)
        for s in data["skipped"][:10]:
            print(f"  {s['file']}: {s['reason']}", file=sys.stderr)
        return 1
    C = (lambda code, s: f"\033[{code}m{s}\033[0m") if (color_enabled() and not a.no_color) else (lambda code, s: s)
    vc = {"RED": "1;41;97", "YELLOW": "1;43;30", "GREEN": "1;42;30"}
    print(f"repobeagle trend: {label}")
    print(f"reports: {len(kept)} used, {len(data['skipped'])} skipped "
          f"({kept[0]['at']} .. {kept[-1]['at']})")
    print(f"{'scanned at':<21} {'commit':<9} {'verdict':<8} crit/high/med/low")
    for e in kept:
        v = C(vc[e["verdict"]], e["verdict"].ljust(8))
        c = e["counts"]
        print(f"{e['at']:<21} {(e['sha'][:7] or '?'):<9} {v} "
              f"{c['critical']}/{c['high']}/{c['medium']}/{c['low']}")
    print(f"series: {' '.join(TREND_LETTER[e['verdict']] for e in kept)} (oldest -> newest)")
    fr = data["first_red"]
    print(f"first RED: {fr['at']} ({fr['sha'][:7] or fr['file']})" if fr else "first RED: none")
    cur = data["current"]
    if cur:
        print(f"current: {cur['verdict']} streak {cur['streak']}"
              + (f" (since {cur['since']})" if cur["since"] else ""))
    if data["regressions"]:
        print("regressions by rule (first seen after a report without it):")
        for r in data["regressions"]:
            print(f"  {r['rule']}  {r['at']}  {r['sha'][:7] or '?'}  ({r['reports']} report(s))")
    else:
        print("regressions: none")
    for s in data["skipped"][:10]:
        print(f"skipped {s['file']}: {s['reason']}")
    if len(kept) < 3:
        print("note: a trend needs three or more comparable reports", file=sys.stderr)
    if a.json:
        Path(a.json).write_text(json.dumps(data, indent=2))
        print(f"[repobeagle] JSON written to {a.json}", file=sys.stderr)
    return 0


MCP_PROTOCOL = "2024-11-05"


MCP_TOOLS = [
    {"name": "scan_repo",
     "description": "Statically scan a git URL or local directory and return the GREEN/YELLOW/RED verdict with the top findings. Never executes repository code. Blocking: the call returns when the scan finishes (default budget 1800 s).",
     "inputSchema": {"type": "object", "required": ["target"], "properties": {
         "target": {"type": "string", "description": "git URL (https/ssh) or existing local directory"},
         "profile": {"type": "string", "enum": ["strict", "balanced", "relaxed"], "description": "verdict thresholds (default balanced)"},
         "privacy_only": {"type": "boolean", "description": "report only privacy/telemetry findings"},
         "network": {"type": "boolean", "description": "run OSV vulnerability and GitHub trust lookups (default true)"},
         "ref": {"type": "string", "description": "branch, tag or commit to scan (git URLs only)"},
         "since": {"type": "string", "description": "only scan files changed since this revision (diff verdict; git URLs only)"},
         "timeout_seconds": {"type": "integer", "minimum": 5, "maximum": 1800,
                             "description": "kill the scan after this many seconds (default 1800); clients must allow at least this long for the reply"}}}},
    {"name": "verify_badge",
     "description": "Verify a published repobeagle badge: Sigstore signature, report freshness against HEAD, and report self-consistency.",
     "inputSchema": {"type": "object", "required": ["repo"], "properties": {
         "repo": {"type": "string", "description": "github slug, e.g. owner/repo"}}}},
    {"name": "explain_report",
     "description": "Explain how a stored report's verdict follows from its profile thresholds, including the margin to the next tier.",
     "inputSchema": {"type": "object", "required": ["report"], "properties": {
         "report": {"type": "string", "description": "path to a report.json produced by 'scan --json' (the scan_repo tool returns one)"}}}},
]


def _mcp_exec(args, timeout=1800):
    cmd = entry_command() + args
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r


def _mcp_workdir():
    """Report directory under the user cache, pruned to the 20 most recent scans."""
    base = Path(os.environ.get("XDG_CACHE_HOME") or (Path(os.environ.get("HOME") or "/tmp") / ".cache")) / "repobeagle" / "mcp"
    base.mkdir(parents=True, exist_ok=True)
    try:
        old = sorted((p for p in base.iterdir() if p.is_dir()), key=lambda p: p.stat().st_mtime)
        for p in old[:-19]:
            shutil.rmtree(p, ignore_errors=True)
    except OSError:
        pass
    return Path(tempfile.mkdtemp(prefix="scan-", dir=base))


def mcp_scan(a):
    target = a.get("target")
    if not isinstance(target, str) or not target:
        raise ValueError("target is required")
    prof = a.get("profile") or "balanced"
    if prof not in PROFILES:
        raise ValueError(f"profile must be one of {sorted(PROFILES)}")
    try:
        timeout = int(a.get("timeout_seconds", 1800))
    except (TypeError, ValueError):
        raise ValueError("timeout_seconds must be an integer number of seconds")
    if not 5 <= timeout <= 1800:
        raise ValueError("timeout_seconds must be between 5 and 1800")
    work = _mcp_workdir()
    rep = work / "report.json"
    args = ["scan", target, "--json", str(rep), "--no-color"]
    if prof != "balanced": args.append("--" + prof)
    if a.get("privacy_only"): args.append("--privacy-only")
    if a.get("network") is False: args += ["--no-osv", "--no-trust"]
    if a.get("ref"): args += ["--ref", str(a["ref"])]
    if a.get("since"): args += ["--since", str(a["since"])]
    try:
        r = _mcp_exec(args, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"scan exceeded timeout_seconds={timeout}; the process was killed. "
                           "Raise timeout_seconds for huge repositories.")
    try:
        d = json.loads(rep.read_text())
    except Exception:
        raise RuntimeError((r.stderr or r.stdout or "scan produced no report")[-800:])
    meta = d.get("meta") or {}
    fs = [f for f in d.get("findings") or [] if isinstance(f, dict) and not f.get("suppressed")]
    top = sorted(fs, key=lambda f: -SEV_ORDER.get(str(f.get("severity")), 0))[:15]
    return {"target": target, "verdict": d.get("verdict"), "counts": d.get("counts"), "why": d.get("why"),
            "scope": meta.get("scope"), "privacy_profile": meta.get("privacy_profile"),
            "findings_total": len(fs),
            "findings": [{"severity": f.get("severity"), "rule": _rule_of(f), "file": f.get("file"),
                          "line": f.get("line"), "title": f.get("title")} for f in top],
            "report": str(rep)}


def mcp_server(a):
    """JSON-RPC 2.0 over stdio (MCP): tools only, no prompts. stdlib only, never executes repo code."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(msg, dict):
            continue
        method, mid = msg.get("method"), msg.get("id")
        params = msg.get("params") or {}
        if method in ("notifications/initialized", "notifications/cancelled"):
            continue
        res: dict[str, Any]
        if method == "initialize":
            res = {"protocolVersion": params.get("protocolVersion") or MCP_PROTOCOL,
                   "capabilities": {"tools": {}},
                   "serverInfo": {"name": "repobeagle", "version": VERSION}}
        elif method == "ping":
            res = {}
        elif method == "tools/list":
            res = {"tools": MCP_TOOLS}
        elif method == "tools/call":
            name = params.get("name")
            args = params.get("arguments") or {}
            try:
                if name == "scan_repo":
                    payload = mcp_scan(args)
                elif name == "verify_badge":
                    repo = args.get("repo")
                    if not isinstance(repo, str) or not repo: raise ValueError("repo is required")
                    r = _mcp_exec(["verify", repo])
                    payload = {"repo": repo, "exit_code": r.returncode,
                               "output": ((r.stdout or "") + (r.stderr or ""))[-2000:]}
                elif name == "explain_report":
                    path = args.get("report")
                    if not isinstance(path, str) or not path: raise ValueError("report is required")
                    r = _mcp_exec(["explain", path])
                    payload = {"report": path, "exit_code": r.returncode,
                               "explanation": ((r.stdout or "") + (r.stderr or ""))[-4000:]}
                else:
                    raise KeyError(str(name))
                res = {"content": [{"type": "text", "text": json.dumps(payload, indent=2)}]}
            except Exception as ex:
                res = {"content": [{"type": "text", "text": f"{type(ex).__name__}: {ex}"}], "isError": True}
        else:
            if mid is not None:
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid,
                                             "error": {"code": -32601, "message": f"method not found: {method}"}}) + "\n")
                sys.stdout.flush()
            continue
        if mid is None:
            continue
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "result": res}) + "\n")
        sys.stdout.flush()
    return 0


def cmd_map(a):
    """Scans (or reads a report) and prints the capability inventory. Never executes repository code."""
    show_all = getattr(a, "all", False)
    if a.report:
        try:
            d = json.loads(Path(a.report).read_text())
        except (OSError, json.JSONDecodeError) as ex:
            print(f"map: cannot read {a.report}: {ex}", file=sys.stderr); return 1
        return render_capabilities(d, a.report, all_entries=show_all)
    if not a.target:
        print("map: give a target or --report", file=sys.stderr); return 1
    work = tempfile.mkdtemp(prefix="repobeagle-map-")
    _WORKDIRS.add(work)
    rep = Path(work) / "report.json"
    args = ["scan", a.target, "--json", str(rep), "--no-color"]
    if a.strict: args.append("--strict")
    elif a.relaxed: args.append("--relaxed")
    if getattr(a, "ref", None): args += ["--ref", a.ref]
    if not a.network: args += ["--no-osv", "--no-trust"]
    if a.no_docker: args.append("--no-docker")
    r = _mcp_exec(args)
    try:
        d = json.loads(rep.read_text())
    except Exception:
        print("map: scan produced no report: " + ((r.stderr or r.stdout or "")[-600:]), file=sys.stderr)
        return 1
    return render_capabilities(d, a.target, all_entries=show_all)








def cmd_web(a):
    """Fetches one page (plus N same-origin assets), runs the existing privacy rules on the bytes, never executes JS."""
    url = a.url.strip()
    scheme = url.split(":", 1)[0].lower()
    if scheme not in ("http", "https", "file"):
        print(f"web: unsupported scheme {scheme!r}; use http(s):// or file://", file=sys.stderr)
        return 1
    work = tempfile.mkdtemp(prefix="repobeagle-web-")
    _WORKDIRS.add(work)
    src = Path(work) / "page"
    src.mkdir()
    notes = []
    try:
        data, final_url = _web_get(url, a.timeout)
    except Exception as ex:
        print(f"web: cannot fetch {url}: {ex}", file=sys.stderr)
        return 1
    truncated = len(data) > WEB_MAX_BYTES
    if truncated:
        notes.append(f"page truncated at {WEB_MAX_BYTES} bytes")
        data = data[:WEB_MAX_BYTES]
    html = data.decode("utf-8", errors="replace")
    (src / "index.html").write_text(html)
    netloc = urllib.parse.urlsplit(url).netloc
    if netloc:
        (src / "CNAME").write_text(netloc)          # first-party inference: own host is not "third party"
    fetched = {"page_bytes": len(data), "assets": 0, "asset_failures": 0,
               "final_url": final_url, "redirected": final_url != url, "truncated": truncated}
    if fetched["redirected"]:
        notes.append(f"redirected to {final_url}")
    if a.assets > 0:
        refs = re.findall(r'(?i)<script[^>]+src\s*=\s*["\']([^"\']+)', html) + \
               re.findall(r'(?i)<link[^>]+rel\s*=\s*["\']stylesheet["\'][^>]*href\s*=\s*["\']([^"\']+)', html)
        seen = set()
        for ref in refs:
            if fetched["assets"] >= a.assets:
                break
            full = urllib.parse.urljoin(url, ref.strip())
            if full in seen or not full.startswith(("http://", "https://", "file://")):
                continue
            seen.add(full)
            if netloc and urllib.parse.urlsplit(full).netloc != netloc:
                continue                            # same-origin only unless file://
            try:
                body, _ = _web_get(full, a.timeout)
            except Exception as ex:
                fetched["asset_failures"] += 1
                notes.append(f"asset fetch failed: {full} ({type(ex).__name__})")
                continue
            ext = Path(urllib.parse.urlsplit(full).path).suffix if Path(urllib.parse.urlsplit(full).path).suffix in (".js", ".css") else ".txt"
            (src / f"asset-{fetched['assets']:03d}{ext}").write_text(body[:WEB_MAX_BYTES].decode("utf-8", errors="replace"))
            fetched["assets"] += 1
    rep = Path(work) / "report.json"
    args = ["scan", str(src), "--privacy-only", "--no-docker",
            "--json", str(rep), "--no-color"]
    if a.strict: args.append("--strict")
    elif a.relaxed: args.append("--relaxed")
    r = _mcp_exec(args)
    try:
        d = json.loads(rep.read_text())
    except Exception:
        print("web: scan produced no report: " + ((r.stderr or r.stdout or "")[-600:]), file=sys.stderr)
        return 1
    meta = d.get("meta") or {}
    meta.update(target=url, url=url, mode="web (fetched once, no JS executed)", fetched=fetched)
    d["meta"] = meta
    d.setdefault("notes", [])
    if notes: d["notes"] = list(d.get("notes") or []) + notes
    if a.json:
        Path(a.json).write_text(json.dumps(d, indent=2))
        print(f"[repobeagle] JSON written to {a.json}", file=sys.stderr)
    print(banner(color_enabled(sys.stderr) and not a.no_color), file=sys.stderr)
    render_report(meta, d.get("findings") or [], d.get("verdict") or "GREEN", d.get("why") or "",
           d.get("counts") or {s: 0 for s in SEV_ORDER}, d.get("notes") or [], d.get("ai_review"),
           color_enabled() and not a.no_color, 10**6 if a.all else 40, a.min_severity)
    return {"GREEN": 0, "YELLOW": 1, "RED": 2}.get(d.get("verdict"), 2)


# --- repobeagle head: metadata-only triage (GitHub contents API or a local dir) --------
HEAD_FILES = ("package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "requirements.txt",
              "pyproject.toml", "setup.py", "setup.cfg", "Cargo.toml", "go.mod", "Gemfile", "pom.xml",
              "SKILL.md", "mcp.json", ".mcp.json", "README.md", "PRIVACY.md", "SECURITY.md", "LICENSE",
              ".repobeagleignore", ".repobeagle.yml", ".github/CODEOWNERS", ".github/PULL_REQUEST_TEMPLATE.md")


HEAD_DIRS = (".github/workflows", ".repobeagle/rules")


HEAD_MAX_BYTES = 400_000


def _head_cache_path(slug):
    base = Path(os.environ.get("XDG_CACHE_HOME") or (Path(os.environ.get("HOME") or "/tmp") / ".cache"))
    return base / "repobeagle" / "head" / (slug.replace("/", "_") + ".json")


def _gh_contents(slug, path, token=None, timeout=15):
    """(object, rate-remaining, error) for one GitHub contents API call; 404 means 'absent', not an error."""
    api = os.environ.get("GITHUB_API_URL") or "https://api.github.com"
    headers = {"User-Agent": WEB_UA, "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"{api}/repos/{slug}/contents/{path}", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode()), resp.headers.get("X-RateLimit-Remaining"), None
    except urllib.error.HTTPError as ex:
        remaining = ex.headers.get("X-RateLimit-Remaining") if ex.headers else None
        return (None, remaining, None) if ex.code == 404 else (None, remaining, f"HTTP {ex.code}")
    except Exception as ex:
        return None, None, type(ex).__name__


def head_collect_local(root):
    """Metadata subset of a local directory: {relpath: text}, scope dict, notes."""
    root = Path(root)
    files: dict[str, str] = {}
    available = 0
    for rel in HEAD_FILES:
        p = root / rel
        if p.is_file():
            available += 1
            try:
                files[rel] = p.read_text(errors="replace")[:HEAD_MAX_BYTES]
            except OSError:
                pass
    for d in HEAD_DIRS:
        dd = root / d
        if dd.is_dir():
            for p in sorted(dd.glob("*.y*ml")):
                available += 1
                rel = p.relative_to(root).as_posix()
                try:
                    files[rel] = p.read_text(errors="replace")[:HEAD_MAX_BYTES]
                except OSError:
                    pass
    return files, {"scope": "metadata", "paths_fetched": len(files), "paths_available": available,
                   "paths": sorted(files), "truncated": False}, []


def head_collect_api(slug, token=None, use_cache=True):
    """Metadata subset via the GitHub contents API: {relpath: text}, scope dict, notes. Rate limits become notes."""
    notes: list[str] = []
    cache = _head_cache_path(slug)
    try:
        ttl = int(os.environ.get("BEAGLE_HEAD_CACHE_TTL", "3600"))
    except ValueError:
        ttl = 3600
    if use_cache and ttl > 0:
        try:
            cached = json.loads(cache.read_text(encoding="utf-8"))
            age = time.time() - float(cached.get("ts", 0))
            if age < ttl and isinstance(cached.get("files"), dict):
                notes.append(f"served from the per-slug cache ({int(age)}s old, TTL {ttl}s; --no-cache to refresh)")
                return cached["files"], cached.get("scope") or {}, notes
        except (OSError, ValueError):
            pass
    files: dict[str, str] = {}
    available = truncated = 0
    def limit_note():
        return ("GitHub API rate limited (set GITHUB_TOKEN for 5,000 requests/hour; "
                "unauthenticated is 60/hour)")
    rate_hit = False
    def fetch(path):
        nonlocal available, rate_hit
        obj, remaining, err = _gh_contents(slug, path, token)
        if err:
            if "403" in err or "429" in err:
                rate_hit = True
                if not any("rate limited" in n for n in notes):
                    notes.append(limit_note())
            else:
                notes.append(f"GitHub API: {path}: {err}")
            return None
        try:
            if remaining is not None and int(remaining) <= 0 and not token:
                rate_hit = True
                if not any("rate limited" in n for n in notes):
                    notes.append(limit_note())
        except ValueError:
            pass
        return obj
    for rel in HEAD_FILES:
        if rate_hit:
            truncated = 1
            break
        obj = fetch(rel)
        if isinstance(obj, dict) and obj.get("type") == "file" and obj.get("content"):
            available += 1
            content = base64.b64decode(obj["content"])
            files[rel] = content[:HEAD_MAX_BYTES].decode("utf-8", "replace")
    for d in HEAD_DIRS:
        if rate_hit:
            truncated = 1
            break
        obj = fetch(d)
        if not isinstance(obj, list):
            continue
        for entry in obj:
            if rate_hit:
                truncated = 1
                break
            if entry.get("type") != "file" or not str(entry.get("name", "")).endswith((".yml", ".yaml")):
                continue
            obj2 = fetch(str(entry.get("path") or ""))
            if isinstance(obj2, dict) and obj2.get("content"):
                available += 1
                content = base64.b64decode(obj2["content"])
                files[str(entry["path"])] = content[:HEAD_MAX_BYTES].decode("utf-8", "replace")
    scope = {"scope": "metadata", "paths_fetched": len(files), "paths_available": max(available, len(files)),
             "paths": sorted(files), "truncated": bool(truncated)}
    if files and use_cache and ttl > 0:
        try:
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps({"ts": time.time(), "scope": scope, "files": files}), encoding="utf-8")
        except OSError:
            pass
    return files, scope, notes


class HeadError(Exception):
    """A head/gate target could not produce a report (bad target, no metadata, checks failure)."""


def head_report(target, profile="balanced", token="", use_cache=True, profile_defaulted=False, persona=""):
    """Metadata-only report for one target (GitHub contents API or a local dir). No clone, no scanners, no repo code."""
    m = GITHUB_REPO_RE.match(target)
    slug = f"{m.group(1)}/{m.group(2)}" if m else (target if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", target) else None)
    if not os.path.isdir(target) and not slug:
        raise HeadError(f"cannot parse a github repo out of {target!r} (use owner/repo, a github URL, or a local dir)")
    work = tempfile.mkdtemp(prefix="repobeagle-head-")
    _WORKDIRS.add(work)
    try:
        if os.path.isdir(target):
            files, scope, notes = head_collect_local(target)
            source = "local path (metadata subset)"
        else:
            files, scope, notes = head_collect_api(str(slug), token, use_cache=use_cache)
            source = "GitHub contents API (no clone)"
        if not files:
            if os.path.isdir(target):
                raise HeadError(f"no metadata files found in {target!r}")
            raise HeadError("no metadata fetched; " + (notes[-1] if notes else "does the repo exist?"))
        src = Path(work) / "meta"
        src.mkdir()
        for rel, text in files.items():
            relp = Path(rel)
            if relp.is_absolute() or ".." in relp.parts:
                continue
            dest = src / relp
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(text, encoding="utf-8")
        t0 = time.time()
        agent_state: dict[str, Any] = {"complete": True, "skipped": []}
        try:
            findings, nfiles = run_agent_checks(src, None, agent_state)
        except Exception as ex:
            raise HeadError(f"checks failed: {type(ex).__name__}: {ex}")
        try:
            repo_config = load_repo_config(src)
        except ConfigError as ex:
            raise HeadError(str(ex))
        if repo_config and repo_config.get("profile") and profile_defaulted:
            profile = str(repo_config["profile"])
        if repo_config and repo_config["custom_checks"]:
            findings += run_custom_checks(src, repo_config["custom_checks"])
        caps = scan_capabilities(src)
        cov = scan_coverage(src)
        raw_count = len(findings)
        findings = collapse(dedupe(findings))
        for f in findings:
            f.setdefault("rule", _rule_of(f))
            rem = remediation_for(f)
            if rem:
                f["remediation"] = rem
        try:
            packs = load_rule_packs(src)
        except ConfigError as ex:
            raise HeadError(str(ex))
        if packs:
            findings += run_rule_packs(src, packs)
        if persona:
            moved = apply_persona(findings, persona)
            notes.append(f"persona {persona}: {moved} finding(s) re-graded by rule severities")
        if repo_config and repo_config["rules"]:
            for f in findings:
                rule = _explain_rule(f)
                new_sev = next((sev for pattern, sev in repo_config["rules"].items()
                                 if fnmatchcase(rule, pattern)), None)
                if new_sev:
                    f["severity"] = new_sev
        entries = load_suppressions(src)
        active, suppressed, expired = apply_suppressions(findings, entries) if entries else (findings, [], [])
        if suppressed:
            notes.append(f"suppressed {len(suppressed)} finding(s) via {SUPPRESS_FILE}")
        notes.extend(suppression_notes(entries, expired))
        v, why, counts = verdict(active, profile, None)
        complete = bool(agent_state.get("complete", True)) and not agent_state.get("skipped")
        if not complete and v == "GREEN":
            v = "YELLOW"
            why = "Incomplete triage: the per-file alarm skipped a metadata file; GREEN is unproven."
        summary = privacy_summary(active)
        meta = {"target": target, "ref": None, "commit": None, "fetched_via": source,
                "complete": complete,
                "mode": "metadata (no clone, no scanners, no repo code executed)", "profile": profile,
                "files": nfiles, "seconds": round(time.time() - t0, 1),
                "tools": {"agent-checks": {"findings": len(active), "seconds": round(time.time() - t0, 1),
                                           "ok": True, "files": nfiles}},
                "suppressed": len(suppressed), "suppressions": suppression_meta(entries),
                "scope": scope, "capabilities": caps, "coverage": cov, "ruleset": RULESET,
                "privacy_mode": "full", "pii_redacted": True}
        if persona:
            meta["persona"] = {"name": persona, "label": PERSONAS[persona]["label"],
                               "deltas": [{"match": pat, "delta": d} for pat, d in PERSONAS[persona]["deltas"]]}
        if packs:
            meta["rule_packs"] = {"files": [p["path"] for p in packs],
                                  "rules": sum(len(p["rules"]) for p in packs)}
        if repo_config:
            meta["config"] = {"path": CONFIG_FILE, "profile": repo_config.get("profile"),
                              "rules": repo_config["rules"], "hosts": repo_config["hosts"],
                              "custom_checks": len(repo_config["custom_checks"])}
        if summary:
            meta["privacy_summary"] = summary
            meta["privacy_profile"] = privacy_profile(summary)
        d = {"version": VERSION, "verdict": v, "why": why, "counts": counts, "meta": meta,
             "privacy_summary": summary, "ai_review": None, "findings": active + suppressed,
             "raw_findings_count": raw_count, "notes": notes, "recommended_actions": ACTIONS[v]}
        return d, notes, source
    finally:
        shutil.rmtree(work, ignore_errors=True)
        _WORKDIRS.discard(work)


def cmd_head(a):
    """Fast metadata-only triage (GitHub contents API or a local dir): no clone, no scanners, no repo code executed."""
    profile = "strict" if a.strict else "relaxed" if a.relaxed else "balanced"
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    try:
        d, notes, source = head_report(a.target, profile, token, use_cache=not a.no_cache,
                                        profile_defaulted=not (a.strict or a.relaxed),
                                        persona=getattr(a, "as_persona", "") or "")
    except HeadError as ex:
        print(f"head: {ex}", file=sys.stderr)
        return 1
    meta = d["meta"]
    if a.json:
        Path(a.json).write_text(json.dumps(d, indent=2))
        print(f"[repobeagle] JSON written to {a.json}", file=sys.stderr)
    if getattr(a, "html", None):
        Path(a.html).write_text(html_report(d))
        print(f"[repobeagle] HTML written to {a.html}", file=sys.stderr)
    print(f"[repobeagle] head: {meta['scope']['paths_fetched']} metadata file(s) from {source}", file=sys.stderr)
    for n in notes:
        print(f"[repobeagle] note: {n}", file=sys.stderr)
    if a.markdown:
        sys.stdout.write(markdown_report(d))
    else:
        render_report(meta, d["findings"], d["verdict"], d["why"], d["counts"], d["notes"], None,
               color_enabled() and not a.no_color, 10**6 if a.all else 40, a.min_severity)
    return {"GREEN": 0, "YELLOW": 1, "RED": 2}[d["verdict"]]




def parse_run_package(argv):
    """(ecosystem, package) from a wrapped runner command (`npx`, `pnpm dlx`, `pipx run`, ...)."""
    argv = [str(x).strip() for x in argv]
    while argv and argv[0] in ("env",):
        argv = argv[1:]
    if not argv:
        return None, None
    head, rest = argv[0], argv[1:]
    if head == "npx":
        eco, args = "npm", rest
    elif head in ("pnpm", "yarn") and rest[:1] == ["dlx"]:
        eco, args = "npm", rest[1:]
    elif head == "bunx":
        eco, args = "npm", rest
    elif head == "pipx" and rest[:1] == ["run"]:
        eco, args = "pypi", rest[1:]
    elif head == "uvx":
        eco, args = "pypi", rest
    elif head == "cargo" and rest[:1] == ["install"]:
        eco, args = "crates", rest[1:]
    else:
        return None, None
    package = next((t for t in args if t and not t.startswith("-")), "")
    if not package:
        return None, None
    if package.startswith("@"):
        if package.count("@") >= 2:
            package = package.rsplit("@", 1)[0]
    elif "@" in package:
        package = package.split("@", 1)[0]
    package = re.split(r"[=<>!~\s]", package, 1)[0]     # pipx/uvx specs: black==24.1.0
    return eco, package


def _repo_url(value):
    """A cloneable https URL from a registry 'repository'/'homepage' value, or None."""
    if not isinstance(value, str):
        return None
    url = value.strip()
    if url.startswith("git+"):
        url = url[len("git+"):]
    elif url.startswith("git://"):
        url = "https://" + url[len("git://"):]
    elif url.startswith("ssh://git@"):
        url = "https://" + url[len("ssh://git@"):]
    elif url.startswith("git@"):
        url = "https://" + url[len("git@"):].replace(":", "/", 1)
    url = re.sub(r"\.git$", "", url.rstrip("/"))
    m = re.match(r"^https?://([^/\s]+)/([^/\s?#]+)/([^/\s?#]+)", url)
    if not m:
        return None
    host, owner, repo = m.group(1), m.group(2), m.group(3)
    if host == "github.com":
        return f"https://github.com/{owner}/{repo}"
    return f"https://{host}/{owner}/{repo}"






def registry_repo(ecosystem, package):
    """Repository URL for a package from its registry's JSON API; cached with a TTL. Never executes the package."""
    cache = _registry_cache_path(ecosystem, package)
    try:
        ttl = int(os.environ.get("BEAGLE_REGISTRY_TTL", str(REGISTRY_TTL)))
    except ValueError:
        ttl = REGISTRY_TTL
    try:
        d = json.loads(cache.read_text(encoding="utf-8"))
        if time.time() - float(d.get("at") or 0) <= ttl:
            return d.get("repo")
    except (OSError, ValueError):
        pass
    repo = None
    if ecosystem == "npm":
        data = _registry_fetch("https://registry.npmjs.org/" + urllib.parse.quote(package, safe="@"))
        value = data.get("repository")
        if isinstance(value, dict):
            value = value.get("url")
        repo = _repo_url(value) or _repo_url(data.get("homepage"))
    elif ecosystem == "pypi":
        data = _registry_fetch("https://pypi.org/pypi/" + urllib.parse.quote(package) + "/json")
        info = data.get("info") or {}
        candidates = list((info.get("project_urls") or {}).values()) + [info.get("home_page")]
        repo = next((r for u in candidates if (r := _repo_url(u or ""))), None)
    elif ecosystem == "crates":
        data = _registry_fetch("https://crates.io/api/v1/crates/" + urllib.parse.quote(package))
        repo = _repo_url((data.get("crate") or {}).get("repository"))
    try:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps({"at": time.time(), "package": package, "ecosystem": ecosystem, "repo": repo}),
                         encoding="utf-8")
    except OSError:
        pass
    return repo


RUN_PASSTHROUGH = ("strict", "relaxed", "no_docker", "no_osv", "offline_vulnerabilities", "no_trust",
                    "no_cache")


def _print_run_report(doc, repo, stream=None):
    stream = stream or sys.stderr
    meta = doc.get("meta") or {}
    counts = doc.get("counts") or {}
    print(f"run: scanned {repo}: {doc.get('verdict')} "
          f"(critical {counts.get('critical', 0)}, high {counts.get('high', 0)}, "
          f"medium {counts.get('medium', 0)})" + (" [partial]" if meta.get("complete") is False else ""),
          file=stream)
    if meta.get("scope"):
        print(f"run: scope {meta['scope']}", file=stream)
    top = sorted(doc.get("findings") or [], key=lambda f: -SEV_ORDER.get(str(f.get("severity")), 0))[:3]
    for f in top:
        title = str(f.get("title") or "")
        rule = str(f.get("rule") or title.split(":")[0])
        if title == rule:
            title = ""
        elif title.startswith(rule + ": "):
            title = title[len(rule) + 2:]
        print(f"  {str(f.get('severity')).upper():<8} {rule}: {f.get('file')}:{f.get('line')} {title[:140]}".rstrip(),
              file=stream)


def cmd_run(a):
    """Install interceptor: scan the package behind a runner command, then run it (or refuse)."""
    argv = [x for x in (a.command or []) if x != "--"]
    if not argv:
        print("run: nothing to run (use: repobeagle run -- npx -y <package>)", file=sys.stderr)
        return 1
    eco = pkg = None
    if not a.repo:
        eco, pkg = parse_run_package(argv)
        if not eco:
            print(f"run: cannot tell which package {argv[0]!r} runs; pass --repo <owner/repo|url|dir>", file=sys.stderr)
            return 1
        print(f"run: {argv[0]} {pkg} -> {eco} registry lookup ...", file=sys.stderr)
        try:
            repo = registry_repo(eco, pkg)
        except Exception as ex:
            print(f"run: {eco} registry lookup for {pkg!r} failed: {type(ex).__name__}: {ex}", file=sys.stderr)
            return 1
        if not repo:
            print(f"run: {eco} package {pkg!r} has no repository URL; pass --repo <owner/repo|url|dir>",
                  file=sys.stderr)
            return 1
    else:
        repo = a.repo
    flags = ["--json", "", "--no-color"]
    for flag in RUN_PASSTHROUGH:
        if getattr(a, flag, False):
            flags.append("--" + flag.replace("_", "-"))
    if getattr(a, "as_persona", None):
        flags += ["--as", a.as_persona]
    if getattr(a, "max_seconds", None) is not None:
        flags += ["--max-seconds", str(a.max_seconds)]
    with tempfile.TemporaryDirectory() as td:
        report = Path(td) / "report.json"
        flags[1] = str(report)
        print(f"run: scanning {repo} ({eco or 'explicit target'}) ...", file=sys.stderr)
        scan = subprocess.run(entry_command() + ["scan", repo,
                                *flags], capture_output=True, text=True, timeout=3600)
        try:
            doc = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            print("run: the scan produced no report; refusing to run", file=sys.stderr)
            print("  " + ((scan.stderr or scan.stdout or "")[-400:]).strip(), file=sys.stderr)
            return 1
    _print_run_report(doc, repo)
    verdict = doc.get("verdict")
    if a.dry_run:
        return 0
    if verdict == "RED":
        if not a.force:
            print("run: RED verdict, refusing to run (pass --force to override)", file=sys.stderr)
            return 1
    elif verdict == "YELLOW":
        if not (a.force or a.yes):
            if sys.stdin.isatty():
                answer = input("run: YELLOW verdict; run it anyway? [y/N] ").strip().lower()
                if answer not in ("y", "yes"):
                    print("run: not run", file=sys.stderr)
                    return 1
            else:
                print("run: YELLOW verdict without --yes/--force; refusing to run", file=sys.stderr)
                return 1
    elif verdict != "GREEN":
        if not a.force:
            print(f"run: unknown verdict {verdict!r}; refusing to run (pass --force)", file=sys.stderr)
            return 1
    print("run: executing " + " ".join(shlex.quote(x) for x in argv), file=sys.stderr)
    return subprocess.run(argv).returncode


# --- Batch full scans: one process per target, bounded concurrency, deterministic reports --------
def cmd_batch(a):
    """Full-scan every target in a listing, one report each, in parallel. Same code path as `scan`."""
    try:
        targets = load_gate_entries(a.targets)
    except ValueError as ex:
        print(f"batch: {ex}", file=sys.stderr)
        return 1
    if not targets:
        print("batch: no targets in the list (one git URL, owner/repo or local dir per line; # comments)",
              file=sys.stderr)
        return 1
    if not (1 <= int(a.jobs) <= 16):
        print("batch: --jobs must be between 1 and 16", file=sys.stderr)
        return 1
    outdir = Path(a.json or "repobeagle-batch")
    try:
        outdir.mkdir(parents=True, exist_ok=True)
    except OSError as ex:
        print(f"batch: cannot create {outdir}: {ex}", file=sys.stderr)
        return 1
    flags: list[str] = ["--jobs", "1"]          # parallelise targets, not scanners inside each target
    for flag in ("strict", "relaxed", "no_docker", "no_osv", "offline_vulnerabilities", "no_trust",
                 "no_redact", "privacy_only", "no_privacy", "no_cache"):
        if getattr(a, flag, False):
            flags.append("--" + flag.replace("_", "-"))
    for opt in ("min_severity", "max_seconds", "release_assets"):
        value = getattr(a, opt, None)
        if value is not None:
            flags += ["--" + opt.replace("_", "-"), str(value)]
    if getattr(a, "as_persona", None):
        flags += ["--as", a.as_persona]
    cli = entry_command()

    def run_one(index, target):
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", target).strip("_")[:60] or f"target{index}"
        out = outdir / f"{index:03d}-{safe}.json"
        argv = cli + ["scan", target, "--json", str(out), "--no-color"] + flags
        t0 = time.time()
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=3600)
            tail = ((r.stderr or "") + (r.stdout or ""))[-400:]
        except subprocess.TimeoutExpired:
            r, tail = None, "scan timed out after 3600 s"
        entry: dict[str, Any] = {"target": target, "seconds": round(time.time() - t0, 1),
                                  "json": str(out) if out.exists() else None,
                                  "exit_code": r.returncode if r else None}
        try:
            d = json.loads(out.read_text())
            entry.update({"verdict": d.get("verdict"), "counts": d.get("counts"),
                          "complete": (d.get("meta") or {}).get("complete")})
        except (OSError, ValueError):
            entry.update({"verdict": "unknown", "counts": {}, "error": tail.strip() or "no report written"})
        return entry

    t0 = time.time()
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=min(int(a.jobs), 16)) as pool:
        entries = list(pool.map(lambda it: run_one(*it), list(enumerate(targets))))
    counts = {v: sum(1 for e in entries if e.get("verdict") == v) for v in ("GREEN", "YELLOW", "RED", "unknown")}
    worst = "RED" if counts["RED"] else "YELLOW" if counts["YELLOW"] else "GREEN" if counts["GREEN"] else "unknown"
    summary = {"version": VERSION, "kind": "batch", "verdict": worst, "counts": counts,
               "entries": entries, "meta": {"targets": len(targets), "jobs": int(a.jobs),
                                            "seconds": round(time.time() - t0, 1), "reports": str(outdir)}}
    (outdir / "batch.json").write_text(json.dumps(summary, indent=2))
    C = (lambda code, s: f"\033[{code}m{s}\033[0m") if (color_enabled() and not a.no_color) else (lambda code, s: s)
    for e in entries:
        extra = "" if e.get("verdict") != "unknown" else "  " + str(e.get("error", ""))[:120]
        print(f"  {str(e.get('verdict')):<7} {e['target']}  ({e.get('seconds')}s){extra}")
    print(f"\n{len(targets)} target(s): " + ", ".join(f"{n} {v}" for v, n in counts.items() if n)
          + f" (jobs {a.jobs}, reports in {outdir}/, summary {outdir}/batch.json)")
    if any(e.get("verdict") == "unknown" for e in entries):
        print(C("33", "  unknown: a target did not produce a report; see batch.json"), file=sys.stderr)
    return {"GREEN": 0, "YELLOW": 1, "RED": 2}.get(worst, 1)


# --- Registry/marketplace gate: batch metadata verdicts for a directory listing ------------
GATE_MAX_ENTRIES = 5000


def load_gate_entries(path):
    """[target] from a directory listing: one target per line (# comments) or JSON strings/{"target": ...}."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as ex:
        raise ValueError(f"cannot read entries: {ex}")
    items: list[str] = []
    if text.lstrip().startswith(("[", "{")):
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as ex:
            raise ValueError(f"{path} is not valid JSON: {ex}")
        raw = doc.get("entries") if isinstance(doc, dict) else doc
        if not isinstance(raw, list):
            raise ValueError('JSON entries must be a list or {"entries": [...]}')
        for item in raw:
            if isinstance(item, str):
                items.append(item)
            elif isinstance(item, dict) and item.get("target"):
                items.append(str(item["target"]))
            else:
                raise ValueError(f"JSON entry is neither a string nor {{'target': ...}}: {item!r}")
    else:
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                items.append(line)
    seen: set[str] = set()
    out: list[str] = []
    for target in items:
        if target not in seen:
            seen.add(target)
            out.append(target)
    if len(out) > GATE_MAX_ENTRIES:
        raise ValueError(f"{len(out)} entries; the gate accepts at most {GATE_MAX_ENTRIES}")
    return out


def gate_entry(target, profile, token, use_cache=True, persona=""):
    """One per-entry verdict for the gate: unfetchable entries are `unknown`, never GREEN."""
    try:
        d, notes, source = head_report(target, profile, token, use_cache=use_cache, persona=persona)
    except HeadError as ex:
        return {"target": target, "verdict": "unknown", "why": str(ex), "counts": {}, "findings": [],
                "source": "unfetchable", "notes": [str(ex)], "seconds": 0.0}
    meta = d.get("meta") or {}
    return {"target": target, "verdict": d.get("verdict"), "why": d.get("why"), "counts": d.get("counts"),
            "findings": d.get("findings") or [], "source": source, "notes": list(notes),
            "seconds": meta.get("seconds"), "suppressed": meta.get("suppressed"),
            "scope": meta.get("scope")}


def _gate_one(entry, profile, token, use_cache, persona=""):
    try:
        return gate_entry(entry, profile, token, use_cache, persona)
    except Exception as ex:  # a broken scanner must not take the whole directory down
        return {"target": entry, "verdict": "unknown", "why": f"{type(ex).__name__}: {ex}", "counts": {},
                "findings": [], "source": "unfetchable", "notes": [str(ex)], "seconds": 0.0}


def gate_report(entries, profile="balanced", token="", baseline=None, jobs=1, use_cache=True, persona=""):
    """Batch verdicts for a listing; `new_red` is RED now and not RED in the baseline (all RED without one)."""
    baseline_verdicts: dict[str, str] = {}
    if baseline:
        try:
            b = json.loads(Path(baseline).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as ex:
            raise ValueError(f"cannot read baseline {baseline}: {ex}")
        raw = b.get("entries") if isinstance(b, dict) else None
        if not isinstance(raw, list):
            raise ValueError(f"{baseline}: not a gate report (no 'entries' list)")
        for e in raw:
            if isinstance(e, dict) and e.get("target"):
                baseline_verdicts[str(e["target"])] = str(e.get("verdict") or "unknown")
    t0 = time.time()
    if jobs and jobs > 1:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(jobs, 16)) as pool:
            rows = list(pool.map(lambda t: _gate_one(t, profile, token, use_cache, persona), entries))
    else:
        rows = [_gate_one(e, profile, token, use_cache, persona) for e in entries]
    counts = {v: sum(1 for r in rows if r["verdict"] == v) for v in ("GREEN", "YELLOW", "RED", "unknown")}
    worst = ("RED" if counts["RED"] else "YELLOW" if counts["YELLOW"] else "GREEN" if counts["GREEN"] else "unknown")
    new_red = [r["target"] for r in rows if r["verdict"] == "RED" and baseline_verdicts.get(r["target"]) != "RED"]
    return {"version": VERSION, "kind": "gate", "verdict": worst, "counts": counts, "entries": rows,
            "new_red": new_red, "unknown": [r["target"] for r in rows if r["verdict"] == "unknown"],
            "meta": {"entries": len(entries), "profile": profile, "ruleset": RULESET,
                     "seconds": round(time.time() - t0, 1), "jobs": jobs or 1,
                     "cache": "on" if use_cache else "off", "baseline": baseline}}


def gate_markdown(d):
    """Markdown table for a directory CI job summary: one row per listing."""
    lines = ["| Entry | Verdict | Findings | Why |", "|---|---|---|---|"]
    for r in d["entries"]:
        rules = ", ".join(sorted({str(f.get("rule")) for f in r.get("findings") or [] if f.get("rule")})[:4]) or "—"
        why = str(r.get("why") or "").replace("|", "\\|")[:180]
        lines.append(f"| `{r['target']}` | {r['verdict']} | {rules} | {why} |")
    return "\n".join(lines) + "\n"


def cmd_gate(a):
    """Registry/marketplace gate: per-entry verdicts for a directory listing, failing only on a new RED."""
    profile = "strict" if a.strict else "relaxed" if a.relaxed else "balanced"
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    try:
        entries = load_gate_entries(a.entries)
    except ValueError as ex:
        print(f"gate: {ex}", file=sys.stderr)
        return 1
    if not entries:
        print("gate: no entries in the list (one target per line; # starts a comment; JSON also accepted)", file=sys.stderr)
        return 1
    try:
        d = gate_report(entries, profile, token, baseline=a.baseline, jobs=a.jobs, use_cache=not a.no_cache,
                        persona=getattr(a, "as_persona", "") or "")
    except ValueError as ex:
        print(f"gate: {ex}", file=sys.stderr)
        return 1
    if a.json:
        Path(a.json).write_text(json.dumps(d, indent=2))
        print(f"[repobeagle] JSON written to {a.json}", file=sys.stderr)
    if a.markdown:
        sys.stdout.write(gate_markdown(d))
    else:
        C = (lambda code, s: f"\033[{code}m{s}\033[0m") if (color_enabled() and not a.no_color) else (lambda code, s: s)
        for r in d["entries"]:
            rules = ", ".join(sorted({str(f.get("rule")) for f in r.get("findings") or [] if f.get("rule")})[:4])
            why = str(r.get("why") or "")[:120]
            print(f"  {r['verdict']:<7} {r['target']}" + (f"  [{rules}]" if rules else "") + (f"  {why}" if why and r["verdict"] == "unknown" else ""))
        print(f"\n{len(entries)} entr{'y' if len(entries) == 1 else 'ies'}: "
              + ", ".join(f"{n} {v}" for v, n in d["counts"].items() if n)
              + f" (profile {profile}{', baseline ' + a.baseline if a.baseline else ', no baseline: every RED is new'})")
        for n in d["unknown"]:
            print(C("33", f"  unknown: {n} — unfetchable or empty, never treated as GREEN"), file=sys.stderr)
        for n in d["new_red"]:
            print(C("1;91", f"  NEW RED: {n}"), file=sys.stderr)
    if a.report_only:
        return 0
    return 1 if d["new_red"] else 0


def cmd_db(a):
    """Status or refresh of the local OSV database. Host-side only; the scan itself stays offline."""
    info = osv_db_info()
    if not a.update:
        print(f"OSV offline database: {info['path']}")
        if info["ecosystems"]:
            for e in info["ecosystems"]:
                print(f"  {e['ecosystem']}: {e['bytes'] // 1024 // 1024} MB"
                      + (" (corrupt)" if e.get("corrupt") else ""))
            print(f"  updated: {info['updated']}  ({info['bytes'] // 1024 // 1024} MB total, "
                  f"{info['age_days']} day(s) old)")
            print("  use: repobeagle scan <target> --offline-vulnerabilities")
            if info["stale"]:
                print(f"  warning: older than the {info['max_age_days']}-day policy "
                      f"(BEAGLE_DB_MAX_AGE_DAYS); run: repobeagle db --update <dir-with-lockfiles>",
                      file=sys.stderr)
            bad = [e["ecosystem"] for e in info["ecosystems"] if e.get("corrupt")]
            if bad:
                print(f"  warning: unreadable database for {', '.join(bad)}; run: repobeagle db --update <dir>",
                      file=sys.stderr)
        else:
            print("  no databases downloaded; run: repobeagle db --update <dir-with-lockfiles>")
        return 0
    target = a.target or "."
    print(f"downloading OSV databases for the ecosystems in {target} ...", file=sys.stderr)
    r = _run(["osv-scanner", "scan", "source", "--offline-vulnerabilities", "--download-offline-databases",
              "-r", target], timeout=int(os.environ.get("BEAGLE_DB_TIMEOUT", "1800")))
    if r is None:
        print("db: osv-scanner not installed; run ./install.sh", file=sys.stderr); return 1
    if r == "timeout":
        print("db: osv-scanner timed out (set BEAGLE_DB_TIMEOUT to raise the limit)", file=sys.stderr); return 1
    info = osv_db_info()
    if not info["ecosystems"]:
        print("db: no database was downloaded (does the target contain a lockfile or manifest?)", file=sys.stderr)
        print((r.stderr or r.stdout or "")[-400:], file=sys.stderr)
        return 1
    for e in info["ecosystems"]:
        print(f"  {e['ecosystem']}: {e['bytes'] // 1024 // 1024} MB")
    print(f"updated: {info['updated']} ({info['bytes'] // 1024 // 1024} MB total) at {info['path']}")
    return 0


INIT_WORKFLOW = """# Generated by `repobeagle init`. Bump the ref below together with the tool.
name: repobeagle
on:
  push:
    branches: [main]
    tags: ["v*"]
  workflow_dispatch:
jobs:
  scan:
    permissions:
      contents: write        # publish the badge branch
      statuses: write        # set the repobeagle/scan commit status
      id-token: write        # keyless-sign the report
      security-events: write # the reusable workflow requests this (upload-sarif) even when unused
    uses: javierbits/repobeagle/.github/workflows/scan.yml@{ref}
    with:
      profile: {profile}
      fail-on-red: {fail_on_red}
      privacy-only: {privacy_only}
      badge-branch: "{badge_branch}"
      set-status: {set_status}
      tools-ref: {ref}
"""


def _repo_slug(target):
    """owner/name for the badge URL: --repo, GITHUB_REPOSITORY, or the origin remote; placeholder otherwise."""
    for value in (os.environ.get("GITHUB_REPOSITORY"),):
        if value and "/" in value:
            return value
    try:
        r = subprocess.run(["git", "-C", str(target), "config", "--get", "remote.origin.url"],
                            capture_output=True, text=True, timeout=15)
    except Exception:
        r = None
    url = (r.stdout or "").strip() if r and r.returncode == 0 else ""
    m = re.search(r"github\.com[:/]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?$", url)
    return f"{m.group(1)}/{m.group(2)}" if m else os.environ.get("REPOBEAGLE_REPO", "OWNER/REPO")


def cmd_init(a):
    """Writes the documented reusable-workflow file and prints the shield lines. Never touches anything else."""
    target = Path(a.target or ".")
    out = Path(a.out) if a.out else target / ".github" / "workflows" / "repobeagle.yml"
    ref = a.tools_ref or RELEASE
    body = INIT_WORKFLOW.format(ref=ref, profile=a.profile, fail_on_red=str(a.fail_on_red).lower(),
                                privacy_only=str(a.privacy_only).lower(), badge_branch=a.badge_branch,
                                set_status=str(a.set_status).lower())
    if a.dry_run:
        sys.stdout.write(body)
        return 0
    old = ""
    try:
        old = out.read_text(encoding="utf-8")
    except OSError:
        pass
    if old == body:
        print(f"{out} is up to date")
    elif old and not a.force:
        print(f"init: {out} exists with different content; re-run with --force to replace it", file=sys.stderr)
        return 1
    else:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(body, encoding="utf-8")
        print(f"wrote {out}")
    slug = a.repo or _repo_slug(target)
    if a.badge_branch:
        print("\nAdd to your README:")
        print(f"![RepoBeagle](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/{slug}/{a.badge_branch}/badge.json)")
        print(f"# full report: https://raw.githubusercontent.com/{slug}/{a.badge_branch}/report.json")
    else:
        print("\nPublishing is disabled (badge-branch empty); the workflow still sets the commit status.")
    print(f"\nCommit {out} and merge it to the default branch; then run the workflow once. "
          f"The toolchain ref is pinned to {ref}.")
    return 0


def cmd_ignore(a):
    """Adds or updates one `.repobeagleignore` line (`rule [# reason] [@YYYY-MM-DD]`), or lists the file."""
    path = Path(a.file)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        raw = ""
    entries = [e for e in (parse_suppression(line, n) for n, line in enumerate(raw.splitlines(), 1)) if e]
    if a.list or not a.rule:
        rows = suppression_meta(entries)
        if a.json:
            Path(a.json).write_text(json.dumps(rows, indent=2))
            print(f"[repobeagle] ignore JSON written to {a.json}", file=sys.stderr)
        if not rows:
            print(f"no suppressions in {a.file}")
            return 0
        for r in rows:
            when = f" until {r['until']}" if r["until"] else ""
            reason = f"  # {r['reason']}" if r["reason"] else ""
            print(f"  {r['status']:<7} {r['rule']}{when}{reason}")
        return 0
    if a.until:
        try:
            date.fromisoformat(a.until)
        except ValueError:
            print("ignore: --until must be YYYY-MM-DD", file=sys.stderr)
            return 1
    if a.report:
        try:
            d = json.loads(Path(a.report).read_text())
        except (OSError, ValueError) as ex:
            print(f"ignore: cannot read report {a.report}: {ex}", file=sys.stderr)
            return 1
        rules = {str(f.get("rule") or str(f.get("title") or "").split(":")[0]) for f in d.get("findings") or []
                 if isinstance(f, dict)}
        if not any(fnmatchcase(rule, a.rule) for rule in rules):
            print(f"ignore: no finding in {a.report} matches {a.rule!r}", file=sys.stderr)
            return 1
    line = a.rule + (f"  # {a.reason}" if a.reason else "") + (f"  @{a.until}" if a.until else "")
    lines = raw.splitlines()
    replaced = False
    for i, existing in enumerate(lines):
        entry = parse_suppression(existing, i + 1)
        if entry and entry["rule"] == a.rule:
            lines[i] = line
            replaced = True
            break
    if not replaced:
        lines.append(line)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    print(f"{'updated' if replaced else 'added'} {a.rule!r} in {a.file}"
          + (f" (until {a.until})" if a.until else ""))
    return 0


def cmd_scan(a):
    print(banner(color_enabled(sys.stderr) and not a.no_color), file=sys.stderr)   # stderr keeps stdout reports clean
    t0 = time.time()
    max_seconds = getattr(a, "max_seconds", None)
    if max_seconds is not None and max_seconds <= 0:
        print("scan: --max-seconds must be greater than 0", file=sys.stderr)
        return 1
    osv_meta: dict[str, Any] = {}
    skipped = []
    profile = "strict" if a.strict else "relaxed" if a.relaxed else "balanced"
    profile_explicit = bool(getattr(a, "strict", False) or getattr(a, "balanced", False) or getattr(a, "relaxed", False))
    config_note = ""
    baseline = None
    if getattr(a, "baseline", None):
        try:
            baseline = json.loads(Path(a.baseline).read_text(encoding="utf-8"))
            if not isinstance(baseline, dict):
                raise ValueError("root must be a JSON object")
        except (OSError, ValueError) as ex:
            print(f"[repobeagle] baseline {a.baseline}: {ex}", file=sys.stderr)
            return 1
    if getattr(a, "privacy_only", False):
        # privacy-only filters non-privacy findings anyway, so skip the work/network for them
        if not getattr(a, "no_osv", False):
            a.no_osv = True
            skipped.append("OSV vulnerability scan")
        if not getattr(a, "no_trust", False):
            a.no_trust = True
            skipped.append("GitHub trust signals")
    work = None
    try:
        work = tempfile.mkdtemp(prefix="repobeagle-")
        if not a.keep:
            _WORKDIRS.add(work)          # atexit / signal handlers remove it on any exit path
        os.chmod(work, 0o700)
        print(f"[repobeagle] fetching {a.target} ...", file=sys.stderr)
        src, how, commit = fetch_repo(a.target, work, getattr(a, "ref", None), getattr(a, "since", None))
        archive_summary = None
        try:
            archive_summary = json.loads((Path(work) / "archive.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        try:
            repo_config = load_repo_config(src)
        except ConfigError as ex:
            print(f"scan: {ex}", file=sys.stderr)
            return 1
        if repo_config:
            if repo_config.get("profile") and not profile_explicit:
                profile = str(repo_config["profile"])
            parts = [f"profile {profile}"] if repo_config.get("profile") else []
            if repo_config["rules"]:
                parts.append(f"{len(repo_config['rules'])} rule override(s)")
            if repo_config["hosts"]:
                parts.append(f"{len(repo_config['hosts'])} allowed host(s)")
            if repo_config["custom_checks"]:
                parts.append(f"{len(repo_config['custom_checks'])} custom check(s)")
            config_note = f"config: {CONFIG_FILE} applied" + (f" ({', '.join(parts)})" if parts else "")
        analysis_deadline = time.monotonic() + max_seconds if max_seconds else None
        analysis_complete = True
        out = Path(work) / "out"; out.mkdir()
        use_docker = not a.no_docker and docker_ok()
        if not a.no_docker and not use_docker:
            print(f"[repobeagle] docker image {IMAGE} not available -> local fallback (run ./install.sh, or ./install.sh --build-local)", file=sys.stderr)
        print(f"[repobeagle] scanning ({'docker --network none' if use_docker else 'local'}) ...", file=sys.stderr)
        cache_state = "disabled" if getattr(a, "no_cache", False) else "miss"
        cache_key = analysis_cache_key(src, commit, use_docker, getattr(a, "since", None),
                                        repo_config["sha256"] if repo_config else "")
        res = cache_load(cache_key) if cache_state == "miss" else None
        cache_note = ""
        if res is not None:
            cache_state = "hit"
            cache_note = (f"analysis cache hit ({cache_key[:12]}): tree, ruleset, image and mode unchanged; "
                           "host-side stages (OSV/trust/verify-deps) are not cached and still run when enabled")
            print(f"[repobeagle] analysis cache hit {cache_key[:12]} ({_cache_root() / (cache_key + '.json')})",
                  file=sys.stderr)
        else:
            try:
                if use_docker:
                    # the container has its own 3600 s timeout; cut it at the deadline (partial report)
                    with _scan_alarm(_deadline_left(analysis_deadline)):
                        res = run_in_docker(src, out, jobs=getattr(a, "jobs", 1))
                else:
                    res = inner(src, out, deadline=analysis_deadline, jobs=getattr(a, "jobs", 1))   # phases guard themselves
            except ScanDeadline:
                res = {"findings": [], "tools": {},
                       "notes": ["scan stopped at --max-seconds before the analysis phase wrote results"],
                       "complete": False}
            if cache_state == "miss" and res.get("complete", True):
                cache_store(cache_key, res)
        if not res.get("complete", True):
            analysis_complete = False
        def budget_exhausted(phase):
            nonlocal analysis_complete
            if analysis_deadline is not None and time.monotonic() >= analysis_deadline:
                analysis_complete = False
                notes.append(f"{phase} skipped: --max-seconds deadline reached; the report is partial")
                return True
            return False
        findings, notes, tools = res["findings"], res["notes"], res["tools"]
        if cache_note:
            notes.append(cache_note)
        if config_note:
            notes.append(config_note)
        if repo_config and repo_config["custom_checks"]:
            custom = run_custom_checks(src, repo_config["custom_checks"])
            findings += custom
            notes.append(f"config: {len(repo_config['custom_checks'])} custom check(s) ran, "
                         f"{len(custom)} finding(s)")
        release_meta: list[dict] = []
        if getattr(a, "release_assets", None):
            try:
                ra_findings, release_meta = scan_release_assets(a.release_assets, Path(work) / "releases",
                                                                analysis_deadline)
            except Exception as ex:
                notes.append(f"release-assets: skipped: {type(ex).__name__}: {ex}")
            else:
                findings += ra_findings
                notes.append(f"release-assets: {len(release_meta)} asset(s) of {a.release_assets} latest release")
        if archive_summary:
            notes.append(f"archive: {archive_summary['archive']} ({archive_summary['format'] or 'uninspectable'}): "
                         f"{archive_summary['extracted']}/{archive_summary['entries']} entries, "
                         f"{archive_summary['bytes']} bytes extracted")
            for item in archive_summary["skipped"][:6]:
                findings.append(finding("agent-checks", "info", archive_summary["archive"], 0,
                                         f"archive-skipped: {item['name']} ({item['reason']})", "",
                                         "The archive member was recorded and not extracted; nothing was executed."))
            if archive_summary["truncated"]:
                findings.append(finding("agent-checks", "low", archive_summary["archive"], 0,
                                         "archive-truncated: extraction stopped at the configured limits",
                                         f"{archive_summary['extracted']}/{archive_summary['entries']} entries, "
                                         f"{archive_summary['bytes']} bytes",
                                         "Only the extracted part was inspected; raise BEAGLE_ARCHIVE_* to widen the budget."))
        try:
            packs = load_rule_packs(src)
        except ConfigError as ex:
            print(f"scan: {ex}", file=sys.stderr)
            return 1
        if packs:
            pack_findings = run_rule_packs(src, packs)
            findings += pack_findings
            notes.append(f"rules: {sum(len(pack['rules']) for pack in packs)} pack rule(s) from "
                         f"{len(packs)} file(s) ran, {len(pack_findings)} finding(s)")
        sk = Path(work) / "skipped.json"
        if sk.exists():
            for n in json.loads(sk.read_text()):
                arch = n.lower().endswith(ARCHIVE_EXT)
                mal = re.search(r"(?i)malicious|malware|sample|payload|infected", n)
                findings.append(finding("agent-checks", "high" if (arch and mal) else "medium", n, 0,
                    ("Archive (not downloaded; uninspectable, likely encrypted malware sample)" if mal else "Archive in repo (not downloaded/inspected)") if arch
                    else "Prebuilt binary/compiled artifact (not downloaded/inspected)", n,
                    "Archives/binaries are never downloaded or extracted; their contents cannot be vetted."))
        if not a.no_osv and not budget_exhausted("OSV scan"):
            t = time.time()
            try:
                with _scan_alarm(_deadline_left(analysis_deadline)):
                    fs, note = scan_osv(src, getattr(a, "offline_vulnerabilities", False))
            except ScanDeadline:
                fs, note = [], "osv-scanner cut by --max-seconds"
                analysis_complete = False
            findings += fs; tools["osv-scanner"] = {"findings": len(fs), "seconds": round(time.time() - t, 1), "ok": note is None}
            ver = tool_version("osv-scanner")
            if ver: tools["osv-scanner"]["version"] = ver
            if note: notes.append(note)
            if getattr(a, "offline_vulnerabilities", False):
                osv_meta["offline_vulnerabilities"] = True
                osv_meta["osv_db"] = osv_db_info()
                if not osv_meta["osv_db"]["ecosystems"]:
                    notes.append(f"offline OSV database missing at {osv_meta['osv_db']['path']}; "
                                 "run 'repobeagle db --update <dir-with-lockfiles>' for deterministic results")
                elif osv_meta["osv_db"]["stale"]:
                    notes.append(f"offline OSV database is {osv_meta['osv_db']['age_days']} day(s) old "
                                 f"(policy: {osv_meta['osv_db']['max_age_days']} days); "
                                 "run 'repobeagle db --update <dir-with-lockfiles>' to refresh")
                bad = [e["ecosystem"] for e in osv_meta["osv_db"]["ecosystems"] if e.get("corrupt")]
                if bad:
                    notes.append(f"offline OSV database unreadable for {', '.join(bad)}; "
                                 "re-run 'repobeagle db --update <dir-with-lockfiles>'")
        if not a.no_trust and not budget_exhausted("trust signals"):
            t = time.time(); fs, note = trust_signals(a.target)
            findings += fs
            if fs or note: tools["trust"] = {"findings": len(fs), "seconds": round(time.time() - t, 1), "ok": note is None}
            if note: notes.append(note)
        if a.verify_deps and not budget_exhausted("verify-deps"):
            try:
                with _scan_alarm(_deadline_left(analysis_deadline)):
                    fs, note = verify_deps(src)
            except ScanDeadline:
                fs, note = [], "verify-deps cut by --max-seconds"
                analysis_complete = False
            findings += fs
            if note: notes.append(note)
        if skipped:
            notes.append("privacy-only: skipped non-privacy stages (" + ", ".join(skipped) + ")")
        persona = getattr(a, "as_persona", None)
        if persona:
            moved = apply_persona(findings, persona)
            notes.append(f"persona {persona}: {moved} finding(s) re-graded by rule severities")
        if repo_config and repo_config["rules"]:
            graded = 0
            for f in findings:
                rule = _explain_rule(f)
                new_sev = next((sev for pattern, sev in repo_config["rules"].items()
                                 if fnmatchcase(rule, pattern)), None)
                if new_sev and f.get("severity") != new_sev:
                    f["severity"] = new_sev
                    graded += 1
            notes.append(f"config: {graded} finding(s) re-graded by {CONFIG_FILE} rule overrides")
        workspace = (res.get("workspace") or {})
        workspace_counts: dict[str, dict[str, int]] = {}
        if workspace.get("packages"):
            for f in findings:
                relf = str(f.get("file") or "")
                for pkg in workspace["packages"]:
                    base = pkg["path"]
                    if relf == base or relf.startswith(base + "/"):
                        f["package"] = pkg["name"]
                        f["package_path"] = base
                        break
            notes.append(f"workspace: {len(workspace['packages'])} package(s) detected"
                         + (f", {workspace.get('dropped', 0)} beyond BEAGLE_MAX_PACKAGES" if workspace.get("dropped") else ""))
        raw_count = len(findings)
        findings = collapse(dedupe(findings))
        if getattr(a, "privacy_only", False):
            findings = [f for f in findings if f["tool"] in ("privacy", "telemetry")]
        elif getattr(a, "no_privacy", False):
            findings = [f for f in findings if f["tool"] not in ("privacy", "telemetry")]
        if not a.no_redact:
            for f in findings:
                if f["tool"] in ("privacy", "telemetry"):
                    f["snippet"] = redact_pii(f["snippet"])
                    f["title"] = redact_pii(f["title"])
        for f in findings:
            f.setdefault("rule", _rule_of(f))
            rem = remediation_for(f)
            if rem:
                f["remediation"] = rem
        entries = load_suppressions(src)
        active, suppressed, expired = apply_suppressions(findings, entries) if entries else (findings, [], [])
        if workspace.get("packages"):
            reported = active + suppressed
            buckets = ["(root)"] + [pkg["name"] for pkg in workspace["packages"]]
            workspace_counts = {name: {sev: 0 for sev in SEV_ORDER} for name in buckets}
            for f in reported:
                name = f.get("package") or "(root)"
                workspace_counts.setdefault(name, {sev: 0 for sev in SEV_ORDER})[str(f.get("severity"))] += 1
        if suppressed:
            notes.append(f"suppressed {len(suppressed)} finding(s) via {SUPPRESS_FILE}: " +
                         ", ".join(sorted({f['title'].split(':')[0] for f in suppressed})))
        notes.extend(suppression_notes(entries, expired))
        ai, note = ai_review(src, active)
        if note: notes.append(note)
        v, why, counts = verdict(active, profile, ai)
        complete = analysis_complete and bool(res.get("complete", True))
        if not complete:
            if v == "GREEN":
                v = "YELLOW"
                why = "Incomplete scan (--max-seconds): no findings so far, but not every phase finished; GREEN is unproven."
            else:
                why = f"{why} (scan incomplete: --max-seconds deadline reached)"
            notes.append("scan incomplete: --max-seconds deadline reached; this verdict cannot be GREEN")
        privacy_mode = "only" if a.privacy_only else "excluded" if a.no_privacy else "full"
        summary = privacy_summary(active)
        meta = {"target": a.target, "ref": getattr(a, "ref", None), "commit": commit,
                "fetched_via": how, "mode": "docker (--network none, read-only)" if use_docker else "local (no docker)",
                "profile": profile, "files": tools.get("agent-checks", {}).get("files"), "seconds": round(time.time() - t0, 1),
                "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "tools": tools, "suppressed": len(suppressed), "suppressions": suppression_meta(entries),
                "pii_redacted": not a.no_redact, "privacy_mode": privacy_mode, "ruleset": RULESET,
                "complete": complete, "cache": cache_state}
        if workspace_counts:
            meta["workspace"] = {"packages": [{"name": p["name"], "path": p["path"], "kind": p["kind"]}
                                              for p in workspace["packages"]],
                                  "dropped": workspace.get("dropped", 0), "counts": workspace_counts}
        if archive_summary:
            meta["archive"] = archive_summary
        if release_meta:
            meta["release_assets"] = release_meta
        if packs:
            meta["rule_packs"] = {"files": [p["path"] for p in packs],
                                  "rules": sum(len(p["rules"]) for p in packs)}
        if getattr(a, "as_persona", None):
            meta["persona"] = {"name": a.as_persona, "label": PERSONAS[a.as_persona]["label"],
                               "deltas": [{"match": pat, "delta": d} for pat, d in PERSONAS[a.as_persona]["deltas"]]}
        if repo_config:
            meta["config"] = {"path": CONFIG_FILE, "profile": repo_config.get("profile"),
                              "rules": repo_config["rules"], "hosts": repo_config["hosts"],
                              "custom_checks": len(repo_config["custom_checks"])}
        meta.update(osv_meta)
        caps = res.get("capabilities")
        if caps: meta["capabilities"] = caps
        if res.get("coverage"): meta["coverage"] = res["coverage"]
        if getattr(a, "trace", False):
            if a.no_docker or not docker_ok():
                notes.append("trace: skipped (needs Docker; --trace runs the install phase in the hardened container)")
            else:
                try:
                    evidence, trace_info = run_trace(src, Path(work) / "trace",
                                                     timeout=getattr(a, "trace_timeout", None) or None)
                except Exception as ex:
                    notes.append(f"trace: failed: {type(ex).__name__}: {ex}")
                else:
                    meta["trace"] = trace_info
                    if evidence:
                        meta["capabilities"] = scan_capabilities(src, trace=evidence)
                        verified = sum(len(v) for v in evidence.values())
                        evidence_counts = ", ".join(f"{k} {len(v)}" for k, v in evidence.items())
                        notes.append(f"trace: {len(trace_info['commands'])} install command(s), "
                                     f"{verified} evidence value(s) ({evidence_counts}); "
                                     f"connect/execve/openat {trace_info['syscalls']['connect']}/"
                                     f"{trace_info['syscalls']['execve']}/{trace_info['syscalls']['openat']}")
                        findings.append(finding("agent-checks", "info", "(trace)", 0,
                                                 f"trace-verified: {verified} capability value(s) confirmed",
                                                 evidence_counts, "The install phase was executed under strace in the "
                                                                  "hardened container; these capabilities were observed, "
                                                                  "not inferred."))
                    else:
                        notes.append("trace: the commands ran but produced no recognised evidence")
        scope_file = Path(work) / "scope.json"
        if scope_file.exists():
            try:
                meta["scope"] = json.loads(scope_file.read_text())
                notes.append(f"scope: changed files only ({meta['scope']['changed_files']} changed since "
                             f"{meta['scope']['since']}); findings elsewhere in the repo are not re-reported")
            except (OSError, ValueError):
                pass
        if summary:
            meta["privacy_summary"] = summary
            meta["privacy_profile"] = privacy_profile(summary)
        render_report(meta, active, v, why, counts, notes, ai, color_enabled() and not a.no_color,
               10**6 if a.all else 40, getattr(a, "min_severity", "info"))
        report_data = {"version": VERSION, "verdict": v, "why": why, "counts": counts, "meta": meta,
                       "privacy_summary": summary, "ai_review": ai, "findings": active + suppressed,
                       "raw_findings_count": raw_count, "notes": notes, "recommended_actions": ACTIONS[v]}
        if a.json:
            Path(a.json).write_text(json.dumps(report_data, indent=2))
            print(f"[repobeagle] JSON written to {a.json}", file=sys.stderr)
        if getattr(a, "html", None):
            Path(a.html).write_text(html_report(report_data))
            print(f"[repobeagle] HTML written to {a.html}", file=sys.stderr)
        if getattr(a, "sbom", None):
            Path(a.sbom).write_text(json.dumps(sbom_report(src, report_data), indent=2))
            print(f"[repobeagle] CycloneDX SBOM written to {a.sbom}", file=sys.stderr)
        if a.keep:
            print(f"[repobeagle] kept clone at {src}", file=sys.stderr)
        if baseline is not None:
            bm = baseline.get("meta") or {}
            if bm.get("ruleset") and bm["ruleset"] != RULESET:
                print(f"[repobeagle] baseline ruleset {bm['ruleset']} differs from this scanner ({RULESET}); "
                      "rule changes may show up as added/removed", file=sys.stderr)
            thr = getattr(a, "baseline_min_severity", "medium")
            gated, added, removed, old_n, new_n = gate_findings(
                baseline, {"findings": active + suppressed}, thr)
            print(f"[repobeagle] baseline {a.baseline}: findings {old_n}; current findings {new_n}; "
                  f"added {len(added)}, removed {len(removed)} (rule + file matching; line moves are not changes)",
                  file=sys.stderr)
            for f in gated[:20]:
                loc = f"{f.get('file')}:{f.get('line')}" if f.get("line") else str(f.get("file"))
                print(f"[repobeagle]   new {str(f.get('severity', '?')).upper()} {f.get('title')} [{loc}]", file=sys.stderr)
            if len(gated) > 20:
                print(f"[repobeagle]   ... {len(gated) - 20} more new finding(s)", file=sys.stderr)
            if gated:
                print(f"[repobeagle] gate: {len(gated)} new finding(s) at/above {thr}", file=sys.stderr)
                return 1
            print(f"[repobeagle] gate: no new findings at/above {thr}", file=sys.stderr)
            return 0
        return {"GREEN": 0, "YELLOW": 1, "RED": 2}[v]
    finally:
        if work and not a.keep:
            shutil.rmtree(work, ignore_errors=True)
            _WORKDIRS.discard(work)


def _verify_rescan(a, d, slug, color):
    """Re-scans the report's pinned commit, with the report's image when recorded, and compares the normalized core.

    Returns an exit code (0 match, 1 failure, 3 mismatch) or None when the report has no pin.
    """
    meta = d.get("meta") or {}
    sha = str(meta.get("scanned_sha") or "")
    repo = slug or str(meta.get("scanned_repo") or "")
    if not (re.fullmatch(r"[0-9a-f]{40}", sha) and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo)):
        print("  rescan:    SKIPPED (the report has no pinned commit/repo; produced by an older workflow)")
        return None
    image, image_note = rescan_image(meta)
    print(f"  rescan:    {image_note}")
    recorded_digest = str(meta.get("image_digest") or "")
    if recorded_digest.startswith("sha256:"):
        local_digest = _local_image_digest(image)
        if local_digest and local_digest != recorded_digest:
            print(f"  warning:   the local {image} resolves to {local_digest}, but the report recorded {recorded_digest}")
    work = tempfile.mkdtemp(prefix="repobeagle-rescan-")
    try:
        out = Path(work) / "report.json"
        prof = str(meta.get("profile") or "balanced")
        if prof not in PROFILES:
            prof = "balanced"
        args = entry_command() + ["scan", f"https://github.com/{repo}",
                "--ref", sha, "--json", str(out), "--no-osv", "--no-trust", "--" + prof]
        mode = meta.get("privacy_mode")
        if mode == "only":
            args.append("--privacy-only")
        elif mode == "excluded":
            args.append("--no-privacy")
        if meta.get("scope"):
            print("  rescan:    note: the report scanned only changed files; the whole commit is rescanned here")
        print(f"  rescan:    scanning {repo}@{sha[:12]} ...")
        r = subprocess.run(args, capture_output=True, text=True, timeout=3600, env=dict(os.environ, BEAGLE_IMAGE=image))
        try:
            fresh = json.loads(out.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            tail = ((r.stderr or r.stdout).strip().splitlines() or [""])[-1]
            print(f"  rescan:    FAILED (scan exited {r.returncode}): {tail[:200]}")
            return 1
        fresh_mode = str((fresh.get("meta") or {}).get("mode") or "")
        if meta.get("mode") and fresh_mode and fresh_mode.split(" ")[0] != str(meta.get("mode")).split(" ")[0]:
            print(f"  warning:   the report was produced in {meta.get('mode')}; this rescan ran in {fresh_mode}")
        match, added, removed = rescan_difference(d, fresh)
        signed_fp = report_fingerprint(d, offline_only=True)
        fresh_fp = report_fingerprint(fresh, offline_only=True)
        if match:
            print(f"  rescan:    {color('1;42;30', 'MATCH')} (normalized core {fresh_fp[:16]})")
            return 0
        print(f"  rescan:    {color('1;43;30', 'DIFFERENT')} (signed {signed_fp[:16]} vs rescan {fresh_fp[:16]}; "
              f"{len(added)} new, {len(removed)} fixed)")
        for f in added[:10]:
            print(f"               new  {str(f.get('severity')).upper()} {f.get('title')} "
                  f"[{f.get('file')}:{f.get('line')}]")
        for f in removed[:10]:
            print(f"               gone {str(f.get('severity')).upper()} {f.get('title')} "
                  f"[{f.get('file')}:{f.get('line')}]")
        return 3
    finally:
        shutil.rmtree(work, ignore_errors=True)


def cmd_verify(a):
    """Check that a published badge report is authentic and current. Exits 0/1/2 (3 with --rescan mismatch)."""
    print(banner(color_enabled(sys.stderr) and not a.no_color), file=sys.stderr)   # stderr keeps stdout reports clean
    if not ((a.report and a.bundle) or a.target):
        print("verify: give a github repo (slug or URL), or local --report + --bundle files", file=sys.stderr)
        return 1
    cosign = _ensure_cosign()
    if not cosign:
        print("verify: could not install cosign; install it manually (https://github.com/sigstore/cosign) or run ./install.sh", file=sys.stderr)
        return 1
    slug = None
    if a.target:
        m = GITHUB_REPO_RE.match(a.target)
        slug = f"{m.group(1)}/{m.group(2)}" if m else (a.target if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", a.target) else None)
        if not slug:
            print(f"verify: cannot parse a github repo out of {a.target!r}", file=sys.stderr)
            return 1
    work = tempfile.mkdtemp(prefix="repobeagle-verify-")
    try:
        if a.report and a.bundle:
            report_path, bundle_path = a.report, a.bundle
        else:
            report_path = os.path.join(work, "report.json")
            bundle_path = os.path.join(work, "report.sigstore.json")
            try:
                _fetch_badge_file(slug, a.branch, "report.json", report_path)
                _fetch_badge_file(slug, a.branch, "report.sigstore.json", bundle_path)
            except Exception as ex:
                print(f"verify: cannot fetch report from {slug}@{a.branch} ({str(ex)[:140]})", file=sys.stderr)
                return 1
        sig_cmd = [cosign, "verify-blob", "--bundle", bundle_path]
        if getattr(a, "key", None):
            sig_cmd.extend(["--key", a.key, "--insecure-ignore-tlog=true"])
        else:
            sig_cmd.extend(["--certificate-identity-regexp", a.identity_regexp,
                            "--certificate-oidc-issuer", VERIFY_ISSUER])
        r = subprocess.run(sig_cmd + [report_path], capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            print("verify: SIGNATURE INVALID", file=sys.stderr)
            errs, seen, uniq = (r.stderr or r.stdout).strip().splitlines(), set(), []
            for ln in errs:
                k = re.sub(r"^(Error: |error during command execution: )+", "", ln.strip())
                if k and k not in seen:
                    seen.add(k); uniq.append(ln.strip())
            print("\n".join(uniq[-3:]) or "(cosign produced no error output)", file=sys.stderr)
            return 1
        try:
            d = json.load(open(report_path, encoding="utf-8"))
        except (OSError, ValueError) as ex:
            print(f"verify: unreadable report: {ex}", file=sys.stderr)
            return 1
        v, c, meta = d.get("verdict"), d.get("counts", {}), d.get("meta", {})
        scanned_repo = str(meta.get("scanned_repo", ""))
        if a.target and scanned_repo and scanned_repo != slug:
            print(f"verify: REJECTED - report was produced for {scanned_repo}, not {slug}", file=sys.stderr)
            return 1
        use_color = color_enabled() and not a.no_color
        C = (lambda code, s: f"\033[{code}m{s}\033[0m") if use_color else (lambda code, s: s)
        print(f"repobeagle verify: {a.target or '(local files)'} (branch {a.branch})")
        print(f"  signature: {C('1;42;30', 'VALID')}  policy: "
              + (f"local key ({a.key})" if getattr(a, "key", None) else "official scan/service/index workflow (main or v* tag)"))
        print(f"  report:    {C({'GREEN': '1;42;30', 'YELLOW': '1;43;30', 'RED': '1;41;97'}.get(v, '1'), str(v))}"
              f"  {c.get('critical', 0)} critical / {c.get('high', 0)} high / {c.get('medium', 0)} medium / {c.get('low', 0)} low")
        scanned = str(meta.get("scanned_sha", ""))
        if scanned:
            print(f"  scanned:   {scanned[:12]} at {meta.get('scanned_repo', '?')} (image {meta.get('image_ref', '?')})")
        print(f"  snippets:  {'redacted by scanner' if meta.get('pii_redacted') else 'raw'}")
        mode = meta.get("privacy_mode")
        if mode:
            print(f"  scope:     {mode} (privacy findings only)" if mode == "only" else
                  f"  scope:     {mode} (privacy findings excluded)" if mode == "excluded" else "  scope:     full")
        if not privacy_mode_consistent(d):
            print(f"  warning:   findings do not match meta.privacy_mode={mode!r}")
        if not privacy_summary_consistent(d):
            print("  warning:   privacy_summary does not match the findings")
        if not verdict_consistent(d):
            print("  warning:   verdict/counts do not match the findings")
        rs_v = (d.get("meta") or {}).get("ruleset")
        if rs_v and rs_v != RULESET:
            print(f"  warning:   report ruleset {rs_v} differs from this scanner ({RULESET}); rules changed since the report")
        drift = toolchain_drift((d.get("meta") or {}).get("tools"), toolchain_pins())
        if drift:
            print(f"  warning:   report toolchain differs from the pinned image ({', '.join(drift)}); "
                  "re-scan with this image to compare verdicts")
        dbm = (d.get("meta") or {}).get("osv_db")
        if isinstance(dbm, dict):
            warning = osv_db_warning(d.get("meta"))
            if warning:
                print(f"  warning:   {warning}")
        summary = d.get("privacy_summary") or privacy_summary(d.get("findings") or [])
        if summary:
            parts = []
            for group, vals in summary.items():
                if isinstance(vals, dict):
                    n = sum(len(v) for v in vals.values())
                    parts.append(f"{group} {n}")
                else:
                    parts.append(f"{group} {len(vals)}")
            print(f"  privacy:   {', '.join(parts)}  (details in report.json)")
        head = a.expect_sha or None
        if head is None and a.target:
            g = subprocess.run(["git", "ls-remote", f"https://github.com/{slug}.git", "HEAD"],
                               capture_output=True, text=True, timeout=60)
            if g.returncode == 0 and g.stdout.strip():
                head = g.stdout.split()[0]
            else:
                print(f"  freshness: UNKNOWN (could not read HEAD of {slug})")
        fresh_rc = 0
        if head and scanned:
            if scanned[:12] == head[:12]:
                print(f"  freshness: {C('1;42;30', 'UP TO DATE')} (HEAD {head[:12]})")
            else:
                print(f"  freshness: {C('1;43;30', 'STALE')} (report is for {scanned[:12]}, HEAD is {head[:12]})")
                fresh_rc = 2
        elif not scanned:
            print("  freshness: UNKNOWN (report has no meta.scanned_sha; produced by an older workflow)")
        if getattr(a, "rescan", False):
            rc = _verify_rescan(a, d, slug, C)
            if rc is not None:
                return rc
        return fresh_rc
    finally:
        shutil.rmtree(work, ignore_errors=True)


def image_problem():
    """Explain why the configured image may not match the installed code."""
    if "jvr0x" in IMAGE:
        return "the wrapper still exports the old jvr0x image"
    tag = IMAGE.rsplit("/", 1)[-1]
    if ":" in tag and RELEASE and not IMAGE.endswith(":" + RELEASE):
        return f"image tag {tag.split(':', 1)[1]!r} does not match the installed code ({RELEASE})"
    return None


def _parse_ver(v):
    m = re.match(r"v?(\d+)\.(\d+)\.(\d+)$", v or "")
    return tuple(map(int, m.groups())) if m else None


def latest_release(timeout=4):
    req = urllib.request.Request("https://api.github.com/repos/javierbits/repobeagle/releases/latest",
                                 headers={"User-Agent": "repobeagle", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode()).get("tag_name", "")


def update_available(force=False):
    """Latest release tag when newer than this install; cached for a day. None offline/disabled."""
    if os.environ.get("BEAGLE_NO_UPDATE_CHECK"):
        return None
    cache = os.path.join(os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache")), "repobeagle", "update.json")
    try:
        with open(cache, encoding="utf-8") as fh:
            cached = json.load(fh)
    except (OSError, ValueError):
        cached = {}
    try:
        fresh = force or time.time() - float(cached.get("ts", 0)) >= float(os.environ.get("BEAGLE_UPDATE_INTERVAL", 86400))
    except (TypeError, ValueError):
        fresh = True
    latest = None if fresh else cached.get("latest")
    if fresh:
        try:
            latest = latest_release()
        except Exception:
            return None
        try:
            os.makedirs(os.path.dirname(cache), exist_ok=True)
            with open(cache, "w", encoding="utf-8") as fh:
                json.dump({"ts": time.time(), "latest": latest}, fh)
        except OSError:
            pass
    cur, new = _parse_ver(VERSION), _parse_ver(latest)
    return latest if cur and new and new > cur else None


def _docker_ok():
    return bool(shutil.which("docker")) and subprocess.run(["docker", "info"], capture_output=True).returncode == 0


def _pull_image(tag):
    if not tag:
        return False
    if not _docker_ok():
        print("[repobeagle] docker unavailable: skipped image pull")
        return False
    ref = f"ghcr.io/javierbits/repobeagle:{tag}"
    print(f"[repobeagle] pulling {ref}")
    return subprocess.call(["docker", "pull", ref]) == 0


def _retarget_wrapper(tag):
    """Point an installed wrapper at another image tag (only its default; BEAGLE_IMAGE still wins)."""
    wrapper = Path(os.environ.get("BEAGLE_BIN", os.path.expanduser("~/.local/bin"))) / "repobeagle"
    try:
        text = wrapper.read_text(encoding="utf-8")
    except OSError:
        return False
    line = f'export BEAGLE_IMAGE="${{BEAGLE_IMAGE:-ghcr.io/javierbits/repobeagle:{tag}}}"'
    new = re.sub(r"(?m)^export BEAGLE_IMAGE=.*$", lambda m: line, text)
    if new == text:
        return False
    try:
        wrapper.write_text(new, encoding="utf-8")
    except OSError:
        return False
    print(f"[repobeagle] wrapper default image set to {tag}")
    return True


def _disk_version(repo):
    try:
        return (repo / "VERSION").read_text(encoding="utf-8").strip().lstrip("v")
    except OSError:
        return ""


def cmd_update(a):
    repo = Path(__file__).resolve().parent.parent
    try:
        latest = latest_release()
    except Exception:
        latest = ""
    if a.check:
        print(f"installed: {VERSION}")
        print(f"latest:    {latest or 'unknown'}")
        new = _parse_ver(latest)
        return 10 if new and _parse_ver(VERSION) and new > _parse_ver(VERSION) else 0
    new, cur = _parse_ver(latest), _parse_ver(VERSION)
    stale = bool(new and cur and new > cur)
    rc = 0
    if (repo / ".git").exists() and shutil.which("git"):
        print(f"[repobeagle] pulling {repo}")
        subprocess.call(["git", "-C", str(repo), "pull", "--ff-only"])
    installer = repo / "install.sh"
    if stale and installer.exists():
        print(f"[repobeagle] installing {latest}")
        rc = subprocess.call(["bash", str(installer)])
    tag = latest or RELEASE
    pulled = _pull_image(tag)
    if (stale and _disk_version(repo) < (latest or "").lstrip("v")) or image_problem():
        # stale/unreadable checkout, stale handle, or the wrapper's tag is wrong
        _retarget_wrapper(tag)
    if not stale:
        print(f"[repobeagle] up to date ({VERSION})" + ("; image refreshed" if pulled else ""))
    elif not installer.exists():
        print(f"[repobeagle] code is still {VERSION}; run ./install.sh in your checkout to update the CLI")
    if os.environ.get("BEAGLE_IMAGE"):
        print(f"[repobeagle] note: BEAGLE_IMAGE={os.environ['BEAGLE_IMAGE']} overrides the wrapper default")
    return rc


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "_inner":
        inner(sys.argv[2], sys.argv[3]); return 0
    if "--version" in sys.argv[1:] or "-V" in sys.argv[1:]:
        envimg = os.environ.get("BEAGLE_IMAGE")
        default = f"ghcr.io/javierbits/repobeagle:{RELEASE}"
        src = " (BEAGLE_IMAGE set)" if envimg and envimg != default else ""
        print(f"RepoBeagle {VERSION}\nimage: {IMAGE}{src}")
        problem = image_problem()
        if problem:
            print(f"warning: {problem}; run ./install.sh to refresh the wrapper", file=sys.stderr)
        return 0
    if "--list-personas" in sys.argv[1:]:
        print_personas()
        return 0
    ap = argparse.ArgumentParser(prog="repobeagle", description="RepoBeagle: Static safety gate for untrusted repos (never executes repo code).")
    ap.add_argument("--list-personas", action="store_true", help="print the --as severity lenses and exit")
    sp = ap.add_subparsers(dest="cmd", required=True)
    def add_scan_args(s, privacy_modes=True):
        s.add_argument("target")
        s.add_argument("--ref", metavar="REV", help="git branch, tag or commit to scan (default: the remote's default branch)")
        s.add_argument("--since", metavar="REV", help="only scan files changed since this revision (requires a git URL)")
        g = s.add_mutually_exclusive_group()
        g.add_argument("--strict", action="store_true"); g.add_argument("--balanced", action="store_true"); g.add_argument("--relaxed", action="store_true")
        s.add_argument("--keep", action="store_true", help="keep the temp clone")
        s.add_argument("--json", metavar="FILE")
        s.add_argument("--as", dest="as_persona", choices=sorted(PERSONAS), metavar="PERSONA",
                       help="severity lens: " + ", ".join(sorted(PERSONAS)) + " (see --list-personas)")
        s.add_argument("--trace", action="store_true",
                       help="also run the install phase in the hardened container under strace and mark capabilities it "
                            "confirms (executes repo code; needs Docker and network for downloads)")
        s.add_argument("--trace-timeout", type=int, metavar="SECONDS", help="timeout for the trace run (default 300)")
        s.add_argument("--release-assets", metavar="OWNER/REPO",
                       help="also download, extract and scan the archive assets of this repo's latest GitHub release")
        s.add_argument("--jobs", type=int, default=4, metavar="N",
                       help="run the four external scanners concurrently (default 4; 1 = sequential)")
        s.add_argument("--no-cache", action="store_true",
                       help="ignore the content-addressed analysis cache (meta.cache=disabled)")
        s.add_argument("--max-seconds", type=float, metavar="SECONDS",
                       help="analysis budget after the tree is fetched: an unfinished scan is written as a partial report "
                            "(meta.complete=false, verdict floor YELLOW)")
        s.add_argument("--html", metavar="FILE", help="write a self-contained HTML report")
        s.add_argument("--sbom", metavar="FILE", help="write a CycloneDX 1.6 SBOM from the scanned lockfiles")
        s.add_argument("--no-docker", action="store_true", help="run scanners locally instead of in the container")
        s.add_argument("--no-osv", action="store_true", help="skip OSV (avoids sending package names to osv.dev)")
        s.add_argument("--offline-vulnerabilities", action="store_true",
                       help="use the local OSV database instead of osv.dev (see 'repobeagle db')")
        s.add_argument("--verify-deps", action="store_true", help="GuardDog-verify deps from requirements.txt/package.json (downloads packages, static only)")
        s.add_argument("--no-trust", action="store_true", help="skip GitHub trust signals (unauthenticated public API)")
        s.add_argument("--all", action="store_true", help="print all findings")
        s.add_argument("--min-severity", choices=list(SEV_ORDER), default="info",
                       help="only print findings at/above this severity (JSON keeps all)")
        s.add_argument("--baseline", metavar="REPORT",
                       help="gate the scan against a stored report: exit 1 only when findings were added at/above "
                            "--baseline-min-severity (rule + file matching; the verdict code is then not used)")
        s.add_argument("--baseline-min-severity", choices=list(SEV_ORDER), default="medium",
                       help="severity of an added finding that fails --baseline (default: medium)")
        s.add_argument("--no-redact", action="store_true", help="show raw emails/phones/cards in privacy finding snippets")
        if privacy_modes:
            pv = s.add_mutually_exclusive_group()
            pv.add_argument("--privacy-only", action="store_true", help="report only privacy/telemetry findings")
            pv.add_argument("--no-privacy", action="store_true", help="drop privacy/telemetry findings")
        s.add_argument("--no-color", action="store_true")

    s = sp.add_parser("scan", help="scan a git URL or local directory")
    add_scan_args(s)
    pr = sp.add_parser("privacy", help="privacy audit: report only privacy/telemetry findings")
    add_scan_args(pr, privacy_modes=False)
    v = sp.add_parser("verify", help="verify a published repobeagle badge (signature + freshness); exit 0 valid/current, 1 invalid, 2 stale")
    v.add_argument("target", nargs="?", help="github repo slug or URL whose repobeagle branch holds the badge")
    v.add_argument("--branch", default="repobeagle", help="badge branch name (default: repobeagle)")
    v.add_argument("--report", help="local report.json instead of fetching")
    v.add_argument("--bundle", help="local report.sigstore.json instead of fetching")
    v.add_argument("--expect-sha", help="commit SHA the report must cover (default: HEAD of the target repo)")
    v.add_argument("--identity-regexp", default=VERIFY_IDENTITY, help="allowed signing workflow identity")
    v.add_argument("--key", metavar="FILE", help="verify a report signed with a local cosign key instead of a workflow identity")
    v.add_argument("--rescan", action="store_true",
                   help="re-scan the report's pinned commit with this install and compare the normalized findings "
                        "(offline stages; exit 3 when they differ)")
    v.add_argument("--no-color", action="store_true")
    ini = sp.add_parser("init", help="write the reusable-workflow file and print the shield lines")
    ini.add_argument("target", nargs="?", default=".", help="repository directory (default: .)")
    ini.add_argument("--out", help="workflow path (default: <target>/.github/workflows/repobeagle.yml)")
    ini.add_argument("--repo", metavar="OWNER/NAME", help="slug for the printed badge URL (default: origin remote)")
    ini.add_argument("--profile", choices=["strict", "balanced", "relaxed"], default="balanced")
    ini.add_argument("--fail-on-red", action="store_true", help="fail the job on a RED verdict")
    ini.add_argument("--privacy-only", action="store_true")
    ini.add_argument("--badge-branch", default="repobeagle", help="badge branch (empty disables publishing)")
    ini.add_argument("--set-status", action="store_true", default=True, help="set the repobeagle/scan commit status (default: on)")
    ini.add_argument("--tools-ref", metavar="REF", help=f"repobeagle toolchain ref to pin (default: {RELEASE})")
    ini.add_argument("--dry-run", action="store_true", help="print the workflow instead of writing it")
    ini.add_argument("--force", action="store_true", help="replace an existing workflow with different content")
    ig = sp.add_parser("ignore", help="add, update or list .repobeagleignore entries (rule [# reason] [@YYYY-MM-DD])")
    ig.add_argument("rule", nargs="?", help="rule id or glob to suppress; omit with --list")
    ig.add_argument("--reason", default="", help="why the finding is accepted (stored after #)")
    ig.add_argument("--until", metavar="YYYY-MM-DD", help="expiry date: the entry stops suppressing after it")
    ig.add_argument("--file", default=SUPPRESS_FILE, help=f"file to edit (default: {SUPPRESS_FILE})")
    ig.add_argument("--list", action="store_true", help="show entries and whether they are active or expired")
    ig.add_argument("--report", metavar="FILE", help="fail when no finding in this report matches the rule")
    ig.add_argument("--json", metavar="FILE")
    ig.add_argument("--no-color", action="store_true")
    hd = sp.add_parser("head", help="fast metadata-only triage (GitHub contents API or a local dir): no clone, no scanners")
    hd.add_argument("target", help="owner/repo, GitHub URL, or local directory")
    hg = hd.add_mutually_exclusive_group()
    hg.add_argument("--strict", action="store_true"); hg.add_argument("--relaxed", action="store_true")
    hd.add_argument("--as", dest="as_persona", choices=sorted(PERSONAS), metavar="PERSONA")
    hd.add_argument("--json", metavar="FILE")
    hd.add_argument("--html", metavar="FILE", help="write a self-contained HTML report")
    hd.add_argument("--markdown", action="store_true", help="print a Markdown card (Slack/Discord/PR comment)")
    hd.add_argument("--no-cache", action="store_true", help="ignore the per-slug response cache")
    hd.add_argument("--all", action="store_true")
    hd.add_argument("--min-severity", choices=list(SEV_ORDER), default="info")
    hd.add_argument("--no-color", action="store_true")
    fx = sp.add_parser("fix", help="rewrite the mechanical findings in a local checkout (unpinned actions, write-all permissions)")
    fx.add_argument("target", help="local directory to edit (fix never clones; a URL is rejected)")
    fx.add_argument("--dry-run", action="store_true", help="print the unified diff and write nothing")
    fx.add_argument("--pins", metavar="FILE", help="JSON {owner/repo@ref: sha} overrides (airgapped runs and tests)")
    fx.add_argument("--no-network", action="store_true", help="only use --pins; never call the GitHub API")
    fx.add_argument("--json", metavar="FILE")
    fx.add_argument("--no-color", action="store_true")
    ex = sp.add_parser("explain", help="explain how a stored report's verdict follows from its profile thresholds")
    ex.add_argument("report", help="report.json produced by 'scan --json'")
    ex.add_argument("--accept", nargs="+", metavar="RULE", default=[],
                    help="simulate accepting these rule ids or globs and print the verdict after (no re-scan)")
    ex.add_argument("--target", choices=["green", "yellow"],
                    help="plan the smallest set of whole rules to accept (least severe first) to reach this verdict")
    ex.add_argument("--write", action="store_true",
                    help="append the accepted/planned rules to the ignore file, with a reason comment")
    ex.add_argument("--ignore-file", default=SUPPRESS_FILE, metavar="FILE",
                    help=f"file written by --write (default: {SUPPRESS_FILE})")
    ex.add_argument("--reason", default="reviewed with repobeagle explain --write",
                    help="reason comment stored by --write")
    df = sp.add_parser("diff", help="compare two stored reports; exit 1 when the change added findings at/above --min-severity")
    df.add_argument("old", help="baseline report.json")
    df.add_argument("new", help="current report.json")
    df.add_argument("--min-severity", choices=list(SEV_ORDER), default="medium",
                    help="fail when an added finding is at/above this severity (default: medium)")
    df.add_argument("--json", metavar="FILE", help="write the added/removed findings as JSON")
    df.add_argument("--no-color", action="store_true")
    tr = sp.add_parser("trend", help="verdict/rule history from the per-SHA reports on a badge branch (or local report files)")
    tr.add_argument("target", nargs="+", help="github repo slug/URL, a directory of report-*.json, or report files")
    tr.add_argument("--branch", default="repobeagle", help="badge branch to read (default: repobeagle)")
    tr.add_argument("--limit", type=int, default=100, metavar="N",
                    help="maximum published reports to read (default: 100)")
    tr.add_argument("--json", metavar="FILE", help="write the ordered series and regressions as JSON")
    tr.add_argument("--no-color", action="store_true")
    sv = sp.add_parser("serve", help="hosted attestation service: immutable per-SHA reports, per-IP/per-repo budgets, optional Sigstore signing")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8080, help="TCP port (0 = ephemeral; the chosen port is printed)")
    sv.add_argument("--cache", metavar="DIR", help="report cache (default: <XDG_CACHE_HOME>/repobeagle/service)")
    sv.add_argument("--root", metavar="DIR", help="also serve local repositories as local/<directory>")
    sv.add_argument("--ip-budget", type=int, default=30, metavar="N", help="requests per IP per hour (0 = unlimited)")
    sv.add_argument("--repo-budget", type=int, default=20, metavar="N", help="scans per repository per hour (0 = unlimited)")
    sv.add_argument("--concurrency", type=int, default=1, metavar="N", help="scans running at once (default: 1)")
    sv.add_argument("--timeout", type=int, default=1800, metavar="SECONDS", help="per-scan timeout")
    sv.add_argument("--sign", action="store_true",
                    help="sign reports with Sigstore (keyless under GitHub OIDC, or with --key)")
    sv.add_argument("--key", metavar="FILE", help="cosign private key used by --sign")
    sv.add_argument("--profile", choices=["strict", "balanced", "relaxed"], default="balanced")
    sv.add_argument("--no-docker", action="store_true", help="scan locally in the service process instead of via the pinned image")
    sv.add_argument("--no-osv", action="store_true", help="skip OSV vulnerability lookups")
    sv.add_argument("--no-trust", action="store_true", help="skip GitHub trust signals")
    sv.add_argument("--privacy-only", action="store_true", help="report only privacy/telemetry findings")
    sv.add_argument("--jobs", type=int, default=1, metavar="N", help="scanner concurrency per scan")
    ap_ = sp.add_parser("app", help="GitHub App webhook server: static scan, one updated PR comment, one check run per commit")
    ap_.add_argument("--host", default="127.0.0.1")
    ap_.add_argument("--port", type=int, default=8080, help="TCP port (0 = ephemeral; the chosen port is printed)")
    ap_.add_argument("--secret", metavar="TEXT", help="webhook secret (or BEAGLE_APP_WEBHOOK_SECRET)")
    ap_.add_argument("--app-id", metavar="ID", help="GitHub App id (or BEAGLE_APP_ID)")
    ap_.add_argument("--private-key", metavar="FILE", help="App private key PEM (or BEAGLE_APP_PRIVATE_KEY)")
    ap_.add_argument("--token", metavar="TOKEN", help="static installation token (or BEAGLE_INSTALLATION_TOKEN) for single-install deployments and tests")
    ap_.add_argument("--api-url", metavar="URL", help="GitHub API base (or BEAGLE_GITHUB_API; default https://api.github.com)")
    ap_.add_argument("--root", metavar="DIR", help="serve local repositories as local/<directory> (tests and self-hosting)")
    ap_.add_argument("--concurrency", type=int, default=1, metavar="N", help="webhook workers (default: 1)")
    ap_.add_argument("--timeout", type=int, default=1800, metavar="SECONDS", help="per-scan timeout")
    ap_.add_argument("--profile", choices=["strict", "balanced", "relaxed"], default="balanced")
    ap_.add_argument("--no-docker", action="store_true", help="scan locally instead of via the pinned image")
    ap_.add_argument("--no-osv", action="store_true", help="skip OSV vulnerability lookups")
    ap_.add_argument("--no-trust", action="store_true", help="skip GitHub trust signals")
    ap_.add_argument("--privacy-only", action="store_true", help="report only privacy/telemetry findings")
    ap_.add_argument("--jobs", type=int, default=1, metavar="N", help="scanner concurrency per scan")
    ix = sp.add_parser("index", help="build the static signed index: curated repositories -> results + searchable Pages site")
    ix.add_argument("entries", nargs="*", help="owner/repo or existing directory entries")
    ix.add_argument("--repos", metavar="FILE", help="file with one entry per line ('#' comments)")
    ix.add_argument("--out", default="public", metavar="DIR", help="output directory for the Pages artifact")
    ix.add_argument("--jobs", type=int, default=4, metavar="N", help="parallel scans (default: 4)")
    ix.add_argument("--cap", type=int, default=1000, metavar="N", help="maximum entries per run (0 = no cap)")
    ix.add_argument("--sign", action="store_true", help="sign every report with Sigstore (keyless under GitHub OIDC, or --key)")
    ix.add_argument("--key", metavar="FILE", help="cosign private key used by --sign")
    ix.add_argument("--profile", choices=["strict", "balanced", "relaxed"], default="balanced")
    ix.add_argument("--no-docker", action="store_true", help="scan locally instead of via the pinned image")
    ix.add_argument("--no-osv", action="store_true", help="skip OSV vulnerability lookups")
    ix.add_argument("--no-trust", action="store_true", help="skip GitHub trust signals")
    ix.add_argument("--privacy-only", action="store_true", help="report only privacy/telemetry findings")
    ix.add_argument("--timeout", type=int, default=1800, metavar="SECONDS", help="per-scan timeout")
    ix.add_argument("--json", metavar="FILE", help="write the run summary as JSON")
    rl = sp.add_parser("release", help="compare a published registry artifact with the repository at its release tag")
    rl.add_argument("slug", help="owner/repo of the source repository")
    rl.add_argument("--tag", help="release tag to compare (default: latest GitHub release)")
    rl.add_argument("--package", metavar="NAME", help="registry package name (default: the repo manifest's name)")
    rl.add_argument("--ecosystem", choices=["auto", "npm", "pypi", "crates"], default="auto")
    rl.add_argument("--version", metavar="VERSION", help="registry version (default: latest published)")
    rl.add_argument("--repo", metavar="DIR", help="local checkout of the tag instead of cloning it")
    rl.add_argument("--tarball", metavar="FILE", help="local registry artifact instead of downloading it")
    rl.add_argument("--registry-json", metavar="FILE", help="local registry metadata instead of fetching it")
    rl.add_argument("--json", metavar="FILE", help="write the comparison as JSON")
    xp = sp.add_parser("export", help="convert a stored report to SARIF (code scanning), Markdown or JSON")
    xp.add_argument("report", help="report.json produced by 'scan --json'")
    xp.add_argument("--format", choices=["sarif", "markdown", "html", "json"], default="sarif")
    xp.add_argument("-o", "--out", metavar="FILE", help="write to FILE instead of stdout")
    sp.add_parser("mcp", help="run an MCP server over stdio: scan_repo, verify_badge, explain_report")
    mp = sp.add_parser("map", help="show what a repo can touch: hosts, secret paths, subprocesses, env vars, storage, hooks")
    mp.add_argument("target", nargs="?", help="git URL or local directory")
    mp.add_argument("--report", metavar="FILE", help="render an existing report.json instead of scanning")
    mp.add_argument("--ref", metavar="REV", help="git branch, tag or commit to scan (requires a git URL)")
    mp.add_argument("--all", action="store_true", help="also list documentation/test-only entries (hidden by default)")
    g = mp.add_mutually_exclusive_group()
    g.add_argument("--strict", action="store_true"); g.add_argument("--relaxed", action="store_true")
    mp.add_argument("--network", action="store_true", help="also run OSV and GitHub trust lookups (slower; the map itself is offline)")
    mp.add_argument("--no-docker", action="store_true")
    wb = sp.add_parser("web", help="privacy audit of a live page: fetched once, never executes its JavaScript")
    wb.add_argument("url", help="http(s):// or file:// URL")
    wb.add_argument("--assets", type=int, default=0, metavar="N", help="also fetch up to N same-origin scripts/stylesheets (default 0)")
    g = wb.add_mutually_exclusive_group()
    g.add_argument("--strict", action="store_true"); g.add_argument("--relaxed", action="store_true")
    wb.add_argument("--json", metavar="FILE")
    wb.add_argument("--all", action="store_true", help="print all findings")
    wb.add_argument("--min-severity", choices=list(SEV_ORDER), default="info")
    wb.add_argument("--no-color", action="store_true")
    wb.add_argument("--timeout", type=int, default=20, metavar="SECONDS")
    dbp = sp.add_parser("db", help="show or refresh the local OSV offline vulnerability database")
    dbp.add_argument("target", nargs="?", default=".", help="directory whose ecosystems to download (default: .)")
    dbp.add_argument("--update", action="store_true", help="download/refresh the database (needs network)")
    ap.add_argument("-V", "--version", action="store_true", help="print the installed version and image tag")
    sp.add_parser("version")
    ru = sp.add_parser("rules", help="lint .repobeagle/rules packs and run their positive/negative fixtures")
    rsub = ru.add_subparsers(dest="rules_cmd", required=True)
    for cmd_name, hlp in (("lint", "validate the pack schema, regex anchoring and backtracking safety"),
                          ("test", "run every rule's positive fixtures (must fire) and negative fixtures (must not)")):
        rcmd = rsub.add_parser(cmd_name, help=hlp)
        rcmd.add_argument("path", nargs="+", help="pack file(s) or directories to search for *.yml/*.yaml")
    rn = sp.add_parser("run", help="scan the package behind a runner command, then run it (or refuse)")
    rn.add_argument("--repo", metavar="TARGET", help="skip the registry lookup: owner/repo, URL or local dir")
    rn.add_argument("--dry-run", action="store_true", help="scan and print the verdict without executing")
    rn.add_argument("--yes", action="store_true", help="approve a YELLOW verdict without prompting (never overrides RED)")
    rn.add_argument("--force", action="store_true", help="run even on YELLOW/RED (recorded in the output)")
    rg = rn.add_mutually_exclusive_group()
    rg.add_argument("--strict", action="store_true"); rg.add_argument("--relaxed", action="store_true")
    rn.add_argument("--no-docker", action="store_true"); rn.add_argument("--no-osv", action="store_true")
    rn.add_argument("--offline-vulnerabilities", action="store_true")
    rn.add_argument("--no-trust", action="store_true"); rn.add_argument("--no-redact", action="store_true")
    rn.add_argument("--no-cache", action="store_true")
    rn.add_argument("--as", dest="as_persona", choices=sorted(PERSONAS), metavar="PERSONA")
    rn.add_argument("--max-seconds", type=float, metavar="SECONDS")
    rn.add_argument("--no-color", action="store_true")
    rn.add_argument("command", nargs=argparse.REMAINDER, help="-- the wrapped command (npx/pnpm dlx/yarn dlx/bunx/pipx run/uvx/cargo install)")
    ba = sp.add_parser("batch", help="full-scan every target in a listing, one report each, in parallel")
    ba.add_argument("targets", help="targets file: one git URL, owner/repo or local dir per line (# comments) or JSON")
    ba.add_argument("--jobs", type=int, default=4, metavar="N", help="targets scanned concurrently (default 4)")
    ba.add_argument("--json", metavar="DIR", default="repobeagle-batch", help="directory for the per-target reports and batch.json")
    bg = ba.add_mutually_exclusive_group()
    bg.add_argument("--strict", action="store_true"); bg.add_argument("--relaxed", action="store_true")
    ba.add_argument("--no-docker", action="store_true"); ba.add_argument("--no-osv", action="store_true")
    ba.add_argument("--offline-vulnerabilities", action="store_true")
    ba.add_argument("--no-trust", action="store_true"); ba.add_argument("--no-redact", action="store_true")
    ba.add_argument("--privacy-only", action="store_true"); ba.add_argument("--no-privacy", action="store_true")
    ba.add_argument("--min-severity", choices=list(SEV_ORDER), default=None)
    ba.add_argument("--max-seconds", type=float, metavar="SECONDS")
    ba.add_argument("--release-assets", metavar="OWNER/REPO")
    ba.add_argument("--no-cache", action="store_true")
    ba.add_argument("--as", dest="as_persona", choices=sorted(PERSONAS), metavar="PERSONA")
    ba.add_argument("--no-color", action="store_true")
    ga = sp.add_parser("gate", help="scan a directory listing (one target per line) and fail only on a new RED")
    ga.add_argument("entries", help="entries file: one owner/repo, git URL or local dir per line (# comments) or JSON")
    gg = ga.add_mutually_exclusive_group()
    gg.add_argument("--strict", action="store_true"); gg.add_argument("--relaxed", action="store_true")
    ga.add_argument("--as", dest="as_persona", choices=sorted(PERSONAS), metavar="PERSONA")
    ga.add_argument("--baseline", metavar="REPORT", help="previous gate JSON: fail only on entries RED now and not RED then")
    ga.add_argument("--json", metavar="FILE")
    ga.add_argument("--markdown", action="store_true", help="print the per-entry markdown table")
    ga.add_argument("--jobs", type=int, default=1, help="parallel metadata fetches (default 1; the head cache is shared)")
    ga.add_argument("--no-cache", action="store_true", help="bypass the GitHub metadata cache")
    ga.add_argument("--report-only", action="store_true", help="always exit 0 (dashboard mode)")
    ga.add_argument("--no-color", action="store_true")
    fb = sp.add_parser("feedback", help="open a prefilled, re-redacted GitHub issue for a finding")
    fb.add_argument("report")
    fg = fb.add_mutually_exclusive_group(required=True)
    fg.add_argument("--false-positive", action="store_true", help="the rule fired but the finding is not a problem")
    fg.add_argument("--miss", action="store_true", help="the rule missed a problem it should have reported")
    fb.add_argument("--rule", help="rule id to report (default: the report's only finding)")
    fb.add_argument("--file", help="file or file:line to disambiguate several findings of the rule")
    fb.add_argument("--attach", action="store_true", help="attach the full report JSON to the issue body")
    fb.add_argument("--repo", default=FEEDBACK_REPO, help="GitHub repository to open the issue in")
    fb.add_argument("--no-open", action="store_true", help="only print the URL; do not launch a browser")
    up = sp.add_parser("update", help="pull the latest release and reinstall")
    up.add_argument("--check", action="store_true", help="only report installed/latest and exit 10 when an update exists")
    a = ap.parse_args()
    if a.cmd == "privacy":
        a.privacy_only, a.no_privacy = True, False
        return cmd_scan(a)
    if a.cmd == "verify":
        return cmd_verify(a)
    if a.cmd == "head":
        return cmd_head(a)
    if a.cmd == "gate":
        return cmd_gate(a)
    if a.cmd == "batch":
        return cmd_batch(a)
    if a.cmd == "rules":
        return cmd_rules(a)
    if a.cmd == "run":
        return cmd_run(a)
    if a.cmd == "ignore":
        return cmd_ignore(a)
    if a.cmd == "init":
        return cmd_init(a)
    if a.cmd == "fix":
        return cmd_fix(a)
    if a.cmd == "explain":
        return cmd_explain(a)
    if a.cmd == "feedback":
        return cmd_feedback(a)
    if a.cmd == "diff":
        return cmd_diff(a)
    if a.cmd == "trend":
        return cmd_trend(a)
    if a.cmd == "serve":
        return cmd_serve(a)
    if a.cmd == "app":
        return cmd_app(a)
    if a.cmd == "index":
        return cmd_index(a)
    if a.cmd == "release":
        return cmd_release(a)
    if a.cmd == "export":
        return cmd_export(a)
    if a.cmd == "mcp":
        return mcp_server(a)
    if a.cmd == "map":
        return cmd_map(a)
    if a.cmd == "web":
        return cmd_web(a)
    if a.cmd == "db":
        return cmd_db(a)
    if a.cmd == "update":
        return cmd_update(a)
    if a.cmd == "version":
        print(VERSION); return 0
    problem = image_problem()
    if problem and a.cmd != "version":
        print(f"[repobeagle] warning: {problem}; run ./install.sh to refresh the wrapper", file=sys.stderr)
    newer = update_available()
    if newer:
        print(f"[repobeagle] update available: {newer} (installed {VERSION}) — run 'repobeagle update'", file=sys.stderr)
    _install_cleanup()
    return cmd_scan(a)