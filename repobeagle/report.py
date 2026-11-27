import argparse, base64, concurrent.futures, difflib, hashlib, hmac, json, os, platform, queue, re, shlex, shutil, signal, subprocess, sys, tempfile, threading, time, unicodedata, uuid, zipfile
import urllib.error, urllib.parse, urllib.request
from datetime import date, datetime, timezone
from fnmatch import fnmatchcase
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from pathlib import Path


# --- cross-module imports ---

from .core import SEV_ORDER, SUPPRESS_FILE, VERSION, _rule_of, finding, iter_files, privacy_profile, read_text, rel








_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def sarif_report(d):
    """Converts a stored report to SARIF 2.1.0 for GitHub code scanning and editors. Pure: never re-scans."""
    meta = d.get("meta") if isinstance(d.get("meta"), dict) else {}
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    fs = [f for f in (d.get("findings") or []) if isinstance(f, dict) and f.get("severity") in SEV_ORDER]
    fs.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f.get("file") or "", f.get("line") or 0))
    for f in fs:
        rule, sev = _rule_of(f), f["severity"]
        rules.setdefault(rule, {"id": rule, "name": rule, "shortDescription": {"text": rule},
                                 "defaultConfiguration": {"level": _SARIF_LEVEL[sev]}, "properties": {"severity": sev}})
        loc = {"artifactLocation": {"uri": f.get("file") or "."}}
        if f.get("line"):
            try: loc["region"] = {"startLine": max(1, int(f["line"]))}
            except (TypeError, ValueError): pass
        msg = (f.get("title") or rule)
        if f.get("snippet"): msg += " — " + str(f["snippet"])
        r = {"ruleId": rule, "level": _SARIF_LEVEL[sev], "message": {"text": msg[:1000]},
             "locations": [{"physicalLocation": loc}],
             "partialFingerprints": {"repobeagle/v1": hashlib.sha256(
                 f"{rule}|{f.get('file')}|{f.get('title')}|{f.get('snippet') or ''}".encode()).hexdigest()},
             "properties": {"tool": f.get("tool"), "severity": sev, "line": f.get("line") or 0,
                            "remediation": f.get("remediation")}}
        if f.get("suppressed"):
            r["suppressions"] = [{"kind": "external", "justification": f"suppressed via {SUPPRESS_FILE}"}]
        results.append(r)
    run = {"tool": {"driver": {"name": "repobeagle", "version": VERSION,
                               "informationUri": "https://github.com/javierbits/repobeagle",
                               "rules": [rules[k] for k in sorted(rules)]}},
           "invocations": [{"executionSuccessful": True}],
           "results": results,
           "properties": {"verdict": d.get("verdict"), "profile": meta.get("profile"),
                          "privacy_mode": meta.get("privacy_mode"), "ruleset": meta.get("ruleset")}}
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def markdown_report(d):
    """Renders a stored report as a Markdown table suitable for a PR comment. Pure."""
    meta = d.get("meta") if isinstance(d.get("meta"), dict) else {}
    c = d.get("counts") or {}
    out = [f"## RepoBeagle: {d.get('verdict') or '?'}", "",
           f"`{meta.get('target', '?')}` · profile `{meta.get('profile', '?')}` · "
           f"{c.get('critical', 0)} critical / {c.get('high', 0)} high / {c.get('medium', 0)} medium / {c.get('low', 0)} low",
           ""]
    fs = [f for f in (d.get("findings") or []) if isinstance(f, dict) and not f.get("suppressed") and f.get("severity") in SEV_ORDER]
    fs.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f.get("file") or "", f.get("line") or 0))
    if fs:
        out += ["| Severity | Rule | Location | Finding | Fix |", "|---|---|---|---|---|"]
        for f in fs[:200]:
            loc = f"{f.get('file')}:{f.get('line')}" if f.get("line") else (f.get("file") or "?")
            cell = lambda s: str(s).replace("|", "\\|").replace("\n", " ")[:200]
            out.append(f"| {f['severity']} | `{cell(_rule_of(f))}` | `{cell(loc)}` | {cell(f.get('title') or '')} | {cell(f.get('remediation') or '')} |")
        if len(fs) > 200:
            out.append(f"| … | | | {len(fs) - 200} more (see the JSON report) | |")
    else:
        out.append("No findings.")
    if d.get("why"):
        out += ["", str(d["why"])]
    return "\n".join(out) + "\n"


def html_report(d):
    """Self-contained HTML report (inline CSS, no external assets); snippets stay exactly as stored (redacted)."""
    from html import escape
    meta = d.get("meta") if isinstance(d.get("meta"), dict) else {}
    c = d.get("counts") or {}
    verdict = str(d.get("verdict") or "?")
    color = {"GREEN": "#1a7f37", "YELLOW": "#9a6700", "RED": "#cf222e"}.get(verdict, "#57606a")
    fs = [f for f in d.get("findings") or [] if isinstance(f, dict) and f.get("severity") in SEV_ORDER]
    fs.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f.get("file") or "", f.get("line") or 0))
    rows = []
    for f in fs:
        loc = f"{f.get('file')}:{f.get('line')}" if f.get("line") else str(f.get("file") or "?")
        extra = ""
        if f.get("meaning"):
            extra += f"<div class='meta'>{escape(str(f['meaning']))}</div>"
        if f.get("snippet"):
            extra += f"<div class='snippet'>{escape(str(f['snippet'])[:400])}</div>"
        if f.get("remediation"):
            extra += f"<div class='fix'>fix: {escape(str(f['remediation']))}</div>"
        if f.get("suppressed"):
            why = (f.get("suppression") or {}).get("reason") or "suppressed"
            extra += f"<div class='meta'>accepted: {escape(str(why))}</div>"
        rows.append(f"<tr class='sev-{escape(str(f['severity']))}{' suppressed' if f.get('suppressed') else ''}'>"
                    f"<td>{escape(str(f['severity']))}</td>"
                    f"<td><code>{escape(_rule_of(f))}</code></td>"
                    f"<td><code>{escape(loc)}</code></td>"
                    f"<td>{escape(str(f.get('title') or ''))}{extra}</td></tr>")
    sc = meta.get("scope") or {}
    facts = [f"target: {meta.get('target', '?')}", f"mode: {meta.get('mode', '?')}",
             f"profile: {meta.get('profile', '?')}", f"ruleset: {meta.get('ruleset', '?')}"]
    if sc:
        facts.append("scope: " + ", ".join(f"{k} {v}" for k, v in sc.items() if not isinstance(v, list)))
    notes = "".join(f"<li>{escape(str(n))}</li>" for n in d.get("notes") or [])
    counts = " · ".join(f"{escape(s)} {c.get(s, 0)}" for s in SEV_ORDER)
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'><title>RepoBeagle report</title>"
            "<style>"
            "body{font:14px/1.45 system-ui,sans-serif;margin:2rem;color:#1f2328;background:#fff}"
            "h1{font-size:1.3rem} .verdict{padding:.2rem .6rem;border-radius:6px;background:" + color + ";color:#fff}"
            "table{border-collapse:collapse;width:100%;margin-top:1rem}"
            "th,td{border-bottom:1px solid #d0d7de;padding:.35rem .5rem;vertical-align:top;text-align:left}"
            "tr.sev-critical td:first-child{color:#cf222e;font-weight:600}"
            "tr.sev-high td:first-child{color:#bc4c00} tr.sev-medium td:first-child{color:#9a6700}"
            "tr.suppressed{opacity:.65} .meta{color:#57606a;font-size:.92em}"
            ".snippet,.fix{font-family:ui-monospace,monospace;font-size:.85em;margin-top:.2rem;white-space:pre-wrap}"
            ".facts{color:#57606a;font-size:.92em}"
            "</style></head><body>"
            f"<h1>RepoBeagle: <span class='verdict'>{escape(verdict)}</span></h1>"
            f"<div class='facts'>{escape(' · '.join(facts))}</div>"
            f"<div class='facts'>{counts}</div>"
            + (f"<h2>Notes</h2><ul>{notes}</ul>" if notes else "")
            + ("<table><thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Finding</th></tr></thead><tbody>"
               + "".join(rows) + "</tbody></table>" if rows else "<p>No findings.</p>")
            + "</body></html>\n")


def render_capabilities(d, label, all_entries=False):
    """Prints what the target can touch. Documentation/test-only entries are collapsed unless all_entries."""
    meta = d.get("meta") if isinstance(d.get("meta"), dict) else {}
    caps = meta.get("capabilities") or {}
    print(f"RepoBeagle capabilities: {label}")
    if not caps:
        print("  (no capability data: report predates the map, or the pass failed)")
        return 0
    print(f"  scanned: {meta.get('files', '?')} file(s), profile {meta.get('profile', '?')}, verdict {d.get('verdict', '?')}")
    names = {"network": "network hosts", "filesystem": "filesystem / secret paths", "processes": "subprocesses",
             "environment": "environment variables", "storage": "client storage"}
    def code_entries(items):
        return [e for e in items if not e.get("doc") and not e.get("test")]
    for key in ("network", "filesystem", "processes", "environment", "storage"):
        items = caps.get(key) or []
        if not items:
            continue
        code, hidden = code_entries(items), len(items) - len(code_entries(items))
        shown = items if all_entries else code
        print(f"  {names[key]} ({len(code)}{f' code, {hidden} docs/test' if hidden else ''}):")
        for e in shown[:8]:
            where = f"[{e.get('file')}:{e.get('line')}]"
            note = (" traced" if e.get("verified") else "") + (" doc" if e.get("doc") else "") + (" test" if e.get("test") else "")
            print(f"    {e.get('value')}  {where}" + (f" x{e['count']}" if (e.get("count") or 1) > 1 else "") + note)
        if len(shown) > 8:
            print(f"    ... {len(shown) - 8} more (see meta.capabilities in --json)")
        elif not shown and hidden:
            print(f"    (only documentation/test entries; --all to list)")
    fs = [f for f in (d.get("findings") or []) if isinstance(f, dict) and not f.get("suppressed")]

    def section(title, match):
        sel = [f for f in fs if match(_rule_of(f), f.get("title") or "")]
        if not sel:
            return
        print(f"  {title} ({len(sel)}):")
        for f in sel[:8]:
            print(f"    {f.get('severity')}: {f.get('title')}  [{f.get('file')}:{f.get('line')}]")
        if len(sel) > 8:
            print(f"    ... {len(sel) - 8} more")

    section("install hooks", lambda r, t: re.search(r"(?i)\b(postinstall|preinstall|prepare|lifecycle script|install hook|build hook)\b", t) is not None)
    section("permissions / capabilities", lambda r, t: r.startswith(("android-permission", "android-feature", "extension-permission", "macos-entitlement", "browser-capability")))
    section("telemetry vendors", lambda r, t: r.startswith("telemetry-"))
    return 0


ACTIONS = {
    "RED": ["Do NOT install, build, run, or point an AI agent at this repo.",
            "Review each critical/high finding at the file:line shown; if confirmed, report the repo/package to GitHub / npm / PyPI.",
            "If you already ran it: rotate SSH keys, API tokens and .env secrets, and check ~/.ssh, shell rc files and crontab for changes."],
    "YELLOW": ["Read the listed findings before trusting it; most may be benign, but confirm each.",
               "Install only in an isolated environment (container/VM/throwaway user) with no secrets present.",
               "Don't let an AI agent auto-run its install steps or MCP servers without reviewing them."],
    "GREEN": ["No red flags found by static analysis. Still pin versions and install in a venv/container.",
              "Static scanning can't prove safety; it does not observe runtime behavior."],
}


def color_enabled(stream=None):
    """Returns True if ANSI colors should be written to stream (default stdout)."""
    return (stream or sys.stdout).isatty() and not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"


BANNER_DOG = [                            # beagle face, front view: white blaze, floppy ears
    r"       .-'''''-.",
    r"     .'  |   |  '.",
    r"  .-/    |   |    \-.",
    r" /  |  _ |   | _  |  \ ",
    r"|   | (o)|   |(o) |   |",
    r"|   |    /   \    |   |",
    r"|   |   / .-. \   |   |",
    r"|   |  (  (_)  )  |   |",
    r" \  |   '-.|.-'   |  /",
    r"  \_|    \_^_/    |_/",
    r"     '-._______.-'",
]


BANNER_WORD = [
    r" ___                  ___                   _",
    r"| _ \ ___  _ __  ___ | _ ) ___  __ _  __ _ | | ___",
    r"|   // -_)| '_ \/ _ \| _ \/ -_)/ _` |/ _` || |/ -_)",
    r"|_|_\\___|| .__/\___/|___/\___|\__,_|\__, ||_|\___|",
    r"          |_|                        |___/",
]


BANNER_TAG = "> Don't clone what you haven't sniffed._"


def banner(use_color):
    """Returns the startup banner (beagle, wordmark, tagline), max 79 columns, ANSI-colored if use_color."""
    C = (lambda code, s: f"\033[{code}m{s}\033[0m" if s else s) if use_color else (lambda code, s: s)
    rows = []
    for i, dog in enumerate(BANNER_DOG):
        # Reason: wordmark sits on rows 3-7 and the tagline on row 9 so both stay centered beside the face.
        right = C("1;96", BANNER_WORD[i - 3]) if 3 <= i < 3 + len(BANNER_WORD) else C("95", BANNER_TAG) if i == 9 else ""
        dog = dog.rstrip()
        rows.append(C("36", dog) + (" " * (26 - len(dog)) + right if right else ""))
    return "\n".join(rows) + "\n"


def render_report(meta, findings, v, why, counts, notes, ai, use_color, maxn=40, min_sev="info"):
    C = (lambda code, s: f"\033[{code}m{s}\033[0m") if use_color else (lambda code, s: s)
    vc = {"RED": "1;41;97", "YELLOW": "1;43;30", "GREEN": "1;42;30"}[v]
    sc = {"critical": "1;91", "high": "91", "medium": "93", "low": "96", "info": "37"}
    print(C("1", f"\nRepoBeagle {VERSION}  |  {meta['target']}"))
    persona = (meta.get("persona") or {}).get("name")
    print(f"mode: {meta['mode']}   profile: {meta['profile']}" + (f"   persona: {persona}" if persona else "")
          + f"   files: {meta['files']}   time: {meta['seconds']}s")
    if (meta.get("scope") or {}).get("scope") == "changed":
        scp = meta["scope"]
        print(C("1", f"  scope: changed files only ({scp.get('changed_files')} since {scp.get('since')}); "
                     "pre-existing findings elsewhere are not re-reported"))
    print(f"tools: " + ", ".join(f"{k}({t['findings']}{'' if t['ok'] else ' !'})" for k, t in meta["tools"].items()))
    partial = " (partial)" if meta.get("complete") is False else ""
    print("\n" + C(vc, f"  VERDICT: {v}{partial}  ") + "  " + why)
    print(f"  critical {counts['critical']}  high {counts['high']}  medium {counts['medium']}  low {counts['low']}\n")
    if meta.get("suppressed"):
        print(C("2", f"  suppressed {meta['suppressed']} finding(s) via {SUPPRESS_FILE} (kept in --json with suppressed=true)"))
    caps = meta.get("capabilities") or {}
    code = lambda k: [e for e in (caps.get(k) or []) if not e.get("doc") and not e.get("test")]
    hidden = sum(len(caps.get(k) or []) - len(code(k)) for k in ("network", "filesystem", "processes", "environment", "storage"))
    bits = [f"{len(code(k))} {label}" for k, label in (("network", "host(s)"), ("filesystem", "secret path(s)"),
                                                       ("processes", "subprocess(es)"), ("environment", "env var(s)"),
                                                       ("storage", "storage use(s)")) if code(k)]
    if bits:
        print(C("1", "  Capabilities: " + ", ".join(bits)
                + (f" (+{hidden} documentation/test hidden)" if hidden else "")
                + "  (repobeagle map for detail)"))
    cov = meta.get("coverage") or {}
    if cov:
        unread = {k: n for k, n in (cov.get("skipped") or {}).items() if n and k != "unsupported"}
        unsupported = (cov.get("skipped") or {}).get("unsupported") or 0
        no_rules = (cov.get("languages") or {}).get("no_rules") or {}
        line = (f"  Coverage: {cov.get('bytes_scanned_pct', '?')}% of source bytes covered by language-aware rules "
                f"({cov.get('files_scanned', '?')}/{cov.get('files_total', '?')} files)")
        if unread:
            line += "; not read: " + ", ".join(f"{n} {k}" for k, n in unread.items())
        if unsupported or no_rules:
            bits = ([f"{unsupported} unsupported extension(s)"] if unsupported else []) + \
                   [f"{n} ({c})" for n, c in no_rules.items()]
            line += "; no language rules for: " + ", ".join(bits)
        print(line)
    if meta.get("privacy_summary"):
        prof = privacy_profile(meta["privacy_summary"])
        if prof:
            print(C("1", prof))
        if meta.get("pii_redacted") and any(f["tool"] in ("privacy", "telemetry") for f in findings):
            print(C("2", "  PII in snippets/titles is redacted; use --no-redact to show raw values."))
        print(C("1", "Privacy summary:"))
        for group, vals in meta["privacy_summary"].items():
            if isinstance(vals, dict):
                line = "; ".join(f"{k}: {', '.join(v[:5])}" + (" …" if len(v) > 5 else "") for k, v in vals.items())
            else:
                line = ", ".join(vals[:8]) + (" …" if len(vals) > 8 else "")
            print(f"  {group}: {line}")
    if ai:
        print(C("1", "AI review: ") + f"intent={ai.get('intent')} confidence={ai.get('confidence')}\n  {ai.get('summary', '')}")
        for k in ai.get("key_concerns", [])[:5]: print(f"   - {k}")
        print()
    total = len(findings)
    thr = SEV_ORDER.get(min_sev, 0)
    findings = [f for f in findings if SEV_ORDER[f["severity"]] >= thr]
    fs = sorted(findings, key=lambda f: (-SEV_ORDER[f["severity"]], f["file"], f["line"]))
    if min_sev != "info":
        print(C("2", f"  printing findings at/above {min_sev} ({total - len(fs)} hidden; counts/verdict cover all)"))
    if fs:
        print(C("1", f"Findings ({len(fs)}, showing {min(len(fs), maxn)}):"))
    for f in fs[:maxn]:
        loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
        print(f"  {C(sc[f['severity']], f['severity'].upper().ljust(8))} [{f['tool']}] {C('1', loc)}"
              + (f"  package: {f['package']}" if f.get("package") else ""))
        print(f"           {f['title']}")
        if f["snippet"]: print(f"           > {f['snippet'][:140]}")
        if f["meaning"]: print(f"           {C('2', f['meaning'][:200])}")
        if f.get("remediation"): print(f"           {C('2', 'fix: ' + f['remediation'][:180])}")
        if f.get("dependency_path"):
            print(f"           {C('2', 'via: ' + ' → '.join(f['dependency_path']))}")
        elif f.get("dependency_note"):
            print(f"           {C('2', 'via: ' + f['dependency_note'])}")
    if len(fs) > maxn: print(f"  ... {len(fs) - maxn} more (use --json or --all)")
    checks = meta.get("checks")
    if isinstance(checks, dict) and checks:
        zero = [r for r, v in checks.items() if v.get("evaluated") and not v.get("hits")]
        with_hits = [r for r, v in checks.items() if v.get("evaluated") and v.get("hits")]
        not_evaluated = [r for r, v in checks.items() if not v.get("evaluated")]
        parts = [f"{len(checks)} rule(s): {len(with_hits)} with hits, {len(zero)} evaluated with zero hits"]
        if zero:
            parts.append("no hits: " + ", ".join(zero[:10]))
        if with_hits:
            parts.append("with hits: " + ", ".join(with_hits[:10]))
        if not_evaluated:
            parts.append("not evaluated: " + ", ".join(not_evaluated[:10]))
        print(C("1", "\nChecks run: ") + "; ".join(parts))
    print(C("1", "\nRecommended actions:"))
    for a in ACTIONS[v]: print(f"  - {a}")
    if notes:
        print(C("2", "\nNotes:"))
        for n in notes: print(C("2", f"  - {n}"))
    print("\n" + C(vc, f"  VERDICT: {v}  ") + f"  critical {counts['critical']}  high {counts['high']}  medium {counts['medium']}  low {counts['low']}")


def collapse(fs, limit=20):
    """Collapse floods of identical-title findings (e.g. 30k archives) into one summary each."""
    groups: dict[tuple[Any, ...], list[dict]] = {}
    for f in fs: groups.setdefault((f["tool"], f["severity"], f["title"]), []).append(f)
    out = []
    for (tool, sev, title), items in groups.items():
        if len(items) > limit and tool == "agent-checks" and items[0]["line"] == 0:
            out += items[:3]
            out.append(finding(tool, sev, "(many files)", 0, f"{title} x{len(items)} total", ", ".join(i["file"] for i in items[3:6]) + ", ...",
                               f"{len(items) - 3} more files with the same finding (full list in --json raw_findings_count)."))
        else:
            out += items
    return out


def dedupe(fs):
    seen, out = set(), []
    for f in sorted(fs, key=lambda f: -SEV_ORDER[f["severity"]]):
        k = (f["file"], f["line"], f["title"])
        if k in seen: continue
        seen.add(k); out.append(f)
    return out


_WORKDIRS: set[str] = set()


def _cleanup_workdirs():
    for w in list(_WORKDIRS):
        shutil.rmtree(w, ignore_errors=True)
        _WORKDIRS.discard(w)


def _on_signal(signum, frame):
    _cleanup_workdirs()
    raise SystemExit(128 + signum)


def _install_cleanup():
    import atexit, signal
    atexit.register(_cleanup_workdirs)
    for sig in (signal.SIGINT, signal.SIGTERM, getattr(signal, "SIGHUP", None)):
        if sig is not None:
            try: signal.signal(sig, _on_signal)
            except (ValueError, OSError): pass   # not in main thread


# --- CycloneDX SBOM export (lockfiles -> purls; OSV findings -> vulnerabilities) ------
SBOM_SCHEMA_VERSION = "1.6"


SBOM_SCHEMA_URL = "http://cyclonedx.org/schema/bom-1.6.schema.json"


SBOM_MAX_COMPONENTS = 5000


def _sbom_purl(ecosystem, name, version):
    if ecosystem == "pypi":
        return f"pkg:pypi/{re.sub(r'[-_.]+', '-', name).lower()}@{version}"
    if ecosystem == "npm":
        return f"pkg:npm/{urllib.parse.quote(name, safe='/')}@{version}"
    return f"pkg:cargo/{name}@{version}"


def _sbom_npm(data):
    """[(name, version)] from package-lock.json v1 (nested dependencies) or v2/v3 (packages)."""
    out = []
    def walk(deps):
        for name, meta in (deps or {}).items():
            if not isinstance(meta, dict):
                continue
            if meta.get("version"):
                out.append((str(name), str(meta["version"])))
            walk(meta.get("dependencies"))
    for key, meta in (data.get("packages") or {}).items():
        if not isinstance(meta, dict) or not meta.get("version"):
            continue
        if not key:  # v3 lists the project itself under "" (it is metadata.component)
            continue
        name = str(meta.get("name") or str(key).split("node_modules/")[-1])
        out.append((name, str(meta["version"])))
    walk(data.get("dependencies"))
    return out


def _sbom_requirements(text):
    """[(name, version)] for pinned `name==version` lines; unpinned or ranged requirements are skipped."""
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "--")):
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][^\s;]*)", line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def _sbom_cargo(text):
    """[(name, version)] from the `[[package]]` blocks of a Cargo.lock."""
    out, cur = [], {}  # type: list[tuple[str, str]], dict[str, str]
    def flush(block):
        if block.get("name") and block.get("version"):
            out.append((block["name"], block["version"]))
    for line in text.splitlines():
        line = line.strip()
        if line == "[[package]]":
            flush(cur)
            cur = {}
            continue
        m = re.match(r'^(name|version)\s*=\s*"([^"]+)"$', line)
        if m and m.group(1) not in cur:
            cur[m.group(1)] = m.group(2)
    flush(cur)
    return out


def sbom_components(root):
    """({purl: component}, [unparsed manifest paths]) from the lockfiles in the scanned tree."""
    comps: dict[str, dict[str, Any]] = {}
    unparsed: list[str] = []
    for p in iter_files(root):
        if len(comps) >= SBOM_MAX_COMPONENTS:
            break
        try:
            if p.name == "package-lock.json":
                ecosystem, pairs = "npm", _sbom_npm(json.loads(read_text(p) or ""))
            elif p.name == "requirements.txt":
                ecosystem, pairs = "pypi", _sbom_requirements(read_text(p) or "")
            elif p.name == "Cargo.lock":
                ecosystem, pairs = "cargo", _sbom_cargo(read_text(p) or "")
            else:
                continue
        except Exception:
            unparsed.append(rel(root, p))
            continue
        for name, version in pairs:
            purl = _sbom_purl(ecosystem, name, version)
            comps.setdefault(purl, {"type": "library", "name": name, "version": version, "purl": purl,
                                     "bom-ref": purl,
                                     "properties": [{"name": "repobeagle:manifest", "value": rel(root, p)}]})
    return comps, unparsed


def sbom_report(root, report):
    """CycloneDX 1.6 document for the scanned tree: purls from lockfiles, OSV findings as vulnerabilities.

    Deterministic: components and vulnerabilities are sorted, the serial number is derived from the
    target and commit (no random uuid), and no wall-clock timestamp is written.
    """
    comps, unparsed = sbom_components(root)
    meta = report.get("meta") or {}
    target = str(meta.get("target") or "unknown")
    commit = str(meta.get("commit") or "")
    props = [{"name": "repobeagle:verdict", "value": str(report.get("verdict"))},
             {"name": "repobeagle:profile", "value": str(meta.get("profile"))},
             {"name": "repobeagle:ruleset", "value": str(meta.get("ruleset"))},
             {"name": "repobeagle:target", "value": target}]
    if commit:
        props.append({"name": "repobeagle:commit", "value": commit})
    for sev, n in (report.get("counts") or {}).items():
        props.append({"name": f"repobeagle:counts.{sev}", "value": str(n)})
    if unparsed:
        props.append({"name": "repobeagle:unparsed-manifests", "value": ", ".join(sorted(unparsed))})
    if meta.get("complete") is False:
        props.append({"name": "repobeagle:complete", "value": "false"})
    vulns: dict[str, dict[str, Any]] = {}
    for f in report.get("findings") or []:
        if not isinstance(f, dict) or f.get("suppressed") or f.get("tool") != "osv-scanner":
            continue
        m = re.search(r": (\S+)@([^\s]+)$", str(f.get("title") or ""))
        if not m:
            continue
        ref = next((purl for purl, c in comps.items() if c["name"] == m.group(1) and c["version"] == m.group(2)), None)
        if not ref:
            continue
        ids = [i.strip() for i in str(f.get("snippet") or "").split(",") if i.strip()]
        for vid in ids or ["unknown"]:
            entry = vulns.setdefault(vid, {"id": vid, "source": {"name": "OSV"}, "affects": [],
                                           "ratings": [{"source": {"name": "OSV"}, "severity": str(f.get("severity")),
                                                        "method": "other"}]})
            if not any(aff.get("ref") == ref for aff in entry["affects"]):
                entry["affects"].append({"ref": ref})
            if f.get("remediation") and "recommendation" not in entry:
                entry["recommendation"] = str(f["remediation"])
    return {"$schema": SBOM_SCHEMA_URL, "bomFormat": "CycloneDX", "specVersion": SBOM_SCHEMA_VERSION,
            "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"{target}@{commit}#{SBOM_SCHEMA_VERSION}")),
            "version": 1,
            "metadata": {"tools": {"components": [{"type": "application", "name": "repobeagle", "version": VERSION}]},
                         "component": {"type": "application", "name": target, "version": commit or "unknown"},
                         "properties": props},
            "components": [comps[p] for p in sorted(comps)],
            "vulnerabilities": sorted(vulns.values(), key=lambda v: (v["id"], v["affects"][0].get("ref", "") if v["affects"] else ""))}