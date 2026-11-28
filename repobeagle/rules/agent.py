import argparse, base64, concurrent.futures, difflib, hashlib, hmac, json, os, platform, queue, re, shlex, shutil, signal, subprocess, sys, tempfile, threading, time, unicodedata, uuid, zipfile
import urllib.error, urllib.parse, urllib.request
from datetime import date, datetime, timezone
from fnmatch import fnmatchcase
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from pathlib import Path


# --- cross-module imports ---

from ..core import AGENT_FILE_RE, ARCHIVE_EXT, BIDI, BINARY_EXT, CODE_EXT, ConfigError, DECODE_EXEC, DOC_EXT, INJECTION_PATTERNS, PIPE_SHELL, PROSE_EXT, READ_RE, SCAN_FILE_SECONDS, SENS_RE, SINK_RE, ScanDeadline, TEST_PATH, ZW, _gitmodules_entries, _is_comment, _json_file, _line_of, _origin_host, _rule_of, _scan_alarm, _url_host, decode_tags, finding, is_tag, iter_files, load_repo_config, own_domains, parse_yaml_subset, read_text, rel, strip_invisible, zip_encrypted
from ..modelmeta import WEIGHT_EXT, lfs_pointer, onnx_prefix_info, read_header, read_safetensors
from ..rules.privacy import PRIVACY_DOC_NAMES, PRIVACY_DOC_RE, PRIVACY_LINK_RE, check_privacy, check_privacy_signals, check_telemetry, privacy_findings, telemetry_findings








def check_unicode(root, p, text, findings):
    r = rel(root, p)
    agent = bool(AGENT_FILE_RE.search(r))
    lines = text.split("\n")
    for i, line in enumerate(lines, 1):
        zw = [c for c in line if c in ZW and not (c == "\ufeff" and i == 1 and line.startswith(c))]
        bd = [c for c in line if c in BIDI]
        tg = [c for c in line if is_tag(c)]
        if not (zw or bd or tg):
            continue
        hidden = decode_tags(line)
        clean = strip_invisible(line)
        instr = any(re.search(pt, hidden + " " + clean) for pt, _ in INJECTION_PATTERNS) or \
                (SENS_RE.search(hidden + " " + clean) and SINK_RE.search(hidden + " " + clean))
        # many ZW chars spliced inside words = keyword-evasion
        spliced = len(re.findall(r"\w[\u200b-\u200f\u2060-\u2064\u00ad]+\w", line)) >= 3
        if tg:
            sev = "critical"
            title = f"Invisible Unicode TAG characters ({len(tg)}) hiding text"
            meaning = f"Decoded hidden text: \"{hidden[:120]}\" -- invisible to humans, read by LLMs."
        elif bd:
            sev = "high" if p.suffix in CODE_EXT else "medium"
            title = f"Bidirectional control characters ({len(bd)}) (Trojan-Source style)"
            meaning = "Bidi overrides can make code/text display differently from what is executed or read."
        else:
            sev = "high" if (agent or spliced) else "low"
            title = f"Zero-width characters ({len(zw)})" + (" spliced inside words" if spliced else "")
            meaning = "Zero-width chars can hide text or break keyword filters; text with them removed: \"" + clean.strip()[:110] + "\""
        if instr or (agent and (spliced or tg)):
            sev = "critical"
            meaning += " Hidden content contains agent instructions / exfiltration language."
        findings.append(finding("agent-checks", sev, r, i, title, clean.strip(), meaning))


def check_agent_text(root, p, text, findings):
    r = rel(root, p)
    if not AGENT_FILE_RE.search(r):
        return
    clean = strip_invisible(text) + ""
    lines = clean.split("\n")
    # also look inside HTML comments (hidden in rendered markdown)
    for m in re.finditer(r"<!--(.*?)-->", clean, re.S):
        body = m.group(1)
        if re.search(r"(?i)\b(ai|agent|assistant|llm|model|claude|cursor|copilot|you\s+must|ignore|instruction)", body) and len(body.strip()) > 15:
            ln = clean[:m.start()].count("\n") + 1
            sev = "critical" if (SENS_RE.search(body) or SINK_RE.search(body) or any(re.search(pt, body) for pt, _ in INJECTION_PATTERNS)) else "high"
            findings.append(finding("agent-checks", sev, r, ln, "Hidden HTML comment addressed to an AI agent",
                                    body.strip().replace("\n", " "), "Not visible when the markdown is rendered, but read by agents."))
    for i, line in enumerate(lines, 1):
        for pt, title in INJECTION_PATTERNS:
            if re.search(pt, line):
                sev = "critical" if (SENS_RE.search(line) or SINK_RE.search(line)) else "high"
                findings.append(finding("agent-checks", sev, r, i, title, line, "Instructions aimed at AI agents reading this file."))
                break




MCP_CODE_RE = re.compile(r"(@mcp\.tool|FastMCP|McpServer|server\.tool\(|registerTool|mcp\.server|ListToolsRequest|@modelcontextprotocol)")


POISON_RE = re.compile(r"(?i)(<\s*important\s*>|otherwise the tool will not work|(do\s+not|don'?t|never)\s+(mention|tell|reveal|disclose)|pass (its|the) content|before using this tool|instead of the (real|actual|requested)|send (all|every) (messages?|emails?) to|concealment)")


def check_tool_poisoning(root, p, text, findings):
    """MCP tool poisoning: hidden instructions inside tool descriptions/docstrings in MCP server code."""
    if p.suffix.lower() not in CODE_EXT or not MCP_CODE_RE.search(text):
        return
    r = rel(root, p)
    lines = text.split("\n")
    for i, line in enumerate(lines, 1):
        m = POISON_RE.search(line)
        inj = any(re.search(pt, line) for pt, _ in INJECTION_PATTERNS)
        if not (m or inj):
            continue
        window = " ".join(lines[max(0, i - 6): i + 6])
        sev = "critical" if (SENS_RE.search(window) or re.search(r"(?i)(do\s+not|don'?t|never)\s+(mention|tell|reveal)|send .* to|sidenote|\+1\d{6,}", window)) else "high"
        findings.append(finding("agent-checks", sev, r, i, "MCP tool poisoning: hidden instructions in a tool description", line,
                                "Text inside an MCP tool definition that the agent reads as instructions (exfiltration / concealment / tool shadowing)."))


def check_exfil(root, p, text, findings):
    r = rel(root, p)
    ext = p.suffix.lower()
    agent = bool(AGENT_FILE_RE.search(r))
    is_code = ext in CODE_EXT or p.name in ("Makefile", "Dockerfile") or ext == ""
    lines = strip_invisible(text).split("\n")
    for i, line in enumerate(lines, 1):
        if len(line) > 2000 or _is_comment(line):
            continue
        m = SENS_RE.search(line)
        if not m:
            continue
        window = " ".join(lines[max(0, i - 4): i + 3])
        reads = READ_RE.search(line) or READ_RE.search(window)
        sink = SINK_RE.search(window)
        if not reads:
            continue
        # .env is the project's own config: expected to be read by its own scripts.
        # Only the other targets (SSH keys, wallets, cookies, cloud creds) are a theft signal.
        toks = {re.sub(r"^[\s'\"/=(]+", "", t.group(0)).strip() for t in SENS_RE.finditer(line)}
        env_only = bool(toks) and all(t.startswith(".env") for t in toks)
        if is_code:
            if sink and not env_only:
                sev, title = "critical", "Code reads secrets/credentials near a network call"
            elif sink:
                sev, title = "medium", "Code reads .env config next to a network call"
            elif env_only:
                sev, title = "low", "Code reads .env (project config, not a credential store)"
            else:
                sev, title = "high", "Code reads sensitive credential files"
            meaning = "Accessing SSH keys, wallets, cookies or cloud creds is a hallmark of credential stealers."
            if env_only:
                meaning = "Reading the repo's own .env is normal; review only that the values are not sent somewhere unexpected."
            if TEST_PATH.search(r):
                sev = "medium"; meaning += " (test path: often benign fixtures)"
        elif agent or ext in DOC_EXT:
            if not sink:
                continue
            imperative = re.search(r"(?i)\b(upload|send|post|exfil|transmit|forward|copy)\b", line + window)
            sev = "critical" if (agent and imperative) else "medium"
            title = "Instructions to read and send secrets/credentials to a URL"
            meaning = "If an AI agent follows this text it may leak your secrets."
        else:
            if not sink:
                continue
            sev, title = "high", "Config/data references secrets next to a network destination"
            meaning = "Possible credential exfiltration configured outside code."
        findings.append(finding("agent-checks", sev, r, i, title, line, meaning))


def check_patterns(root, p, text, findings):
    r = rel(root, p)
    ext = p.suffix.lower()
    is_doc = ext in DOC_EXT and not AGENT_FILE_RE.search(r)
    lines = text.split("\n")
    for i, line in enumerate(lines, 1):
        if len(line) > 4000:
            continue
        if PIPE_SHELL.search(line):
            sev = "low" if is_doc else ("medium" if p.name in ("Makefile",) else "high")
            findings.append(finding("agent-checks", sev, r, i, "Download-and-execute (pipe to shell)", line,
                                    "Runs whatever a remote server returns, with no review." + (" (in docs: common but risky install pattern)" if is_doc else "")))
        if DECODE_EXEC.search(line):
            findings.append(finding("agent-checks", "high", r, i, "eval/exec of decoded blob", line, "Typical obfuscated-payload loader."))
        if ext in CODE_EXT:
            blob = re.search(r"[\w+/=-]{400,}", line)
            if blob and "data:" not in line and shannon(blob.group(0)) > 5.2:
                findings.append(finding("agent-checks", "medium", r, i, f"high-entropy-blob: {len(blob.group(0))}-char encoded blob (entropy {shannon(blob.group(0)):.2f})",
                                        line[:80] + "...", "Embedded high-entropy payloads are often used to hide malware."))
            elif re.search(r"[A-Za-z0-9+/]{400,}={0,2}", line):
                findings.append(finding("agent-checks", "medium", r, i, "Large base64-like blob in source", line[:80] + "...", "Embedded encoded payloads are often used to hide malware."))


MCP_NAME_RE = re.compile(r"(?i)(^|/)(\.?mcp(_servers)?\.json|[^/]*\.mcp\.json|plugin\.json|[^/]*\.plugin\.json|marketplace\.json|claude_desktop_config\.json|"
                         r"\.claude/settings[^/]*\.json|\.cursor/mcp\.json|\.vscode/mcp\.json|\.codex/config\.toml|\.gemini/settings\.json|\.windsurf/mcp[^/]*\.json|hooks\.json)$")


def check_mcp(root, p, text, findings):
    r = rel(root, p)
    if not MCP_NAME_RE.search(r):
        return
    add = lambda sev, title, needle, meaning: findings.append(finding("agent-checks", sev, r, _line_of(text, needle), title, needle, meaning))
    try:
        data = json.loads(text) if p.suffix == ".json" else None
    except Exception:
        data = None
    flat = []
    def walk(o, path=""):
        if isinstance(o, dict):
            for k, v in o.items(): walk(v, f"{path}.{k}")
        elif isinstance(o, list):
            for v in o: walk(v, path + "[]")
        else:
            flat.append((path, o))
    if data is not None:
        walk(data)
    else:
        flat = [("", l) for l in text.split("\n")]
    for path, val in flat:
        if not isinstance(val, (str, bool, int)):
            continue
        sval = str(val)
        lp = path.lower()
        if re.search(r"(?i)^(ba|z)?sh$|^bash\s+-c|^sh\s+-c|^cmd(\.exe)?$|powershell|\bcurl\b|\bwget\b", sval) and ("command" in lp or "args" in lp or not lp):
            add("high", "MCP/plugin server runs a raw shell or downloader", sval, "The server definition hands the agent a general shell or fetches remote code.")
        if re.search(r"(?i)^(\*|Bash\(\*\)|Bash|shell|all|\*:\*|mcp__\*)$", sval) and any(k in lp for k in ("allow", "permission", "tools", "autoapprove", "alwaysallow", "trust")):
            add("high", "Over-broad tool permission / auto-approve", sval, "Grants the agent every tool or unrestricted shell without confirmation.")
        if isinstance(val, bool) and val and any(k in lp for k in ("dangerously", "trust", "autoapprove", "yolo", "skippermission", "bypass")):
            add("high", f"Dangerous flag enabled ({path.strip('.')})", path.split(".")[-1], "Disables confirmation prompts for agent actions.")
        if "args" in lp and re.fullmatch(r"(/|~|~/|\$HOME|\$\{HOME\}|C:\\\\?|/home|/Users|/root|\.\./\.\.)/?", sval.strip()):
            add("high", "Filesystem access to root/home directory", sval, "The server can read and write your entire disk/home, including keys and .env files.")
        if re.match(r"https?://", sval) and any(k in lp for k in ("url", "endpoint", "server", "baseurl")) and not re.match(r"https?://(localhost|127\.0\.0\.1)", sval):
            add("medium", "Remote MCP/plugin server endpoint", sval, "Agent traffic (possibly including file contents) goes to this third-party server.")
        if re.search(r"(?i)npx\s+-y|^-y$|uvx|pipx\s+run", sval) and ("args" in lp or "command" in lp):
            add("medium", "MCP server auto-installs and runs a package at launch", sval, "Unpinned packages fetched at each start can change under you.")
        if "env" in lp and re.search(r"(?i)token|secret|key|password", lp) and isinstance(val, str) and val and not val.startswith("${") and not val.startswith("<"):
            pass
        if SENS_RE.search(sval):
            add("high", "Manifest references credential files", sval, "Plugin/MCP config points at secrets.")


def check_install_hooks(root, p, text, findings):
    r = rel(root, p)
    name = p.name
    def auto_sev(cmd, base):
        return "critical" if (PIPE_SHELL.search(cmd) or re.search(r"(?i)\b(curl|wget)\b|node\s+-e|python[0-9.]*\s+-c|base64|eval|\bnc\b", cmd) or SENS_RE.search(cmd)) else base
    if name == "package.json":
        try:
            data = json.loads(text)
        except Exception:
            return
        for k, v in (data.get("scripts") or {}).items():
            if k in ("preinstall", "install", "postinstall", "prepare", "prepublish", "preuninstall", "postuninstall"):
                base = "low" if (k == "prepare" and re.search(r"(?i)husky|tsc|build|rollup|webpack", str(v))) else "high" if k != "prepare" else "medium"
                sev = auto_sev(str(v), base)
                findings.append(finding("agent-checks", sev, r, _line_of(text, f'"{k}"'), f"npm lifecycle script '{k}' runs automatically on install", f'"{k}": "{v}"',
                                        "npm runs this on `npm install` with your user's permissions."))
    elif name == "setup.py":
        if "cmdclass" in text:
            findings.append(finding("agent-checks", "medium", r, _line_of(text, "cmdclass"), "setup.py overrides install commands (cmdclass)", "cmdclass", "Custom code runs during pip install."))
        for i, line in enumerate(text.split("\n"), 1):
            if re.search(r"os\.system|subprocess\.|urllib|requests\.|socket\.|exec\(|eval\(", line):
                findings.append(finding("agent-checks", auto_sev(line, "high"), r, i, "setup.py executes commands / network at install time", line, "Runs during `pip install` of this source."))
    elif name == "pyproject.toml":
        for i, line in enumerate(text.split("\n"), 1):
            if re.search(r"\[tool\.hatch\.build(\.targets\.\w+)?\.hooks|backend-path|\[tool\.setuptools\.cmdclass", line):
                findings.append(finding("agent-checks", "medium", r, i, "Custom build hook / in-tree build backend", line, "Code from the repo runs at build/install time; review it."))
    elif name in ("devcontainer.json", ".devcontainer.json"):
        for k in ("initializeCommand", "onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand", "postAttachCommand"):
            m = re.search(r'"%s"\s*:\s*(.+)' % k, text)
            if m:
                base = "high" if k == "initializeCommand" else "medium"
                findings.append(finding("agent-checks", auto_sev(m.group(1), base), r, _line_of(text, f'"{k}"'), f"Dev container auto-runs '{k}'", m.group(0),
                                        "Runs automatically when the folder is opened in a dev container" + (" (on the HOST)" if k == "initializeCommand" else "") + "."))
    elif name == "tasks.json" and ".vscode" in r and "folderOpen" in text:
        findings.append(finding("agent-checks", "high", r, _line_of(text, "folderOpen"), "VS Code task runs automatically on folder open", "runOn: folderOpen", "Opening the repo in VS Code (if trusted) executes this task."))
    elif re.search(r"(^|/)(\.husky|\.githooks|\.git-hooks)/", r) or name in ("lefthook.yml", ".pre-commit-config.yaml"):
        sev = auto_sev(text, "low")
        findings.append(finding("agent-checks", sev, r, 1, "Git hook configuration", text.strip().split("\n")[0], "Runs on git operations if you install the hooks."))
    elif name in ("Makefile", "GNUmakefile") or name.endswith(".mk"):
        for i, line in enumerate(text.split("\n"), 1):
            if SENS_RE.search(line) and SINK_RE.search(line):
                findings.append(finding("agent-checks", "high", r, i, "Makefile target touches secrets and network", line, "Running `make` would expose credentials."))


# ----------------------------------------------------------------------------
# Hidden markdown, build-time hooks, GitHub Actions, binaries/obfuscation, typosquats
# ----------------------------------------------------------------------------
MD_EXT = {".md", ".mdx", ".mdc", ".markdown"}


AG_RE = r"(\bagents?\b|assistant|\bAI\b|LLM|ignore (all |any )?(previous|prior)|do not tell|upload|exfil|send (it|them|to)|curl |wget |\.ssh|\.env\b|\.aws|credentials|api[_ ]?key|token)"


MD_RULES = [
    ("md-details-instruction", re.compile(r"(?is)<details>((?:(?!</details>).){0,600}?(ignore (all |any )?previous|do not tell the user|upload|exfil|\.ssh|\.aws/credentials))(?:(?!</details>|<details>).){0,2000}</details>"),
     "Collapsed <details> block carries agent instructions", "Collapsed by default when rendered, but read in full by agents."),
    ("md-alt-title-instruction", re.compile(r"(?i)(!\[[^\]\n]{0,300}" + AG_RE + r"[^\]\n]{0,300}\]|(alt|title)=\"[^\"\n]{0,300}" + AG_RE + ")"),
     "Image alt/title text carries agent instructions", "Alt/title text is rarely seen by humans but is read by agents."),
    ("md-css-hidden", re.compile(r"(?i)<[a-z]+[^>\n]*style=\"[^\"]*(display:\s*none|visibility:\s*hidden|font-size:\s*0|opacity:\s*0[;\" ]|(left|top|text-indent):\s*-\d{3,}|color:\s*(#fff\b|#ffffff|white))"),
     "CSS-hidden text in markdown", "Text styled to be invisible when rendered; agents still read it."),
    ("md-padded-line", re.compile(r"\S.{0,200}[ \t\u00a0]{150,}\S"),
     "Line padded with whitespace to push text off-screen", "Long runs of spaces hide trailing text past the visible edge of viewers."),
]


def check_markdown_hidden(root, p, text, findings):
    if p.suffix.lower() not in MD_EXT:
        return
    r = rel(root, p)
    clean = strip_invisible(text)
    ln = lambda pos: clean[:pos].count("\n") + 1
    # HTML comments in ALL markdown (agent files are already covered, stronger, by check_agent_text)
    if not AGENT_FILE_RE.search(r):
        for m in re.finditer(r"<!--(.*?)-->", clean, re.S):
            body = m.group(1)[:600]
            if not (len(body.strip()) > 15 and re.search(r"(?i)" + AG_RE, body)):
                continue
            # Boilerplate under .github/ (issue/PR templates) is written for humans, not agents.
            sev = "info" if r.startswith(".github/") else "medium"
            if sev == "medium" and not re.search(r"(?i)(\bagents?\b|\bAI\b|\bLLM\b|assistant|copilot|claude|"
                                                 r"ignore (all |any )?(previous|prior)|do not tell|exfiltrat)", body):
                sev = "low"      # only generic wording (upload/curl/.env) -> weaker signal
            findings.append(finding("agent-checks", sev, r, ln(m.start()), "md-comment-instruction: hidden HTML comment with agent/exfil wording",
                                    body.strip(), "Not visible when the markdown is rendered, but read by agents."))
    for rule, rx, title, meaning in MD_RULES:
        for m in rx.finditer(clean):
            findings.append(finding("agent-checks", "medium", r, ln(m.start()), f"{rule}: {title}", m.group(0)[:200], meaning))
            break


BUILD_FETCH_RE = re.compile(r"(urllib|urlopen|requests\.(get|post)|http\.client|socket\.|subprocess|os\.system|os\.popen|pip\.main)")


STD_BACKENDS = ("setuptools", "hatchling", "flit_core", "flit.", "poetry", "pdm", "maturin", "scikit_build", "mesonpy", "sipbuild", "pybind11", "whey", "uv_build")


def check_build_hooks(root, p, text, findings):
    r, name = rel(root, p), p.name
    lines = text.split("\n")
    def each(rx, sev, rule, title, meaning, once=False):
        for i, line in enumerate(lines, 1):
            if re.search(rx, line):
                findings.append(finding("agent-checks", sev, r, i, f"{rule}: {title}", line, meaning))
                if once: return
    if name in ("setup.cfg", "build.py", "hatch_build.py") or re.match(r"_build.*\.py$", name):
        each(BUILD_FETCH_RE, "high", "install-time-fetch", "build script runs commands / network at install time", "Runs during pip install/build of this source.")
    elif name == "build.rs":
        each(r"(Command::new|reqwest|ureq|TcpStream|curl|https?://)", "medium", "rust-build-rs", "Cargo build script runs commands / network", "build.rs executes on `cargo build` with your permissions.")
    elif p.suffix == ".go":
        each(r"^//go:generate .*(curl|wget|https?://|\bsh -c|bash)", "high", "go-generate-fetch", "go:generate downloads or runs a shell", "Runs on `go generate`; often wired into build instructions.")
    elif p.suffix in (".gyp", ".gypi"):
        each(r"['\"]actions?['\"]\s*:", "medium", "node-gyp-action", "node-gyp action runs a command at build", "Executed by node-gyp during `npm install` of native addons.", once=True)
    elif name == "pyproject.toml":
        m = re.search(r"(?m)^\s*build-backend\s*=\s*[\"']([^\"']+)", text)
        if m and not m.group(1).startswith(STD_BACKENDS):
            findings.append(finding("agent-checks", "medium", r, _line_of(text, m.group(0).strip()), "pip-build-hook: non-standard build backend", m.group(0),
                                    "An unknown PEP 517 backend runs arbitrary code on pip install."))
    elif name in ("Makefile", "GNUmakefile", "Justfile", "justfile") or name.endswith(".mk"):
        each(r"(\bcurl\b|\bwget\b|base64|\beval\b|\bnc\b)", "low", "make-just-hooks", "Make/just target downloads, decodes or opens sockets", "Runs if you invoke make/just; review before building.", once=True)


def check_workflows(root, p, text, findings):
    r = rel(root, p)
    if not re.search(r"(^|/)\.github/workflows/[^/]+\.ya?ml$", r):
        return
    lines = text.split("\n")
    add = lambda sev, rule, title, i, snip, meaning: findings.append(finding("agent-checks", sev, r, i, f"{rule}: {title}", snip, meaning))
    trig = re.search(r"(?m)^\s*(on:.*|-\s*)?\b(pull_request_target|workflow_run)\b", text)
    if trig:
        i = _line_of(text, trig.group(2))
        head = re.search(r"github\.event\.(pull_request\.head|workflow_run\.head)|head\.(sha|ref)|refs/pull/", text)
        if head:
            add("high", "gha-pwn-request", "privileged trigger checks out untrusted PR code", _line_of(text, head.group(0)), head.group(0),
                "pull_request_target/workflow_run runs with secrets + write token; checking out the PR head lets attackers run code with them.")
        else:
            add("medium", "gha-privileged-trigger", f"workflow uses {trig.group(2)}", i, trig.group(2), "Runs with repository secrets on events from forks; review carefully.")
    unpinned = []
    for i, line in enumerate(lines, 1):
        if re.search(r"(echo|printf|cat)\b[^\n]*\$\{\{\s*secrets\.", line):
            add("high", "gha-secret-echo", "secret printed in a workflow step", i, line, "Secrets written to logs or files can leak.")
        if PIPE_SHELL.search(line):
            add("medium", "gha-curl-pipe-shell", "workflow pipes a download into a shell", i, line, "CI runs whatever the remote server returns, with CI secrets available.")
        if re.search(r"(write-all|^\s*(contents|actions|packages|pull-requests|id-token):\s*write)", line):
            add("low", "gha-write-permissions", "workflow token has write permissions", i, line, "A compromised step can push code or publish packages.")
        if re.search(r"^\s*-?\s*uses:\s*(?!\./|docker://)[^@\s]+@(?![0-9a-f]{40}\b)", line):
            unpinned.append((i, line))
    if unpinned:
        add("low", "gha-unpinned-action", f"{len(unpinned)} action(s) on a tag/branch, not a commit SHA", unpinned[0][0], unpinned[0][1],
            "Tags can be moved to malicious code (e.g. tj-actions/changed-files, 2025).")


MAGIC = [(b"\x7fELF", "ELF executable"), (b"MZ", "Windows PE executable"), (b"\xcf\xfa\xed\xfe", "Mach-O binary"), (b"\xce\xfa\xed\xfe", "Mach-O binary"),
         (b"\xca\xfe\xba\xbe", "Mach-O universal / Java class"), (b"\xfe\xed\xfa\xcf", "Mach-O binary")]


DOCKER_FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?([^\s#]+)(?:\s+AS\s+(\S+))?", re.I)


PIP_EXTRA_INDEX_RE = re.compile(r"^\s*(?:--)?extra-index-url\s*[=:]?\s*(\S+)", re.M)


def check_supply_chain(root, findings):
    """Submodule and dependency-supply-chain rules: `.gitmodules`, Dockerfiles, pip/npm/yarn config."""
    root = Path(root)
    origin = _origin_host(root)
    mods = _gitmodules_entries(root)
    for m in mods:
        ref = m.get("path") or m.get("name") or "(submodule)"
        branch = m.get("branch") or ""
        if branch and not re.fullmatch(r"[0-9a-f]{40}", branch):
            findings.append(finding("agent-checks", "low", ".gitmodules", m.get("line", 1),
                f"submodule-unpinned: {ref} tracks branch {branch!r}",
                f"{m.get('url', '')} branch={branch}",
                "The superproject records a commit, but a branch ref drifts; `--remote` updates follow it. Pin the commit and avoid branch tracking in CI."))
        host = _url_host(m.get("url", ""))
        if origin and host and host != origin:
            findings.append(finding("agent-checks", "medium", ".gitmodules", m.get("line", 1),
                f"submodule-host: {ref} comes from {host}",
                m.get("url", ""),
                f"Submodule content is pulled from {host}, not the repository host {origin}; a pivot you did not review here."))
    if mods:
        paths = ", ".join(sorted((m.get("path") or m.get("name") or "?") for m in mods)[:6])
        findings.append(finding("agent-checks", "info", ".gitmodules", 1,
            f"submodule-uninspected: {len(mods)} submodule(s) not fetched", paths,
            "Fetch runs with `--no-recurse-submodules`, so only `.gitmodules` is inspected: this code was not scanned."))
    for p in sorted(iter_files(root)):
        name = p.name
        r = rel(root, p)
        if name == "Dockerfile" or name.lower().endswith(".dockerfile"):
            text = read_text(p) or ""
            stages: set[str] = set()
            for i, line in enumerate(text.splitlines(), 1):
                m = DOCKER_FROM_RE.match(line)
                if not m:
                    continue
                image, alias = m.group(1), m.group(2)
                if alias:
                    stages.add(alias.lower())
                if image.lower() in stages or image.lower() == "scratch" or image.startswith("$"):
                    continue
                tag = image.rsplit("@", 1)[1] if "@" in image else (image.rsplit(":", 1)[1] if ":" in image.rsplit("/", 1)[-1] else "")
                if not tag or tag.lower() == "latest":
                    findings.append(finding("agent-checks", "low", r, i,
                        f"dockerfile-base-unpinned: FROM {image}", line.strip(),
                        "No version tag or digest: the base image can change under you. Pin a tag and prefer `@sha256:` for reproducibility."))
        elif name.startswith("requirements") and name.endswith(".txt"):
            text = read_text(p) or ""
            for m in PIP_EXTRA_INDEX_RE.finditer(text):
                line = text[:m.start()].count("\n") + 1
                findings.append(finding("agent-checks", "medium", r, line,
                    "dependency-confusion: pip --extra-index-url", m.group(1),
                    "An extra index is searched alongside PyPI; an attacker can publish a higher version of a name you already use on it. Pin versions and hashes, or use a single index."))
        elif name in ("pip.conf", "pip.ini"):
            text = read_text(p) or ""
            for m in PIP_EXTRA_INDEX_RE.finditer(text):
                line = text[:m.start()].count("\n") + 1
                findings.append(finding("agent-checks", "medium", r, line,
                    "dependency-confusion: pip --extra-index-url", m.group(1),
                    "An extra index is searched alongside PyPI; a lookalike index can win the version resolution."))
        elif name in (".npmrc", ".yarnrc", ".yarnrc.yml"):
            text = read_text(p) or ""
            for i, line in enumerate(text.splitlines(), 1):
                if re.match(r"^\s*registry\s*[=:]\s*http://", line, re.I):
                    findings.append(finding("agent-checks", "medium", r, i,
                        "dependency-confusion: npm registry over plaintext", line.strip(),
                        "The registry is fetched over plaintext HTTP: a network attacker can swap tarballs."))
        elif name == "package.json":
            text = read_text(p) or ""
            try:
                pkg = json.loads(text)
            except ValueError:
                pkg = None
            if isinstance(pkg, dict):
                def line_of(needle):
                    return next((i for i, l in enumerate(text.splitlines(), 1) if needle in l), 1)
                for section in ("dependencies", "devDependencies", "optionalDependencies"):
                    deps = pkg.get(section) or {}
                    if not isinstance(deps, dict):
                        continue
                    for dep, spec in deps.items():
                        if isinstance(spec, str) and spec.startswith("http://"):
                            findings.append(finding("agent-checks", "medium", r, line_of(f'"{dep}"'),
                                f"dependency-confusion: npm http tarball {dep}", spec,
                                "A dependency is fetched over plaintext HTTP from an arbitrary host; pin it to https and a known registry."))
                for key in ("resolutions", "overrides"):
                    if isinstance(pkg.get(key), dict) and pkg[key]:
                        findings.append(finding("agent-checks", "low", r, line_of(f'"{key}"'),
                            f"dependency-confusion: {key} override present", key,
                            "Yarn resolutions/overrides replace the registry metadata resolution; review that the forced version is intended."))


def check_magic(root, p, findings):
    """Executable content hidden behind a non-binary extension (e.g. an ELF named logo.png). Reads 4 bytes only."""
    try:
        with open(p, "rb") as fh: head = fh.read(4)
    except OSError:
        return False
    for sig, kind in MAGIC:
        if head.startswith(sig) and (sig != b"MZ" or p.suffix.lower() not in (".txt", ".md")):
            findings.append(finding("agent-checks", "high", rel(root, p), 0, f"magic-mismatch: extension '{p.suffix or '(none)'}' hides a {kind}", kind,
                                    "Executables disguised as images/data are a classic dropper trick."))
            return True
    return False


MODEL_URL_RE = re.compile(r"https?://[^\s'\"<>)\]}]+", re.I)


# A chat template is Jinja, but the payload that matters is a shell/downloader command
# the model is told to reproduce. Anchored on the command shapes agents and humans
# actually run, not on every word that happens to be a program name.
MODEL_COMMAND_RE = re.compile(r"""(?ix)
    (?:
        \b(?:powershell|pwsh|cmd|bash|zsh|fish|sh)\b[^\n]{0,40}\s-(?:c|command|e|enc|encodedcommand)\b
      | \b(?:curl|wget)\b[^\n]{0,300}(?:https?://|\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\s-(?:o|o-|output|outfile)\b)
      | \biwr\b[^\n]{0,300}(?:https?://|-outfile\b)
      | \b(?:invoke-webrequest|invoke-restmethod)\b[^\n]{0,300}(?:https?://|-outfile\b)
      | \bhttps?://\S+[^\n]{0,80}\s-outfile\b
      | \b(?:start-process|unblock-file|iex)\b
      | \|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b
    )
""")


# A system message literal prepended to the conversation: the template changes what
# the model is told before the user's first token.
GGUF_SYSTEM_LITERAL_RE = re.compile(
    r"""(?sx)\{\s*['"]role['"]\s*:\s*['"]system['"]\s*,\s*['"]content['"]\s*:\s*
        (?P<q>['"])(?P<content>.{0,4000}?)(?P=q)\s*\}""")
GGUF_PREPEND_RE = re.compile(r"(?sx)\[\s*\{.{0,20000}?\}\s*\]\s*\+\s*(?:messages|conversation|history|prompt)\b")


def check_gguf(root, p, findings):
    """Read a GGUF metadata header (never the weights) and audit its chat template.

    `tokenizer.chat_template` is applied automatically by llama.cpp, Ollama, LM Studio
    and most GGUF consumers. A template that injects a system message can make the
    model print a shell command; an agent that pastes the answer then runs it.
    """
    r = rel(root, p)
    metadata, info = read_header(p)
    if info.get("lfs"):
        oid, size = info["lfs"]
        findings.append(finding("agent-checks", "medium", r, 0,
            "gguf-metadata-unavailable: GGUF weights are a Git LFS pointer, metadata not inspected",
            f"oid sha256:{oid[:12]}… size {size}",
            "The model card and the chat template live inside the file. Fetch the header (or scan with network access) before trusting a GREEN verdict."))
        return
    if metadata is None:
        findings.append(finding("agent-checks", "medium", r, 0,
            "gguf-metadata-unreadable: GGUF header could not be parsed",
            info.get("error") or f"{info.get('read')} bytes read",
            "A GGUF whose header cannot be parsed cannot be checked for an injected chat template."))
        return
    if not info.get("complete"):
        findings.append(finding("agent-checks", "medium", r, 0,
            "gguf-metadata-truncated: chat template may sit beyond the scanned prefix",
            f"parsed {info.get('consumed')} of {info.get('size')} bytes",
            "Raise BEAGLE_MODEL_HEADER_MAX_BYTES or scan the file directly; keys after the truncation point were not inspected."))
    templates = {k: v for k, v in metadata.items() if "chat_template" in k.lower() and isinstance(v, str)}
    if not templates:
        findings.append(finding("agent-checks", "info", r, 0,
            "gguf-metadata: GGUF header inspected (no chat template)",
            f"{len(metadata)} metadata key(s), {info.get('consumed')} bytes read",
            "No tokenizer.chat_template means the consumer uses its own formatting."))
        return
    for key, template in templates.items():
        visible = strip_invisible(template)
        if visible != template:
            findings.append(finding("agent-checks", "high", r, 0,
                "gguf-chat-template-invisible: invisible Unicode hides text in the chat template",
                visible[:140],
                "Zero-width/bidi/tag characters are invisible to a human reading the model card but not to the model."))
        for pattern, title in INJECTION_PATTERNS:
            m = re.search(pattern, visible)
            if m:
                findings.append(finding("agent-checks", "high", r, 0,
                    f"gguf-chat-template-injection: {title}", m.group(0),
                    f"The automatically applied `{key}` contains instructions aimed at the model."))
                break
        cmd = MODEL_COMMAND_RE.search(template)
        if cmd:
            findings.append(finding("agent-checks", "critical", r, 0,
                "gguf-chat-template-command: chat template makes the model print a shell command",
                template[cmd.start():cmd.start() + 240],
                f"`{key}` is applied on every load. Consumers do not run it, but the model reproduces it (the template may say \"copy this line\"); an agent or a human pasting the answer runs it."))
        literal = GGUF_SYSTEM_LITERAL_RE.search(template)
        if literal and GGUF_PREPEND_RE.search(template):
            content = re.sub(r"\s+", " ", literal.group("content")).strip()
            if content:
                findings.append(finding("agent-checks", "medium" if cmd else "high", r, 0,
                    "gguf-chat-template-system: chat template injects a system message into every conversation",
                    content[:140],
                    f"`{key}` prepends its own system message before the user's messages; the model card may not mention it."))
        urls = MODEL_URL_RE.findall(template)
        if urls and not cmd:
            findings.append(finding("agent-checks", "low", r, 0,
                "gguf-chat-template-url: chat template references a remote URL",
                urls[0],
                "The model is told to mention this host; not a request by the scanner, but a dependency in the output."))
        findings.append(finding("agent-checks", "info", r, 0,
            "gguf-metadata: chat template inspected",
            f"`{key}`: {len(template)} chars, {info.get('consumed')} header bytes read",
            "The template is applied automatically by llama.cpp, Ollama and LM Studio. It is data, not executed by the scanner."))


def _weight_metadata_text(root, p, findings, key, text, rule):
    """Report arbitrary metadata text that hides instructions, commands or a remote URL."""
    r = rel(root, p)
    visible = strip_invisible(text)
    if visible != text:
        findings.append(finding("agent-checks", "high", r, 0,
            f"{rule}-invisible: invisible Unicode hides text in {key}",
            visible[:140],
            "Zero-width/bidi/tag characters are invisible to a reader but not to the consumer."))
    for pattern, title in INJECTION_PATTERNS:
        m = re.search(pattern, visible)
        if m:
            findings.append(finding("agent-checks", "high", r, 0,
                f"{rule}-injection: {title}", m.group(0),
                f"`{key}` carries instructions aimed at an agent or the model."))
            break
    cmd = MODEL_COMMAND_RE.search(text)
    if cmd:
        findings.append(finding("agent-checks", "critical", r, 0,
            f"{rule}-command: {key} contains a shell command",
            text[cmd.start():cmd.start() + 240],
            f"`{key}` is free-form metadata; an agent or a human reading it can run the command."))
    urls = MODEL_URL_RE.findall(text)
    if urls:
        findings.append(finding("agent-checks", "low", r, 0,
            f"{rule}-url: {key} references a remote URL", urls[0],
            "The value depends on a host outside the repository."))


def check_safetensors(root, p, findings):
    """Audit the JSON header of a safetensors file; tensor payloads are never read."""
    r = rel(root, p)
    header, info = read_safetensors(p)
    if info.get("lfs"):
        oid, size = info["lfs"]
        findings.append(finding("agent-checks", "medium", r, 0,
            "weight-metadata-unavailable: safetensors weights are a Git LFS pointer, header not inspected",
            f"oid sha256:{oid[:12]}… size {size}",
            "Fetch the header (or scan with network access) before trusting a GREEN verdict on a model repo."))
        return
    if header is None:
        findings.append(finding("agent-checks", "medium", r, 0,
            "safetensors-header-unreadable: safetensors JSON header could not be parsed",
            info.get("error") or f"{info.get('read')} bytes read",
            "A header that cannot be parsed cannot be checked for injected metadata."))
        return
    if not info.get("complete"):
        findings.append(finding("agent-checks", "medium", r, 0,
            "safetensors-header-truncated: header longer than the scanned prefix",
            f"parsed {info.get('consumed')} of {info.get('size')} bytes",
            "Raise BEAGLE_MODEL_HEADER_MAX_BYTES or scan the file directly; metadata beyond the cut was not inspected."))
    tensors = [k for k, v in header.items() if k != "__metadata__" and isinstance(v, dict)]
    meta = header.get("__metadata__")
    keys = sorted(meta) if isinstance(meta, dict) else []
    findings.append(finding("agent-checks", "info", r, 0,
        "safetensors-header: JSON header inspected",
        f"{len(tensors)} tensor(s), metadata keys: {', '.join(keys[:8]) or 'none'}; {info.get('consumed')} bytes",
        "The header names tensors, dtypes, shapes and offsets. The payload is not read."))
    if isinstance(meta, dict):
        for k, v in meta.items():
            if isinstance(v, str) and v:
                _weight_metadata_text(root, p, findings, f"__metadata__.{k}", v, "safetensors-metadata")


def check_weight_header(root, p, findings):
    """Sample the header of any other weight container; never decode the payload as source."""
    r = rel(root, p)
    try:
        with open(p, "rb") as fh:
            head = fh.read(4096)
    except OSError:
        return
    pointer = lfs_pointer(head)
    if pointer:
        oid, size = pointer
        findings.append(finding("agent-checks", "medium", r, 0,
            "weight-metadata-unavailable: model weights are a Git LFS pointer, header not inspected",
            f"oid sha256:{oid[:12]}… size {size}",
            "The header (and any embedded metadata) was not read; fetch it before trusting a GREEN verdict."))
        return
    suffix = p.suffix.lower()
    kind = ""
    if head[:4] == b"PK\x03\x04":
        kind = "ZIP container (PyTorch checkpoint / archive)"
    elif head[:8] == b"\x89HDF\r\n\x1a\n":
        kind = "HDF5 (Keras/TensorFlow weights)"
    elif head[4:8] == b"TFL3":
        kind = "TensorFlow Lite flatbuffer"
    elif suffix == ".onnx":
        props = onnx_prefix_info(head)
        kind = "ONNX protobuf" + (f" (producer {props.get('producer_name')})" if props.get("producer_name") else "")
        for key in ("producer_name", "producer_version", "domain", "doc_string"):
            if isinstance(props.get(key), str) and props[key]:
                _weight_metadata_text(root, p, findings, f"onnx.{key}", props[key], "onnx-metadata")
    elif suffix in (".plan", ".engine"):
        kind = "TensorRT engine"
    elif suffix == ".ot":
        kind = "Optimum/OpenVINO container"
    elif suffix == ".mlmodel":
        kind = "Core ML protobuf"
    findings.append(finding("agent-checks", "info", r, 0,
        "weight-metadata: model-weight header sampled",
        f"{suffix or '(none)'}: {kind or 'binary container'}; {head[:16].hex()}",
        "Only the header was read; the tensor payload is not parsed as source and cannot hide text instructions."))


def _chat_templates_in_json(obj, out, depth=0):
    if depth > 5:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if "chat_template" in str(k):
                if isinstance(v, str):
                    out.append(v)
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, str):
                            out.append(item)
                        elif isinstance(item, dict) and isinstance(item.get("template"), str):
                            out.append(item["template"])
            elif isinstance(v, (dict, list)):
                _chat_templates_in_json(v, out, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            if isinstance(v, (dict, list)):
                _chat_templates_in_json(v, out, depth + 1)


def check_chat_template(root, p, text, findings):
    """Audit chat templates stored as text (`tokenizer_config.json`, `*.jinja`).

    The same payload may live in the GGUF/safetensors metadata or beside it; a model card
    that only mentions one copy must not hide the other.
    """
    ext = p.suffix.lower()
    if ext in (".jinja", ".j2"):
        templates = [text]
    elif ext == ".json" and '"chat_template' in text:
        try:
            data = json.loads(text)
        except ValueError:
            return
        templates = []
        _chat_templates_in_json(data, templates)
    else:
        return
    for template in templates:
        if template and template.strip():
            _weight_metadata_text(root, p, findings, "chat_template", template, "chat-template")


def check_weight(root, p, findings):
    """Dispatch a model-weight file to its format check. Weights are never decoded as text."""
    suffix = p.suffix.lower()
    if suffix == ".gguf":
        check_gguf(root, p, findings)
    elif suffix == ".safetensors":
        check_safetensors(root, p, findings)
    else:
        check_weight_header(root, p, findings)


def shannon(s):
    from collections import Counter
    from math import log2
    n = len(s)
    return -sum(c / n * log2(c / n) for c in Counter(s).values())


DIST_RE = re.compile(r"(^|/)(dist|build|vendor|static|public|assets|out|lib/vendor)/|\.(min|bundle|umd)\.[cm]?js$")


POPULAR = {
    "npm": "react lodash express axios chalk commander debug moment request webpack typescript eslint mongoose prettier dotenv cross-env electron puppeteer nodemon jquery underscore".split(),
    "pypi": "requests numpy pandas django flask urllib3 setuptools boto3 pyyaml cryptography pillow selenium colorama jinja2 pytest openai httpx pydantic fastapi aiohttp".split(),
    "crates": "serde tokio regex reqwest anyhow chrono hyper".split(),
}


def _lev(a, b):
    prev = list(range(len(b) + 1))
    for i, x in enumerate(a, 1):
        cur = [i]
        for j, y in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[-1] + 1, prev[j - 1] + (x != y)))
        prev = cur
    return prev[-1]


def typosquat_of(eco, name):
    k = name.lower().replace("_", "-")
    pop = POPULAR[eco]
    if k in pop or k.startswith("@"):
        return None
    for t in pop:
        if len(t) > 4 and 0 < _lev(k, t) <= 1 + (len(t) > 7):
            return t
        if (sorted(k) == sorted(t) and k != t) or k in (t + "-js", t + "js", t + "-py", "py" + t, "python-" + t, "node-" + t):
            return t
    return None


def dep_names(p, text):
    name = p.name
    out = []
    if name == "package.json":
        try: data = json.loads(text)
        except Exception: return "npm", []
        for sec in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            out += list((data.get(sec) or {}).keys())
        return "npm", out
    if name == "Cargo.toml":
        on = False
        for line in text.split("\n"):
            if line.startswith("["): on = "dependencies" in line; continue
            m = on and re.match(r"\s*([A-Za-z0-9_-]+)\s*=", line)
            if m: out.append(m.group(1))
        return "crates", out
    if re.match(r"requirements.*\.txt$", name):
        for line in text.split("\n"):
            m = re.match(r"\s*([A-Za-z][\w.-]*)", line)
            if m and not line.lstrip().startswith(("-", "#")): out.append(m.group(1))
        return "pypi", out
    if name == "pyproject.toml":
        for m in re.finditer(r"""["']([A-Za-z][\w.-]*)\s*(\[[^\]]*\])?\s*([<>=!~;]|["'])""", text):
            out.append(m.group(1))
        return "pypi", out
    return None, []


def check_obfuscation_deps(root, p, text, findings):
    r = rel(root, p)
    if p.suffix.lower() in (".js", ".mjs", ".cjs") and not DIST_RE.search(r):
        for i, line in enumerate(text.split("\n"), 1):
            if len(line) > 3000 and line.count(" ") < len(line) / 40:
                findings.append(finding("agent-checks", "low", r, i, "minified-outside-dist: minified code in a source path", line[:80] + "...",
                                        "Minified code outside build output can't be reviewed; check it matches its source."))
                break
    eco, names = dep_names(p, text)
    for n in dict.fromkeys(names):
        t = typosquat_of(eco, n) if eco else None
        if t:
            findings.append(finding("agent-checks", "high", r, _line_of(text, n), f"typosquat-dep: {eco} '{n}' looks like '{t}'", n,
                                    "Name is one edit away from a popular package: a common way to slip in malware. Check the registry page before installing."))


# ----------------------------------------------------------------------------
# Repo trust signals (host only, unauthenticated GitHub API; LOW/INFO only)
# ----------------------------------------------------------------------------
# --- Provenance signals: signatures, association, release immutability, fork drift (LOW/INFO only) ---
def trust_provenance(slug, repo, get):
    """Best-effort GitHub API payloads for provenance; never raises, missing data is simply absent."""
    prov: dict[str, Any] = {}
    branch = str(repo.get("default_branch") or "")
    parent = repo.get("parent") or {}
    if branch:
        try:
            c = get(f"repos/{slug}/commits/{urllib.parse.quote(branch, safe='')}")
            ver = ((c.get("commit") or {}).get("verification") or {})
            prov["commit"] = {"verified": ver.get("verified"), "reason": ver.get("reason"),
                              "author": (c.get("author") or {}).get("login")}
        except Exception:
            pass
    try:
        tags = get(f"repos/{slug}/tags?per_page=1")
        if tags:
            tag = tags[0]
            sha = ((tag.get("commit") or {}).get("sha") or "")
            if sha:
                c = get(f"repos/{slug}/commits/{urllib.parse.quote(sha, safe='')}")
                ver = ((c.get("commit") or {}).get("verification") or {})
                prov["tag"] = {"name": tag.get("name"), "verified": ver.get("verified"), "reason": ver.get("reason")}
    except Exception:
        pass
    try:
        rel = get(f"repos/{slug}/releases/latest")
        if rel and rel.get("immutable") is not None:
            prov["release"] = {"tag": rel.get("tag_name"), "immutable": rel.get("immutable")}
    except Exception:
        pass
    if repo.get("fork") and parent.get("full_name") and branch:
        owner = ((repo.get("owner") or {}).get("login") or "")
        base = str(parent.get("default_branch") or "main")
        try:
            cmp = get(f"repos/{parent['full_name']}/compare/{urllib.parse.quote(base, safe='')}"
                      f"...{owner}:{branch}")
            prov["fork"] = {"upstream": parent.get("full_name"), "ahead": cmp.get("ahead_by"),
                             "files": len(cmp.get("files") or [])}
        except Exception:
            pass
    return prov


def trust_findings(requested, repo, owner, contributors, now=None, provenance=None):
    import datetime as D
    now = now or D.datetime.now(D.timezone.utc)
    age = lambda s: (now - D.datetime.fromisoformat(s.replace("Z", "+00:00"))).days
    ra, st = age(repo["created_at"]), repo.get("stargazers_count", 0)
    oa = age(owner["created_at"]) if owner and owner.get("created_at") else None
    T = lambda sev, rule, txt: finding("trust", sev, "(github)", 0, f"{rule}: {txt}", "", "Context signal only; never decides the verdict alone.")
    fs = [T("info", "trust-signals", f"repo {ra}d old, {st} stars, {repo.get('forks_count', 0)} forks, {contributors} contributors, owner {oa if oa is not None else '?'}d old")]
    if repo.get("full_name", requested).lower() != requested.lower():
        fs.append(T("low", "repo-moved", f"{requested} now resolves to {repo['full_name']} (renamed or transferred)"))
    if ra < 30: fs.append(T("low", "young-repo", f"repo created {ra} days ago"))
    if oa is not None and oa < 90: fs.append(T("low", "young-owner", f"owner account {oa} days old"))
    if st >= 500 and ra < 60: fs.append(T("low", "star-spike", f"{st} stars in {ra} days"))
    if contributors <= 1 and st >= 200: fs.append(T("low", "single-contributor", f"{st} stars but one contributor"))
    if repo.get("archived"): fs.append(T("info", "archived", "repo is archived"))
    prov = provenance or {}
    commit = prov.get("commit") or {}
    if commit:
        if commit.get("verified") is False:
            fs.append(T("info", "commit-unsigned",
                        f"default-branch commit is not signed (reason: {commit.get('reason') or 'unknown'})"))
        if not commit.get("author"):
            fs.append(T("low", "commit-unassociated",
                        "default-branch commit author email is not linked to a GitHub account"))
    tag = prov.get("tag") or {}
    if tag and tag.get("verified") is False:
        fs.append(T("info", "tag-unsigned",
                    f"latest tag {tag.get('name') or '?'} points at an unsigned commit "
                    f"(reason: {tag.get('reason') or 'unknown'})"))
    release = prov.get("release") or {}
    if release.get("immutable") is True:
        fs.append(T("info", "release-immutable", f"latest release {release.get('tag') or '?'} is immutable"))
    elif release.get("immutable") is False:
        fs.append(T("low", "release-mutable",
                    f"latest release {release.get('tag') or '?'} is not immutable: its tag or assets can be replaced"))
    fork = prov.get("fork") or {}
    if fork:
        ahead, files = fork.get("ahead"), fork.get("files")
        if ahead or files:
            fs.append(T("low", "fork-drift",
                        f"{ahead} commit(s) ahead, {files} file(s) changed vs upstream {fork.get('upstream') or '?'}"))
        else:
            fs.append(T("info", "fork-synced", "fork has no commits ahead of upstream"))
    return fs


def trust_signals(target):
    m = re.match(r"^(?:https?://|git@|ssh://git@)github\.com[/:]([^/]+)/([^/#?]+?)(?:\.git)?/?$", target)
    if not m:
        return [], None
    slug = f"{m.group(1)}/{m.group(2)}"
    api = os.environ.get("BEAGLE_GITHUB_API", "https://api.github.com")
    def get(path, want_headers=False):
        req = urllib.request.Request(f"{api}/{path}", headers={"Accept": "application/vnd.github+json", "User-Agent": "repobeagle"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read()
            return (json.loads(body or b"null"), resp.headers) if want_headers else json.loads(body)
    try:
        repo = get(f"repos/{slug}")
        try: owner = get(f"users/{repo['owner']['login']}")
        except Exception: owner = None
        contributors = 1
        try:
            data, hdr = get(f"repos/{slug}/contributors?per_page=1&anon=1", True)
            lm = re.search(r'[?&]page=(\d+)>;\s*rel="last"', hdr.get("Link", "") or "")
            contributors = int(lm.group(1)) if lm else len(data or [])
        except Exception:
            pass
        provenance = trust_provenance(slug, repo, get)
        return trust_findings(slug, repo, owner, contributors, provenance=provenance), None
    except Exception as ex:
        return [], f"trust signals skipped (GitHub API unavailable or rate-limited: {str(ex)[:80]})"


# --- Workspace / monorepo attribution: package boundaries and per-package first-party inference -----
MAX_WORKSPACE_PACKAGES = int(os.environ.get("BEAGLE_MAX_PACKAGES", "50") or 50)




def _package_display_name(directory):
    """Manifest-derived package name (never executes anything), or the directory name."""
    pkg = _json_file(directory / "package.json")
    if isinstance(pkg, dict) and pkg.get("name"):
        return str(pkg["name"])
    try:
        text = (directory / "Cargo.toml").read_text(errors="replace")
        m = re.search(r'(?ms)^\[package\].*?^\s*name\s*=\s*"([^"]+)"', text)
        if m:
            return m.group(1)
    except OSError:
        pass
    try:
        text = (directory / "pyproject.toml").read_text(errors="replace")
        m = re.search(r'(?ms)^\[project\].*?^\s*name\s*=\s*"([^"]+)"', text)
        if m:
            return m.group(1)
    except OSError:
        pass
    try:
        text = (directory / "go.mod").read_text(errors="replace")
        m = re.search(r"(?m)^module\s+(\S+)", text)
        if m:
            return m.group(1).rsplit("/", 1)[-1]
    except OSError:
        pass
    return directory.name


def workspace_packages(root):
    """Detected monorepo packages: [{name, path, kind}] sorted, capped.

    Reads npm/pnpm/yarn workspaces, Cargo workspaces, go.work modules and nested Python projects;
    never executes anything and never leaves the tree.
    """
    root = Path(root)
    found: dict[str, str] = {}

    def add(rel, kind):
        if rel in found:
            return
        d = root / rel
        if d.is_dir() and rel != ".":
            found[str(Path(rel).as_posix())] = kind

    def add_globs(patterns, marker, kind):
        for pattern in patterns or []:
            if not isinstance(pattern, str):
                continue
            for d in sorted(root.glob(pattern)):
                if d.is_dir() and (d / marker).is_file():
                    add(d.relative_to(root).as_posix(), kind)

    pkg = _json_file(root / "package.json")
    if isinstance(pkg, dict):
        ws = pkg.get("workspaces")
        if isinstance(ws, dict):
            ws = ws.get("packages")
        if isinstance(ws, list):
            add_globs(ws, "package.json", "npm")
    try:
        pnpm = parse_yaml_subset((root / "pnpm-workspace.yaml").read_text(encoding="utf-8"))
        if isinstance(pnpm, dict):
            add_globs(pnpm.get("packages") or [], "package.json", "npm")
    except (OSError, ValueError):
        pass
    try:
        cargo = (root / "Cargo.toml").read_text(errors="replace")
        if re.search(r"(?m)^\[workspace\]", cargo):
            members = re.search(r"(?ms)^\[workspace\].*?^\s*members\s*=\s*\[(.*?)\]", cargo)
            for member in re.findall(r'"([^"]+)"', members.group(1) if members else ""):
                if any(ch in member for ch in "*?["):
                    add_globs([member], "Cargo.toml", "cargo")
                else:
                    add(Path(member).as_posix().lstrip("./"), "cargo")
    except OSError:
        pass
    try:
        gowork = (root / "go.work").read_text(errors="replace")
        block = re.search(r"(?ms)^use\s*\((.*?)^\)", gowork)
        if block:
            uses = [ln.strip().strip('"') for ln in block.group(1).splitlines() if ln.strip()]
        else:
            uses = re.findall(r"(?m)^use\s+(\S+)", gowork)
        for use in uses:
            add(Path(use).as_posix().lstrip("./"), "go")
    except OSError:
        pass
    for p in iter_files(root):
        if p.name in ("pyproject.toml", "setup.py"):
            d = p.parent
            if d != root and (d / p.name).is_file():
                add(d.relative_to(root).as_posix(), "python")
    detected = [{"name": _package_display_name(root / rel), "path": rel, "kind": kind}
                for rel, kind in sorted(found.items())]
    return detected[:MAX_WORKSPACE_PACKAGES], detected[MAX_WORKSPACE_PACKAGES:]


def run_model_checks(root):
    """(findings, files) for model-weight headers and template files only. Static and pure
    Python, so the host can run it when the pinned container image predates these readers."""
    findings: list[dict] = []
    files = 0
    for p in iter_files(root):
        if p.suffix.lower() in WEIGHT_EXT:
            files += 1
            check_weight(root, p, findings)
        elif p.suffix.lower() in (".jinja", ".j2") or (
                p.suffix.lower() == ".json" and p.name.lower() in ("tokenizer_config.json", "chat_template.json")):
            text = read_text(p)
            if text is not None:
                files += 1
                check_chat_template(root, p, text, findings)
    return findings, files


def run_agent_checks(root, deadline=None, state=None):
    root = Path(root)
    """Regex/agent checks over the tree. `deadline` (monotonic) bounds the work; `state` records partial results."""
    if state is not None:
        state.setdefault("complete", True)
        state.setdefault("skipped", [])
    findings: list[dict] = []
    telemetry: dict[str, Any] = {}
    optouts: set[str] = set()
    optouts_code: set[str] = set()
    privacy: dict[str, Any] = {}
    masks: set[str] = set()
    privacy_doc = None
    own = own_domains(root)
    try:
        policy = load_repo_config(root) or {}
    except ConfigError:
        policy = {}
    for host in policy.get("hosts") or []:
        own.add(host)
    workspace, dropped = workspace_packages(root)
    own_by_package = {pkg["path"]: own_domains(root / pkg["path"]) | set(policy.get("hosts") or [])
                      for pkg in workspace}

    def own_for(relpath):
        for pkg in workspace:
            base = pkg["path"]
            if relpath == base or relpath.startswith(base + "/"):
                return own_by_package[base]
        return own
    prose: list[str] = []
    nfiles = 0
    def check_one(p):
        nonlocal privacy_doc
        r = rel(root, p)
        low = p.name.lower()
        if low in PRIVACY_DOC_NAMES or PRIVACY_DOC_RE.search(r):
            privacy_doc = privacy_doc or r
        if low.endswith(ARCHIVE_EXT):
            enc = zip_encrypted(p)
            if enc:
                findings.append(finding("agent-checks", "high", r, 0, "Password-protected/encrypted archive (uninspectable)", low,
                                        "Encrypted archives can't be scanned; this is how malware samples are shipped. Never extract on a real machine."))
            else:
                findings.append(finding("agent-checks", "medium", r, 0, "Archive in repo (contents not scanned)", low, "Archives are never extracted; review where it came from."))
            return
        if p.suffix.lower() in WEIGHT_EXT:
            check_weight(root, p, findings)
            return
        if p.suffix.lower() in BINARY_EXT:
            findings.append(finding("agent-checks", "medium", r, 0, "Prebuilt binary/compiled artifact in repo", p.suffix, "Binaries can't be reviewed as source; verify where they came from."))
            return
        if check_magic(root, p, findings):
            return
        text = read_text(p)
        if text is None:
            return
        if p.suffix.lower() in PROSE_EXT or low.startswith(("readme", "privacy", "security", "notice")):
            if sum(len(x) for x in prose) < 800_000:
                prose.append(text)
        check_unicode(root, p, text, findings)
        check_agent_text(root, p, text, findings)
        check_exfil(root, p, text, findings)
        check_patterns(root, p, text, findings)
        check_mcp(root, p, text, findings)
        check_tool_poisoning(root, p, text, findings)
        check_install_hooks(root, p, text, findings)
        check_markdown_hidden(root, p, text, findings)
        check_build_hooks(root, p, text, findings)
        check_workflows(root, p, text, findings)
        check_chat_template(root, p, text, findings)
        check_obfuscation_deps(root, p, text, findings)
        if len(text) <= 2_000_000:       # huge/minified files are generated; keep the scan cheap
            check_telemetry(root, p, text, telemetry, optouts, optouts_code)
            check_privacy(root, p, text, privacy, own_for(r))
            check_privacy_signals(root, p, text, privacy, masks)
    skipped_slow: list[str] = []
    for p in iter_files(root):
        nfiles += 1
        if nfiles > 50000:
            break
        if deadline is not None and time.monotonic() >= deadline:
            if state is not None:
                state["complete"] = False
            break
        budget = SCAN_FILE_SECONDS
        if deadline is not None:
            budget = max(0.01, min(SCAN_FILE_SECONDS, deadline - time.monotonic()))
        try:
            with _scan_alarm(budget):
                check_one(p)
        except ScanDeadline:
            skipped_slow.append(rel(root, p))
            if deadline is not None and time.monotonic() >= deadline:
                if state is not None:
                    state["complete"] = False
                break
    if skipped_slow:
        if state is not None:
            state["skipped"].extend(skipped_slow)
            state["complete"] = False
        for sf in skipped_slow[:5]:
            findings.append(finding("agent-checks", "info", sf, 0,
                                     "Slow-file: skipped after the per-file alarm",
                                     f"{SCAN_FILE_SECONDS:.0f}s budget",
                                     "The regex checks on this file exceeded the per-file budget; the rest of the scan "
                                     "continued. Exclude generated files or split the file if findings are expected there."))
    try:
        check_supply_chain(root, findings)
    except Exception as ex:
        findings.append(finding("agent-checks", "info", "(repo)", 0,
                                 "supply-chain checks failed", type(ex).__name__,
                                 "The submodule/Dockerfile/dependency-index checks could not complete; the rest of the scan continued."))
    tf = telemetry_findings(
        telemetry, optouts, optouts_code)
    tracking_kinds = {"telemetry-analytics", "telemetry-ads", "telemetry-session-replay", "telemetry-crash", "telemetry-apm"}
    tracked = {_rule_of(f) for f in tf} & tracking_kinds
    pf = privacy_findings(privacy)
    if not tracked:
        pf = [f for f in pf if not f["title"].startswith("telemetry-identify")]
    findings += tf + pf
    vendor_names = {f["title"].split(": ", 1)[1].replace(" (transitive)", "") for f in tf if f["title"].startswith("telemetry-")}
    if privacy_doc and vendor_names and prose:
        doc_text = " ".join(prose).casefold()
        missing = sorted(v for v in vendor_names if v.casefold() not in doc_text)
        if missing:
            findings.append(finding("privacy", "info", "(repo)", 0, "undisclosed-vendor: trackers not named in any doc",
                                     ", ".join(missing[:6]) + (" …" if len(missing) > 6 else ""),
                                     "The repo has a privacy doc/README but these detected vendors are not named there; check the policy discloses them."))
    dnt = any(o == "Do-Not-Track" or o.startswith("DO_NOT_TRACK") for o in optouts_code)
    dnt_documented = dnt or any(o == "Do-Not-Track" or o.startswith("DO_NOT_TRACK") for o in optouts)
    if tracked:
        if dnt:
            findings.append(finding("privacy", "info", "(repo)", 0, "dnt-respect: Do-Not-Track / opt-out is referenced",
                                     ", ".join(sorted(optouts)[:3]),
                                     "Telemetry exists and the repo references a Do-Not-Track/opt-out switch, so the signal can be honoured."))
        elif optouts_code:
            findings.append(finding("privacy", "info", "(repo)", 0,
                                     "dnt-respect: opt-out handled in code (Do-Not-Track not read)",
                                     ", ".join(sorted(optouts_code)[:3]),
                                     "The repo calls an SDK opt-out switch, but does not read navigator.doNotTrack/Global Privacy Control; browser-level signals may still be ignored."))
        else:
            findings.append(finding("privacy", "low", "(repo)", 0,
                                     "dnt-respect: Do-Not-Track only documented, not handled" if dnt_documented else
                                     "dnt-respect: trackers but no Do-Not-Track/opt-out reference",
                                     ", ".join(sorted(optouts)[:3]) if dnt_documented else "no DO_NOT_TRACK / navigator.doNotTrack found",
                                     "The docs mention an opt-out but no code reads it, so the signal may be ignored."
                                     if dnt_documented else
                                     "Browsers send Do-Not-Track and DO_NOT_TRACK is a de-facto standard; without a reference these signals are ignored."))
        if "telemetry-session-replay" in tracked:
            if masks:
                findings.append(finding("privacy", "info", "(repo)", 0, "session-replay-mask: masking option referenced",
                                         ", ".join(sorted(masks)[:4]),
                                         "The repo configures input/text masking for session replay, so recorded PII can be limited."))
            else:
                findings.append(finding("privacy", "low", "(repo)", 0, "session-replay-mask: session replay with no masking option found",
                                         "no maskAllInputs/maskText/data-hj-suppress/… in the repo",
                                         "Session replay vendors record DOM/inputs; without a masking directive the vendor defaults decide what PII is captured. Verify them."))
        if not any(f["title"].startswith("consent-manager") for f in pf) and \
           tracked & {"telemetry-analytics", "telemetry-ads", "telemetry-session-replay"}:
            findings.append(finding("privacy", "low", "(repo)", 0, "consent-gating: trackers with no consent manager detected",
                                     "no CMP found",
                                     "Analytics/ads/session replay are present but no OneTrust/Cookiebot/Osano/… was detected; verify tracking waits for consent."))
    rules = {_rule_of(f) for f in pf}
    if rules & {"ios-tracking-domain", "ios-data-type", "ios-purpose-string", "ios-api-category"} and \
       tracked & {"telemetry-ads", "telemetry-analytics"}:
        if "ios-tracking" in rules:
            findings.append(finding("privacy", "info", "(repo)", 0, "ios-tracking-declaration: manifest declares tracking",
                                     "PrivacyInfo.xcprivacy with <key>NSPrivacyTracking</key><true/>",
                                     "The iOS privacy manifest declares tracking and ad/analytics SDKs are present, so the declaration is consistent."))
        else:
            findings.append(finding("privacy", "low", "(repo)", 0, "ios-tracking-declaration: manifest omits NSPrivacyTracking",
                                     "PrivacyInfo.xcprivacy without <key>NSPrivacyTracking</key><true/>",
                                     "An iOS privacy manifest exists but does not declare tracking, while ad/analytics SDKs are present; "
                                     "Apple may treat data linked to identity as tracking."))
    collects = bool(tracked) or bool(rules & {"pii-log", "pii-email", "pii-phone", "pii-address", "client-id"})
    if collects and "data-retention" not in rules:
        findings.append(finding("privacy", "low", "(repo)", 0, "data-retention: data collected but no retention/expiry setting found",
                                 "no retention/ttl/expiry/delete_after value in the repo",
                                 "Personal data is collected but nothing says when it is deleted; check the privacy policy."))
    ga = any("Google Analytics" in f["title"] for f in tf)
    if ga and any(f["title"].startswith("consent-manager") for f in pf) and "consent-mode" not in rules:
        findings.append(finding("privacy", "low", "(repo)", 0, "consent-mode: Google Analytics with a CMP but no Consent Mode",
                                 "no analytics_storage/ad_storage consent signals found",
                                 "Google requires Consent Mode v2 in the EEA; without it tags may run before consent."))
    if "upload-surface" in rules and "upload-limit" not in rules:
        findings.append(finding("privacy", "low", "(repo)", 0, "upload-limit: uploads accepted with no size cap found",
                                 "no max file/body size setting in the repo",
                                 "Unbounded request bodies can carry more data than intended; check the server/framework default."))
    if rules & {"external-endpoint", "third-party-cdn", "insecure-endpoint"} and "referrer-policy" not in rules:
        findings.append(finding("privacy", "low", "(repo)", 0, "referrer-policy: third-party requests with no Referrer-Policy",
                                 "no Referrer-Policy header or <meta name=referrer>",
                                 "By default the full page URL (including path and query) is sent as Referer to third parties."))
    cap_keys = {f["title"].split(": ", 1)[1] for f in pf if f["title"].startswith("browser-capability: ")}
    if cap_keys & {"camera/microphone", "geolocation", "screen capture", "clipboard"} and "permissions-policy" not in rules:
        findings.append(finding("privacy", "low", "(repo)", 0, "permissions-policy: sensor APIs used with no Permissions-Policy",
                                 ", ".join(sorted(cap_keys & {"camera/microphone", "geolocation", "screen capture", "clipboard"})),
                                 "A Permissions-Policy header lets you keep camera/microphone/geolocation off for third-party iframes."))
    if privacy_doc:
        findings.append(finding("privacy", "info", privacy_doc, 1, "privacy-doc: privacy policy present", privacy_doc,
                                 "The repo ships a privacy policy/manifest; read it to see what it admits to collecting."))
    elif prose and (m := PRIVACY_LINK_RE.search(" ".join(prose))):
        findings.append(finding("privacy", "info", "(repo)", 0, "privacy-doc: privacy policy linked (external)",
                                 (m.group(1) or m.group(2))[:140],
                                 "No policy file, but the docs link an external privacy policy; read it to see what is disclosed."))
    elif any(f["severity"] in ("high", "medium", "low") for f in tf + pf):
        findings.append(finding("privacy", "low", "(repo)", 0, "privacy-doc: no privacy policy file",
                                 "expected PRIVACY.md or PrivacyInfo.xcprivacy",
                                 "The repo collects/transmits data but ships no privacy policy/manifest file."))
    if workspace:
        for f in findings:
            relf = str(f.get("file") or "")
            for pkg in workspace:
                base = pkg["path"]
                if relf == base or relf.startswith(base + "/"):
                    f["package"] = pkg["name"]
                    f["package_path"] = base
                    break
        if state is not None:
            state["workspace"] = {"packages": workspace, "dropped": len(dropped)}
    return findings, nfiles