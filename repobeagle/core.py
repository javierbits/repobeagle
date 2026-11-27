import argparse, base64, concurrent.futures, difflib, hashlib, hmac, json, os, platform, queue, re, shlex, shutil, signal, subprocess, sys, tempfile, threading, time, unicodedata, uuid, zipfile
import urllib.error, urllib.parse, urllib.request
from datetime import date, datetime, timezone
from fnmatch import fnmatchcase
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from pathlib import Path


# --- cross-module imports ---



HERE = Path(__file__).resolve().parent.parent


RULES_DIR = HERE / "rules"


def entry_command():
    """argv prefix that re-enters this scanner: the checkout shim when present, else the package."""
    shim = Path(__file__).resolve().parent.parent / "repobeagle.py"
    if shim.is_file():
        return [sys.executable, str(shim)]
    return [sys.executable, "-m", "repobeagle"]

def _read_version(here=None):
    """Single source of truth: the VERSION file (also read by install.sh).

    A wheel install ships it under share/repobeagle; the checkout keeps it next to the module.
    """
    here = Path(here) if here else HERE
    for cand in (here / "VERSION", Path(sys.prefix) / "share" / "repobeagle" / "VERSION"):
        try:
            value = cand.read_text().strip()
        except OSError:
            continue
        if value:
            return value
    return "v1.0.0"


RELEASE = _read_version()                 # e.g. v1.0.0 (image tag)


VERSION = RELEASE.lstrip("v")             # e.g. 1.0.0 (display / JSON)


IMAGE = os.environ.get("BEAGLE_IMAGE", f"ghcr.io/javierbits/repobeagle:{RELEASE}")


SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


MAX_FILE = 1_500_000


SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", "dist", "build", "target", ".mypy_cache"}


# strictness: verdict thresholds
PROFILES: dict[str, dict[str, Any]] = {
    # RED if any finding >= red_sev (count >= red_count); YELLOW if any >= yellow_sev
    "strict":   {"red": [("high", 1)],                    "yellow": "low"},
    "balanced": {"red": [("critical", 1)],                "yellow": "medium"},
    "relaxed":  {"red": [("critical", 1)],                "yellow": "high"},
}


def finding(tool, sev, file, line, title, snippet="", meaning=""):
    """A finding with its stable rule id materialized (no consumer splits titles)."""
    rule = str(title).split(":")[0].split(" (")[0]
    return {"tool": tool, "severity": sev, "rule": rule, "file": file, "line": line, "title": title,
            "snippet": re.sub(r"\s+", " ", (snippet or "")).strip()[:160], "meaning": meaning}


# ----------------------------------------------------------------------------
# File helpers
# ----------------------------------------------------------------------------
def iter_files(root):
    """Walk the tree in a stable (sorted) order: findings that aggregate per rule/key keep the
    same first file:line and snippet regardless of the filesystem's readdir order."""
    root = Path(root)
    for dp, dns, fns in os.walk(root, followlinks=False):
        dns[:] = sorted(d for d in dns if d not in SKIP_DIRS)
        for fn in sorted(fns):
            p = Path(dp) / fn
            if p.is_symlink():
                continue
            yield p


def read_text(p):
    try:
        if p.stat().st_size > MAX_FILE:
            return None
        b = p.read_bytes()
    except OSError:
        return None
    if b"\x00" in b[:8192]:
        return None
    return b.decode("utf-8", errors="replace")


def rel(root, p):
    return str(Path(p).relative_to(root))


def _is_comment(line):
    return line.lstrip().startswith(("//", "#", "*", "/*", "<!--", ";", "--"))


def _in_line_comment(line, pos):
    """True when the host at pos sits in an inline comment (URLs contain // after the scheme colon)."""
    before = line[:pos]
    if "#" in before:
        return True
    i = before.find("//")
    while i != -1:
        if i == 0 or before[i - 1] != ":":
            return True
        i = before.find("//", i + 2)
    return False


# ----------------------------------------------------------------------------
# Agent-specific checks (pure Python)
# ----------------------------------------------------------------------------
ZW = set(map(chr, [0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x180E, 0xFEFF, 0x00AD]))


BIDI = set(map(chr, list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A))))


def is_tag(c): return 0xE0000 <= ord(c) <= 0xE007F


INVIS_NAMES = {"\u200b": "ZERO WIDTH SPACE", "\u200c": "ZWNJ", "\u200d": "ZWJ", "\u2060": "WORD JOINER", "\ufeff": "ZWNBSP/BOM"}


AGENT_FILE_RE = re.compile(r"(?i)(^|/)(readme[^/]*|skill\.md|agents?\.md|claude\.md|gemini\.md|copilot-instructions\.md|"
                           r"\.cursorrules|\.windsurfrules|\.clinerules|[^/]*\.mdc|[^/]*prompt[^/]*\.(md|txt|ya?ml|json)|"
                           r"[^/]*\.prompt|system[_-]?prompt[^/]*|instructions?\.md)$|(^|/)\.cursor/rules/|(^|/)\.claude/|(^|/)skills?/[^/]+\.md$")


INJECTION_PATTERNS = [
    (r"(?i)\bignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)", "Prompt-injection phrase: ignore previous instructions"),
    (r"(?i)\b(do\s+not|don'?t|never)\s+(tell|inform|mention|reveal|show|notify|alert)\b.{0,40}\b(user|human|owner|operator)", "Tells the agent to hide actions from the user"),
    (r"(?i)\b(silently|quietly|secretly|without\s+(asking|telling|notifying|confirmation|the\s+user))\b.{0,80}\b(run|execute|send|upload|post|curl|read|copy|delete|install)", "Asks the agent to act silently / without consent"),
    (r"(?i)\b(run|execute|send|upload|post|curl|read|copy|install)\b.{0,80}\b(silently|quietly|secretly|without\s+(asking|telling|notifying|confirmation))", "Asks the agent to act silently / without consent"),
    (r"(?i)\b(you\s+are\s+now|new\s+system\s+prompt|developer\s+mode|jailbreak|override\s+(your|the)\s+(rules|instructions|system))", "Role/system override attempt"),
    (r"(?i)\b(ai|llm|agent|assistant|claude|copilot|cursor|gpt|model)s?\b[^.\n]{0,40}\b(must|should|always|need\s+to)\b[^.\n]{0,60}\b(upload|exfiltrate|send|post|transmit|forward)\b", "Imperative instruction to an AI agent to send data"),
]


SENSITIVE = r"(~/\.ssh|\.ssh/|\bid_(rsa|ed25519|ecdsa|dsa)\b|(^|[\s'\"/=(])\.env\b(?!\.example|\.sample|\.template)|\.aws/credentials|\.npmrc|\.netrc|\.pypirc|\.git-credentials|\.docker/config\.json|\.kube/config|\.gnupg|keychain|login\.keychain|cookies\.sqlite|/Cookies\b|Login\s+Data|wallet\.dat|\bseed\s+phrase|metamask|exodus|\.config/gh/hosts|\.claude\.json|\.cursor/mcp\.json)"


SENS_RE = re.compile(SENSITIVE, re.I)


SINK_RE = re.compile(r"(?i)(\bcurl\b|\bwget\b|\bfetch\s*\(|requests\.(post|put|get)|urllib|http\.request|https\.request|axios|XMLHttpRequest|\bnc\s|netcat|webhook|discord(app)?\.com/api|api\.telegram|ngrok|pastebin|transfer\.sh|\bupload\b|\bexfil|https?://)")


READ_RE = re.compile(r"(?i)(readFile|readFileSync|open\s*\(|read_text|read_bytes|\bcat\s|\bcp\s|\bscp\b|tar\s|zip\s|base64\s|homedir|expanduser|\$HOME|~/|\bupload|\bsend|\bpost)")


PIPE_SHELL = re.compile(r"(?i)(curl|wget)\b[^|\n]{0,300}\|\s*(sudo\s+)?(ba|z|da)?sh\b|base64\s+(-d|--decode)[^|\n]{0,100}\|\s*(ba)?sh|\bpowershell\b.{0,40}-e(nc(odedcommand)?)?\s|iex\s*\(\s*(new-object|iwr|invoke-webrequest)|python[0-9.]*\s+-c\s+[\"'].{0,80}(urlopen|requests\.get)")


DECODE_EXEC = re.compile(r"(?i)(eval|exec|Function)\s*\(\s*(atob|base64\.b64decode|Buffer\.from\([^)]*base64|zlib\.decompress|codecs\.decode|bytes\.fromhex)")


CODE_EXT = {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".vue", ".svelte", ".astro", ".py", ".sh", ".bash", ".zsh", ".rb", ".go", ".rs", ".ps1", ".php", ".pl", ".lua", ".java", ".kt", ".cs", ".swift", ".bat", ".cmd"}


DOC_EXT = {".md", ".mdx", ".rst", ".txt", ".html", ".adoc"}


def strip_invisible(s):
    return "".join(c for c in s if c not in ZW and c not in BIDI and not is_tag(c))


def decode_tags(s):
    return "".join(chr(ord(c) - 0xE0000) for c in s if is_tag(c) and 0x20 <= ord(c) - 0xE0000 < 0x7F)


def _line_of(text, needle):
    if not needle:
        return 1
    idx = text.find(needle)
    return text[:idx].count("\n") + 1 if idx >= 0 else 1


def _url_host(url):
    """Hostname of a git/http URL, including scp-like `git@host:owner/repo`."""
    url = (url or "").strip()
    if not url:
        return ""
    if "://" in url:
        try:
            return (urllib.parse.urlsplit(url).hostname or "").lower()
        except ValueError:
            return ""
    m = re.match(r"^(?:[^@/]+@)?([^:/]+):", url)
    return m.group(1).lower() if m else ""


def _gitmodules_entries(root):
    """[{name, path, url, branch, line}] from `.gitmodules`; empty when absent."""
    p = Path(root) / ".gitmodules"
    try:
        text = read_text(p) or ""
    except OSError:
        return []
    mods = []
    cur = None
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            name = line.strip("[]").strip()
            cur = {"name": name.split('"')[1] if '"' in name else name.replace("submodule", "").strip(),
                   "path": "", "url": "", "branch": "", "line": i}
            if name.lower().startswith("submodule"):
                mods.append(cur)
            else:
                cur = None
            continue
        if cur is not None and "=" in line:
            k, v = line.split("=", 1)
            k, v = k.strip().lower(), v.strip()
            if k in ("path", "url", "branch"):
                cur[k] = v
    return mods


def _origin_host(root):
    try:
        text = (Path(root) / ".git" / "config").read_text(errors="replace")
    except OSError:
        return ""
    section = ""
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            section = s[1:-1].strip().lower()
            continue
        if section.startswith('remote "origin"') and s.lower().startswith("url"):
            return _url_host(s.split("=", 1)[1]) if "=" in s else ""
    return ""


# ----------------------------------------------------------------------------
# Privacy: third-party endpoints, browser storage/cookies, platform permissions
# ----------------------------------------------------------------------------
PROSE_EXT = {".md", ".mdx", ".markdown", ".rst", ".adoc"}


TEST_SRC_RE = re.compile(r"(?i)(^|/)(tests?|__tests__|spec)/")


I18N_FILE_RE = re.compile(r"(?i)(^|/)(locales?|i18n|translations?|l10n)/")


GENERATED_DIR_RE = re.compile(r"(?i)(^|/)(generated|__generated__|gen)/")


TEST_FILE_RE = re.compile(r"(?i)(^|/)[^/]*\.(?:test|spec)\.[a-z]+$")


PACKAGE_MANAGER_RE = re.compile(r'"packageManager"\s*:')


AUTHORS_FILE_RE = re.compile(r"(?i)(^|/)(authors|contributors|credits|thanks)(\.\w+)?$")


LICENSE_FILE_RE = re.compile(r"(?i)(^|/)(licen[cs]e|copying|notice)([.-][^/]*)?$")


URL_HOST_RE = re.compile(r"(?i)\b(https?|wss?)://([a-z0-9][a-z0-9.-]*[a-z0-9])")


NON_NET_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "example.com", "example.org", "www.w3.org", "w3.org",
                 "purl.org", "schema.org", "json-schema.org", "creativecommons.org", "opensource.org", "spdx.org",
                 "xmlns.com", "unicode.org", "ietf.org", "rfc-editor.org", "python.org", "nodejs.org",
                 "schemas.android.com", "schemas.xmlsoap.org"}


THIRD_PARTY_CDN = {"fonts.googleapis.com", "fonts.gstatic.com", "use.typekit.net", "cdn.jsdelivr.net", "unpkg.com",
                   "fonts.bunny.net", "api.fontshare.com", "fonts.cdnfonts.com",
                   "cdnjs.cloudflare.com", "esm.sh", "cdn.skypack.dev", "code.jquery.com", "ajax.googleapis.com",
                   "cdn.tailwindcss.com", "static.cloudflareinsights.com"}


COOKIE_WRITE_RE = re.compile(r"(document\.cookie\s*=|\bCookies\.(?:set|remove)\s*\()")


STORAGE_RE = re.compile(r"(?i)(localStorage|sessionStorage)\.(setItem|removeItem)|"
                          r"(localStorage|sessionStorage)\.[A-Za-z_$][\w$]*\s*=[^=]|\bindexedDB\b")


CONSENT_RE = re.compile(r"(?i)(onetrust|optanon|cookiebot|osano|cookieyes|klaro|tarteaucitron|cookieconsent|"
                        r"consent-manager|quantcast|didomi|usercentrics|borlabs|iubenda|complianz|axeptio|cookiehub|"
                        r"cookieinformation|termly|consentmanager|sirdata|civicuk|cookielaw\.org|otSDKStub|usercentrics\.eu|sourcepoint|"
                        r"sp-prod\.net|privacy-mgmt\.com|trustarc|truste\.com|cookiepro|\bfides\b|cookiefirst)")


SET_COOKIE_RE = re.compile(r"(?i)['\"]set-cookie['\"]")


SET_COOKIE_READ_RE = re.compile(r"(?i)(\.get|\.getheader|header\(\)\.get)\([^)]*['\"]set-cookie")


ANDROID_PERMS = {
    "ACCESS_FINE_LOCATION": ("high", "precise location"), "ACCESS_BACKGROUND_LOCATION": ("high", "location in the background"),
    "ACCESS_COARSE_LOCATION": ("medium", "approximate location"), "CAMERA": ("high", "camera"),
    "RECORD_AUDIO": ("high", "microphone"), "READ_CONTACTS": ("high", "contacts"),
    "WRITE_CONTACTS": ("medium", "contacts"), "READ_SMS": ("high", "SMS"), "SEND_SMS": ("medium", "SMS"),
    "RECEIVE_SMS": ("medium", "SMS"), "READ_CALL_LOG": ("high", "call log"), "READ_PHONE_STATE": ("medium", "phone state / identifiers"),
    "READ_EXTERNAL_STORAGE": ("medium", "shared storage"), "WRITE_EXTERNAL_STORAGE": ("medium", "shared storage"),
    "READ_MEDIA_IMAGES": ("medium", "photos"), "READ_MEDIA_VIDEO": ("medium", "videos"), "READ_MEDIA_AUDIO": ("medium", "audio files"),
    "ACCESS_MEDIA_LOCATION": ("high", "photo location metadata"), "BODY_SENSORS": ("medium", "body sensors"),
    "ACTIVITY_RECOGNITION": ("medium", "physical activity"), "GET_ACCOUNTS": ("medium", "accounts on the device"),
    "READ_CALENDAR": ("medium", "calendar"), "QUERY_ALL_PACKAGES": ("medium", "all installed apps"),
    "BLUETOOTH_SCAN": ("medium", "nearby Bluetooth devices"), "BLUETOOTH_CONNECT": ("low", "Bluetooth devices"),
    "POST_NOTIFICATIONS": ("low", "notifications"), "ACCESS_ADSERVICES_AD_ID": ("high", "advertising ID"),
    "ACCESS_ADSERVICES_ATTRIBUTION": ("medium", "ad attribution (Privacy Sandbox)"),
    "ACCESS_ADSERVICES_TOPICS": ("medium", "ad topics (Privacy Sandbox)"),
    "NEARBY_WIFI_DEVICES": ("medium", "nearby Wi-Fi devices"),
    "AD_ID": ("high", "advertising ID"), "READ_PHONE_NUMBERS": ("medium", "phone number"),
    "READ_MEDIA_VISUAL_USER_SELECTED": ("info", "user-selected photos only (Android 14 partial access)"),
}


EXT_HIGH = {"tabs", "history", "cookies", "webRequest", "bookmarks", "downloads", "management", "clipboardRead",
            "geolocation", "nativeMessaging", "declarativeNetRequest", "topSites", "sessions", "readingList",
            "debugger", "webNavigation", "proxy", "privacy", "unlimitedStorage", "background"}


EXT_INFO = {"activeTab", "alarms", "storage", "unlimitedStorage", "contextMenus", "idle", "background", "offscreen"}


ANDROID_IGNORE = {"INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE", "VIBRATE", "WAKE_LOCK", "FOREGROUND_SERVICE"}


def _priv_add(privacy, rule, sev, key, r, line_no, line, meaning):
    k = (rule, key)
    t = privacy.get(k)
    if t:
        t["count"] += 1
        return
    privacy[k] = {"rule": rule, "sev": sev, "key": key, "file": r, "line": line_no, "snippet": line, "count": 1, "meaning": meaning}


ENDPOINT_EXT = CODE_EXT | {".html", ".htm", ".css", ".scss", ".json", ".yml", ".yaml", ".toml", ".xml", ".cfg", ".ini", ".conf", ".env", ".tf"}


ENDPOINT_NAMES = {"Dockerfile", "Makefile", "GNUmakefile", "Justfile", "justfile", "Caddyfile", "Procfile", "Brewfile", "go.mod", "go.sum"}


PRIVATE_HOST_RE = re.compile(r"(?i)(^10\.|^192\.168\.|^127\.|^169\.254\.|^172\.(1[6-9]|2\d|3[01])\.|"
                             r"^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|\.local$|\.lan$|\.internal$|\.localhost$|"
                             r"^\[?fe80:|^\[?fc|^\[?fd)")


RESERVED_TLD_RE = re.compile(r"(?i)\.(invalid|test|example|localhost)$")


def _endpoint_noise(host):
    """Local/LAN/reserved hosts and single-label names are not third parties and have nothing to leak."""
    return bool(PRIVATE_HOST_RE.search(host)) or bool(RESERVED_TLD_RE.search(host)) or "." not in host


KNOWN_HOSTS = {
    "github.com", "gitlab.com", "bitbucket.org", "raw.githubusercontent.com", "gist.github.com",
    "pypi.org", "files.pythonhosted.org", "npmjs.com", "registry.npmjs.org", "crates.io", "static.crates.io",
    "rubygems.org", "packagist.org", "huggingface.co", "cdn-lfs.huggingface.co", "docker.com", "docker.io",
    "ghcr.io", "quay.io", "google.com", "googleapis.com", "gstatic.com", "cloudflare.com", "amazonaws.com",
    "aws.amazon.com", "azure.com", "microsoft.com", "apple.com", "mozilla.org", "w3.org", "schema.org",
    "json-schema.org", "opensource.org", "spdx.org", "unicode.org", "rfc-editor.org", "python.org", "nodejs.org",
    "rust-lang.org", "go.dev", "golang.org", "shields.io", "img.shields.io", "badgen.net", "doi.org", "arxiv.org",
    "wikipedia.org", "x.com", "twitter.com", "linkedin.com", "youtube.com", "discord.gg", "discord.com", "slack.com",
    "stripe.com", "paypal.com", "sentry.io", "ingest.sentry.io", "githubusercontent.com",
    "images.unsplash.com", "picsum.photos", "gravatar.com", "avatars.githubusercontent.com",
}


KNOWN_SUFFIXES = (".githubusercontent.com", ".googleapis.com", ".gstatic.com", ".amazonaws.com", ".cloudfront.net",
                  ".azureedge.net", ".cloudflare.com", ".huggingface.co", ".pythonhosted.org", ".npmjs.org",
                  ".stripe.com", ".paypal.com", ".sentry.io")


def _known_host(host):
    return host in KNOWN_HOSTS or host.endswith(KNOWN_SUFFIXES)


EMBED_RE = re.compile(r"(?is)<(iframe|embed|object)\b([^>]*)>")


SRC_ATTR_RE = re.compile(r"(?i)\bsrc\s*=\s*[\"']([^\"']+)")


DATA_ATTR_RE = re.compile(r"(?i)\bdata\s*=\s*[\"']([^\"']+)")


ACTION_ATTR_RE = re.compile(r"(?i)\baction\s*=\s*[\"']([^\"']+)")


ALLOW_ATTR_RE = re.compile(r"(?i)\ballow\s*=\s*[\"']([^\"']*)")


IFRAME_RISKY = {"camera", "microphone", "geolocation", "clipboard-read", "clipboard-write",
                "display-capture", "midi", "serial", "usb", "web-share"}


def _iframe_allow_perms(attrs):
    """Feature (origin) pairs delegated by an iframe allow attribute."""
    m = ALLOW_ATTR_RE.search(attrs or "")
    if not m:
        return []
    out = []
    for part in m.group(1).split(";"):
        bits = part.strip().split()
        if bits and bits[0].lower() in IFRAME_RISKY:
            out.append(bits[0].lower() + (f" ({bits[1]})" if len(bits) > 1 else ""))
    return out


SANDBOX_RE = re.compile(r"(?i)\bsandbox\b")


CREDENTIALLESS_RE = re.compile(r"(?i)\bcredentialless\b")


REFERRER_UNSAFE_RE = re.compile(r"(?i)unsafe-url")


JS_IMPORT_URL_RE = re.compile(r"(?i)\b(?:import|from)\s*\(?\s*[\"']((?:https?:)?//[^\"']+)")


SCRIPT_RE = re.compile(r"(?i)<script[^>]+src\s*=\s*[\"']((?:https?:)?//[^\"']+)")


MEDIA_RE = re.compile(r"(?i)<(?:img|source|video|audio|picture)\b[^>]*\bsrc\s*=\s*[\"']((?:https?:)?//[^\"']+)")


POSTER_RE = re.compile(r"(?i)<video\b[^>]*\bposter\s*=\s*[\"']((?:https?:)?//[^\"']+)")


CSS_IMPORT_RE = re.compile(r"(?i)@import\s+(?:url\()?\s*[\"']?((?:https?:)?//[^\"')\s]+)")


SRCSET_RE = re.compile(r"(?i)<(?:img|source)\b[^>]*\bsrcset\s*=\s*[\"']([^\"']+)")


LINK_TAG_RE = re.compile(r"(?is)<link\b([^>]*)>")


REL_ATTR_RE = re.compile(r"(?i)\brel\s*=\s*[\"']([^\"']+)")


HREF_ATTR_RE = re.compile(r"(?i)\bhref\s*=\s*[\"']([^\"']+)")


COOKIE_MAXAGE_RE = re.compile(r"(?i)max-age\s*=\s*(\d+)")


COOKIE_EXPIRES_RE = re.compile(r"(?i)expires\s*=\s*([^;\"']+)")


def _expiry_days(value):
    """Days until a cookie Expires date (RFC 1123, ISO 8601 or unix epoch); None when unparsable."""
    import datetime as dt
    from email.utils import parsedate_to_datetime
    raw = value.strip().strip('"\'')
    when = None
    try:
        when = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        try:
            when = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            if raw.isdigit():
                try:
                    when = dt.datetime.fromtimestamp(int(raw), dt.timezone.utc)
                except (ValueError, OSError, OverflowError):
                    when = None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.timezone.utc)
    return (when - dt.datetime.now(dt.timezone.utc)).days


FORM_RE = re.compile(r"(?i)<form[^>]+action\s*=\s*[\"']((?:https?:)?//[^\"']+)")


def _host_of(url):
    m = re.match(r"(?i)(?:https?:)?//([a-z0-9][a-z0-9.-]*[a-z0-9])", url.strip())
    return m.group(1).lower() if m else None


REFERRER_POLICY_RE = re.compile(r"(?i)(referrer-?policy|referrerpolicy\s*[:=]|rel\s*=\s*[\"'][^\"']*noreferrer|"
                             r"<meta[^>]+name\s*=\s*[\"']referrer)")


PERMISSIONS_POLICY_RE = re.compile(r"(?i)(permissions-?policy)")


DOMAIN_URL_RE = re.compile(r"(?i)https?://([a-z0-9][a-z0-9.-]*[a-z0-9])")


def own_domains(root):
    """Best-effort first-party domains from CNAME/package.json/pyproject/composer/setup.cfg (never executes anything)."""
    root = Path(root)
    found = set()
    def add(*values):
        for v in values:
            if not v:
                continue
            m = DOMAIN_URL_RE.search(str(v))
            host = m.group(1) if m else (str(v).strip() if "." in str(v) and " " not in str(v) else None)
            if host:
                found.add(host.lower().removeprefix("www."))
    try:
        add((root / "CNAME").read_text(errors="replace").strip())
    except OSError:
        pass
    for name in ("package.json",):
        try:
            d = json.loads((root / name).read_text(errors="replace"))
            repo = d.get("repository")
            add(d.get("homepage"), repo.get("url") if isinstance(repo, dict) else repo)
        except (OSError, ValueError):
            pass
    try:
        text = (root / "pyproject.toml").read_text(errors="replace")
        for m in re.finditer(r'(?m)^\s*(?:homepage|repository|documentation|url)\s*=\s*[\"\']([^\"\']+)', text):
            add(m.group(1))
    except OSError:
        pass
    try:
        d = json.loads((root / "composer.json").read_text(errors="replace"))
        add(d.get("homepage"))
    except (OSError, ValueError):
        pass
    try:
        text = (root / "setup.cfg").read_text(errors="replace")
        for m in re.finditer(r"(?mi)^\s*url\s*=\s*(\S+)", text):
            add(m.group(1))
    except OSError:
        pass
    try:
        text = (root / "Cargo.toml").read_text(errors="replace")
        for m in re.finditer(r'(?m)^\s*(?:homepage|repository|documentation)\s*=\s*"([^"]+)"', text):
            add(m.group(1))
    except OSError:
        pass
    try:
        text = (root / "pubspec.yaml").read_text(errors="replace")
        pubspec_home = re.search(r"(?m)^\s*homepage:\s*(\S+)", text)
        if pubspec_home:
            add(pubspec_home.group(1))
    except OSError:
        pass
    return found


PERSONAS: dict[str, dict[str, Any]] = {
    "ci": {
        "label": "CI / supply chain",
        "description": "Repository CI and dependency risk: workflow shell, install hooks, unpinned bases, dependency confusion",
        "deltas": [("gha-*", 1), ("Download-and-execute", 1), ("npm lifecycle script", 1),
                   ("dockerfile-base-unpinned", 1), ("dependency-confusion", 1), ("submodule-*", 1),
                   ("pip-build-hook", 1), ("go-generate-fetch", 1), ("rust-build-rs", 1),
                   ("install-time-fetch", 1), ("node-gyp-action", 1), ("make-just-hooks", 1)],
    },
    "agent-operator": {
        "label": "Agent operator",
        "description": "What an agent will read and obey: hidden instructions, invisible text, tool/MCP permissions",
        "deltas": [("md-*", 2), ("Invisible Unicode TAG characters", 1), ("Zero-width characters", 1),
                   ("Dangerous flag enabled", 1), ("Over-broad tool permission / auto-approve", 1),
                   ("MCP server auto-installs and runs a package at launch", 1),
                   ("MCP/plugin server runs a raw shell or downloader", 1),
                   ("Remote MCP/plugin server endpoint", 1),
                   ("Asks the agent to act silently / without consent", 1),
                   ("Instructions to read and send secrets/credentials to a URL", 1),
                   ("Filesystem access to root/home directory", 1)],
    },
    "maintainer": {
        "label": "Repository maintainer",
        "description": "Repo health: telemetry/privacy noise is turned down, structural findings stay",
        "deltas": [("telemetry-*", -1), ("privacy-*", -1), ("cookie-*", -1), ("third-party-*", -1),
                   ("session-replay-mask", -1), ("consent-*", -1), ("dnt-respect", -1),
                   ("vendor-pii", -1), ("data-retention", -1)],
    },
    "consumer": {
        "label": "End-user / consumer",
        "description": "Running this on my machine: install payloads and secrets matter more, CI/dev rules matter less",
        "deltas": [("Download-and-execute", 1), ("npm lifecycle script", 1), ("pip-build-hook", 1),
                   ("install-time-fetch", 1), ("install-time-network", 1),
                   ("Prebuilt binary/compiled artifact in repo", 1), ("Password-protected/encrypted archive (uninspectable)", 1),
                   ("gha-*", -1), ("md-*", -1), ("dockerfile-base-unpinned", -1), ("submodule-*", -1),
                   ("telemetry-*", 1)],
    },
}


def persona_delta(persona, rule):
    """Sum of the persona's severity deltas matching `rule` (fnmatch globs)."""
    return sum(int(d) for pattern, d in PERSONAS[persona]["deltas"] if fnmatchcase(rule, pattern))


def shift_severity(severity, delta):
    """Move a severity by `delta` steps, clamped to info..critical (ascending scale)."""
    order = ["info", "low", "medium", "high", "critical"]
    idx = order.index(severity) if severity in order else 0
    return order[max(0, min(len(order) - 1, idx + delta))]


def apply_persona(findings, persona):
    """Re-grade findings with the persona's rule deltas (before config overrides and the verdict)."""
    moved = 0
    for f in findings:
        delta = persona_delta(persona, _explain_rule(f))
        if delta:
            new_sev = shift_severity(str(f.get("severity") or "info"), delta)
            if new_sev != f.get("severity"):
                moved += 1
            f["severity"] = new_sev
    return moved


def print_personas():
    """`--list-personas`: the severity lenses, what they care about and each glob delta."""
    for name, p in PERSONAS.items():
        print(f"{name:<15} {p['label']}")
        print(f"{'':<15} {p['description']}")
        print(f"{'':<15} deltas: " + ", ".join(f"{pat} {'+' if d > 0 else ''}{d}" for pat, d in p["deltas"]))
    print("\n`--as <persona>` only re-grades findings; the profile still sets the verdict thresholds. "
          "Explicit .repobeagle.yml rule overrides win.")


RULE_PACK_VERSION = 1


RULE_PACK_MAX_MATCHES = 20


PACK_UNANCHORED = re.compile(r"^(?:\(\?[a-zA-Z]+\))*")


PACK_NESTED_QUANT = re.compile(r"\((?:\\\\.|[^()])*?[+*{][^()]*?\)[+*{]")


def parse_rule_pack(path):
    """(pack, errors) for a `.repobeagle/rules` pack; YAML subset or JSON. Never raises on content errors."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as ex:
        return None, [f"{path}: cannot read: {ex}"]
    try:
        doc = json.loads(text)
    except ValueError:
        try:
            doc = parse_yaml_subset(text)
        except ValueError as ex:
            return None, [f"{path}: {ex}"]
    errors: list[str] = []
    where = str(path)
    if not isinstance(doc, dict):
        return None, [f"{where}: top level must be a mapping with `version` and `rules`"]
    version = doc.get("version")
    try:
        version_num = int(version) if version is not None else None
    except (TypeError, ValueError):
        version_num = None
    if version_num != RULE_PACK_VERSION:
        errors.append(f"{where}: version must be {RULE_PACK_VERSION} (got {version!r})")
    rules = doc.get("rules")
    if not isinstance(rules, list) or not rules:
        errors.append(f"{where}: `rules` must be a non-empty list")
        rules = []
    seen: set[str] = set()
    compiled_rules = []
    for idx, rule in enumerate(rules, 1):
        if not isinstance(rule, dict):
            errors.append(f"{where}: rules[{idx}] must be a mapping")
            continue
        rid = rule.get("id")
        if not isinstance(rid, str) or not re.fullmatch(r"[a-z][a-z0-9-]{2,}", rid or ""):
            errors.append(f"{where}: rules[{idx}].id must match [a-z][a-z0-9-]{{2,}}")
            continue
        rw = f"{where}: rule {rid!r}"
        if rid in seen:
            errors.append(f"{rw}: duplicate id")
        seen.add(rid)
        paths = rule.get("paths")
        if isinstance(paths, str):
            paths = [paths]
        if not isinstance(paths, list) or not paths or not all(isinstance(x, str) and x.strip() for x in paths):
            errors.append(f"{rw}.paths must be a non-empty list of globs")
            paths = []
        pattern = rule.get("regex")
        compiled = None
        if not isinstance(pattern, str) or not pattern:
            errors.append(f"{rw}.regex must be a non-empty regex")
        else:
            stripped = PACK_UNANCHORED.sub("", pattern)
            if stripped and not stripped.startswith(("^", "\\b")):
                errors.append(f"{rw}.regex is unanchored: start it with ^ (per line) or \b")
            if PACK_NESTED_QUANT.search(pattern):
                errors.append(f"{rw}.regex has nested quantifiers (catastrophic backtracking risk), e.g. (a+)+")
            try:
                compiled = re.compile(pattern)
            except re.error as ex:
                errors.append(f"{rw}.regex does not compile: {ex}")
        severity = rule.get("severity")
        if severity not in SEV_ORDER:
            errors.append(f"{rw}.severity must be one of {', '.join(SEV_ORDER)}")
        meaning = rule.get("meaning")
        if not isinstance(meaning, str) or not meaning.strip():
            errors.append(f"{rw}.meaning must be a one-sentence reason")
        remediation = rule.get("remediation")
        if not isinstance(remediation, str) or not remediation.strip():
            errors.append(f"{rw}.remediation must name the fix")
        fixtures = rule.get("fixtures")
        if not isinstance(fixtures, dict):
            errors.append(f"{rw}.fixtures must map `positive` and `negative` to fixture strings")
            fixtures = {}
        for kind in ("positive", "negative"):
            values = fixtures.get(kind)
            if not isinstance(values, list) or not values or not all(isinstance(v, str) and v for v in values):
                errors.append(f"{rw}.fixtures.{kind} must be a non-empty list of fixture strings")
        compiled_rules.append({"id": rid, "paths": paths or [], "pattern": pattern or "", "_compiled": compiled,
                               "severity": severity, "meaning": (meaning or "").strip() if isinstance(meaning, str) else "",
                               "remediation": (remediation or "").strip() if isinstance(remediation, str) else "",
                               "fixtures": {k: fixtures.get(k) or [] for k in ("positive", "negative")}})
    return {"path": str(path), "version": doc.get("version"), "rules": compiled_rules}, errors


def _pack_fixture_path(glob, index):
    """A concrete path matching `glob` (used to place synthetic fixtures for `rules test`)."""
    path = glob.replace("**/", "").replace("**", "")
    if "*" in path:
        path = path.replace("*", "fixture", 1)
    if not Path(path).suffix:
        path = path.rstrip("/") + f"/fixture{index}.txt"
    return path.lstrip("/") or f"fixture{index}.txt"


def run_rule_packs(root, packs):
    """Findings from compiled rule packs: same finding() shape, capped per rule with a summary."""
    findings: list[dict] = []
    root = Path(root)
    for pack in packs:
        for rule in pack["rules"]:
            matched = 0
            for glob in rule["paths"]:
                for p in sorted(root.glob(glob)):
                    if not p.is_file():
                        continue
                    text = read_text(p)
                    if not text:
                        continue
                    for lineno, line in enumerate(text.splitlines(), 1):
                        if not rule["_compiled"].search(line):
                            continue
                        matched += 1
                        if matched <= RULE_PACK_MAX_MATCHES:
                            f = finding("rules", rule["severity"], rel(root, p), lineno,
                                        f"{rule['id']}: {rule['meaning']}", line.strip()[:200], rule["meaning"])
                            if rule["remediation"]:
                                f["remediation"] = rule["remediation"]
                            findings.append(f)
            if matched > RULE_PACK_MAX_MATCHES:
                findings.append(finding("rules", rule["severity"], "(repo)", 0,
                                         f"{rule['id']}: matched {matched - RULE_PACK_MAX_MATCHES} more line(s)",
                                         f"{matched} matches total",
                                         "Only the first matches per rule are shown; narrow the paths or regex."))
    return findings


def load_rule_packs(root):
    """Compiled packs from `<root>/.repobeagle/rules/*.yml|*.yaml`; ConfigError on any invalid pack."""
    base = Path(root) / ".repobeagle" / "rules"
    if not base.is_dir():
        return []
    packs = []
    for p in sorted(list(base.glob("*.yml")) + list(base.glob("*.yaml"))):
        pack, errors = parse_rule_pack(p)
        if errors:
            raise ConfigError("; ".join(errors))
        if pack:
            packs.append(pack)
    return packs


def rules_lint(paths):
    """Lint pack files; (files, rules, errors)."""
    files, rule_count, errors = [], 0, []
    for raw in paths:
        base = Path(raw)
        candidates = sorted(list(base.rglob("*.yml")) + list(base.rglob("*.yaml"))) if base.is_dir() else [base]
        for p in candidates:
            files.append(p)
            pack, errs = parse_rule_pack(p)
            if errs:
                errors += errs
            elif pack:
                rule_count += len(pack["rules"])
    return files, rule_count, errors


def cmd_rules(a):
    """`rules lint|test`: validate rule packs and run their positive/negative fixtures."""
    files, rule_count, errors = rules_lint(a.path)
    if not files:
        print(f"rules {a.rules_cmd}: no pack files found in {', '.join(a.path)}", file=sys.stderr)
        return 1
    if errors:
        for e in errors:
            print(f"rules lint: {e}", file=sys.stderr)
        print(f"rules lint: {len(errors)} error(s) in {len(files)} file(s)", file=sys.stderr)
        return 1
    print(f"PASS rules lint: {len(files)} pack file(s), {rule_count} rule(s)")
    if a.rules_cmd == "lint":
        return 0
    failures = 0
    for p in files:
        pack, _ = parse_rule_pack(p)
        for rule in (pack or {}).get("rules") or []:
            for kind in ("positive", "negative"):
                for i, text in enumerate(rule["fixtures"][kind]):
                    with tempfile.TemporaryDirectory() as td:
                        target = Path(td) / _pack_fixture_path(rule["paths"][0], i)
                        try:
                            target.parent.mkdir(parents=True, exist_ok=True)
                            target.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
                        except OSError as ex:
                            print(f"FAIL {rule['id']} {kind}[{i}]: cannot write fixture: {ex}", file=sys.stderr)
                            failures += 1
                            continue
                        got = {_explain_rule(f) for f in run_rule_packs(td, [pack])}
                        fired = rule["id"] in got
                        ok = fired if kind == "positive" else not fired
                        if not ok:
                            failures += 1
                            why = "did not fire" if kind == "positive" else "fired"
                            print(f"FAIL {rule['id']} {kind}[{i}]: {why} on {text!r}", file=sys.stderr)
                        else:
                            print(f"PASS {rule['id']} {kind}[{i}]")
    if failures:
        print(f"rules test: {failures} fixture failure(s)", file=sys.stderr)
        return 1
    print("PASS rules test: every positive fixture fired its rule id and no negative did")
    return 0


CONFIG_FILE = ".repobeagle.yml"


class ConfigError(Exception):
    """Invalid repository policy config: fail loudly, never silently ignore a typo."""


_RULE_IDS: set[str] | None = None


BUILTIN_DYNAMIC_RULES = (
    "high-entropy-blob", "magic-mismatch", "minified-outside-dist", "typosquat-dep",
    "md-comment-instruction", "md-details-instruction", "md-alt-title-instruction",
    "md-css-hidden", "md-padded-line",
    "submodule-host", "submodule-uninspected", "submodule-unpinned",
    "npm lifecycle script 'postinstall' runs automatically on install",
)


BUILTIN_PHRASE_RULES = (
    "Asks the agent to act silently / without consent",
    "Code reads secrets/credentials near a network call",
    "Coverage-low",
    "Dangerous flag enabled",
    "Download-and-execute",
    "Filesystem access to root/home directory",
    "GuardDog npm package",
    "GuardDog pypi package",
    "Instructions to read and send secrets/credentials to a URL",
    "Invisible Unicode TAG characters",
    "MALICIOUS package",
    "MCP server auto-installs and runs a package at launch",
    "MCP/plugin server runs a raw shell or downloader",
    "Over-broad tool permission / auto-approve",
    "Remote MCP/plugin server endpoint",
    "Slow-file",
    "Vulnerable dependency",
    "custom-check",
    "npm lifecycle script",
    "Zero-width characters",
)


def known_rule_ids():
    """Built-in rule ids: hyphenated literals, rule tables, telemetry families, OSV/GuardDog and
    sentence-style agent findings. Imported lazily: the rule modules depend on this module."""
    global _RULE_IDS
    if _RULE_IDS is None:
        from .rules.agent import MD_RULES
        from .rules.privacy import PRIVACY_RULE_ORDER, TELEMETRY_PACKAGES, TELEMETRY_RULES
        from .rules.registry import RULES
        source = "\n".join(p.read_text(encoding="utf-8")
                            for p in sorted(Path(__file__).resolve().parent.rglob("*.py")))
        ids = set(re.findall(r'"([a-z][a-z0-9-]{2,})"', source))
        ids |= {f"telemetry-{kind}" for kind, *_ in TELEMETRY_RULES}
        ids |= {f"telemetry-{kind}" for kind, *_ in TELEMETRY_PACKAGES}
        ids |= set(PRIVACY_RULE_ORDER)
        ids |= set(RULES)
        ids |= set(BUILTIN_PHRASE_RULES)
        ids |= set(BUILTIN_DYNAMIC_RULES)
        for rule in MD_RULES:
            if isinstance(rule, (tuple, list)) and rule and isinstance(rule[0], str):
                ids.add(rule[0])
        _RULE_IDS = ids
    return _RULE_IDS


def _strip_yaml_comment(line):
    quote = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i]
    return line


def _yaml_scalar(value):
    v = value.strip()
    if not v:
        return ""
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        if v[0] == '"':
            try:
                return json.loads(v)
            except ValueError:
                return v[1:-1]
        return v[1:-1].replace("''", "'")
    if v in ("true", "false"):
        return v == "true"
    if v in ("null", "~"):
        return None
    return v


def _yaml_inline(value):
    """Scalar, or an inline `[a, b]` list of scalars (quotes respected). JSON is accepted as a YAML subset."""
    v = value.strip()
    if not (v.startswith("[") and v.endswith("]")):
        return _yaml_scalar(v)
    inner = v[1:-1].strip()
    if not inner:
        return []
    out, cur, quote = [], [], None
    for ch in inner:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            cur.append(ch)
        elif ch == ",":
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if quote:
        raise ValueError("unterminated quoted string in an inline list")
    tail = "".join(cur).strip()
    if tail:
        out.append(tail)
    return [_yaml_scalar(x) for x in out if x != ""]


def parse_yaml_subset(text):
    """Block mappings/lists, scalars and inline lists (the subset a policy file needs); comments and blank lines."""
    lines = []
    for n, raw in enumerate(text.splitlines(), 1):
        if raw[:len(raw) - len(raw.lstrip(" \t"))].find("\t") >= 0:
            raise ValueError(f"line {n}: use spaces, not tabs, for indentation")
        stripped = _strip_yaml_comment(raw).rstrip()
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        lines.append({"indent": indent, "text": stripped.strip(), "line": n})

    def block(i, indent):
        if i >= len(lines) or lines[i]["indent"] < indent:
            return {}, i
        if lines[i]["text"].startswith("- "):
            return seq(i, indent)
        out: dict[str, Any] = {}
        while i < len(lines) and lines[i]["indent"] == indent and not lines[i]["text"].startswith("- "):
            entry = lines[i]
            if ":" not in entry["text"]:
                raise ValueError(f"line {entry['line']}: expected 'key: value'")
            key, _, rest = entry["text"].partition(":")
            key, rest = key.strip(), rest.strip()
            if not key:
                raise ValueError(f"line {entry['line']}: empty key")
            i += 1
            if rest:
                out[key] = _yaml_inline(rest)
            elif i < len(lines) and lines[i]["indent"] > indent:
                out[key], i = block(i, lines[i]["indent"])
            elif i < len(lines) and lines[i]["indent"] == indent and lines[i]["text"].startswith("- "):
                out[key], i = seq(i, indent)
            else:
                out[key] = {}
        return out, i

    def seq(i, indent):
        out: list[Any] = []
        while i < len(lines) and lines[i]["indent"] == indent and lines[i]["text"].startswith("-"):
            entry = lines[i]
            body = entry["text"][1:].strip()
            i += 1
            if not body:
                if i < len(lines) and lines[i]["indent"] > indent:
                    value, i = block(i, lines[i]["indent"])
                    out.append(value)
                else:
                    out.append(None)
                continue
            if ":" in body and body[0] not in "\"[''[{" and not body.startswith(("[", '{"')):
                key, _, rest = body.partition(":")
                item: dict[str, Any] = {key.strip(): _yaml_inline(rest) if rest.strip() else {}}
                if i < len(lines) and lines[i]["indent"] > indent:
                    more, i = block(i, lines[i]["indent"])
                    if not isinstance(more, dict):
                        raise ValueError(f"line {entry['line']}: list item mixes a mapping with a scalar list")
                    item.update(more)
                out.append(item)
            else:
                out.append(_yaml_inline(body))
        return out, i

    if not lines:
        return {}
    doc, end = block(0, lines[0]["indent"])
    if end != len(lines):
        raise ValueError(f"line {lines[end]['line']}: unexpected indentation")
    return doc


def load_repo_config(root):
    """Validated `.repobeagle.yml` (or JSON) or None. Unknown rule ids/severities/profiles are errors, not no-ops."""
    path = Path(root) / CONFIG_FILE
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        doc = json.loads(text)
    except ValueError:
        try:
            doc = parse_yaml_subset(text)
        except ValueError as ex:
            raise ConfigError(f"{CONFIG_FILE}: {ex}")
    if not isinstance(doc, dict):
        raise ConfigError(f"{CONFIG_FILE}: the top level must be a mapping")
    cfg: dict[str, Any] = {"path": CONFIG_FILE, "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                           "rules": {}, "hosts": [], "custom_checks": []}
    profile = doc.get("profile")
    if profile is not None:
        if profile not in PROFILES:
            raise ConfigError(f"{CONFIG_FILE}: unknown profile {profile!r} (use {', '.join(PROFILES)})")
        cfg["profile"] = profile
    rules = doc.get("rules") or {}
    if not isinstance(rules, dict):
        raise ConfigError(f"{CONFIG_FILE}: `rules` must map rule ids to severities")
    known = known_rule_ids()
    for rule, severity in rules.items():
        if not isinstance(rule, str) or not rule:
            raise ConfigError(f"{CONFIG_FILE}: rule ids must be non-empty strings")
        if severity not in SEV_ORDER:
            raise ConfigError(f"{CONFIG_FILE}: rule {rule!r} has unknown severity {severity!r} "
                              f"(use {', '.join(SEV_ORDER)})")
        if any(ch in rule for ch in "*?["):
            if not any(fnmatchcase(k, rule) for k in known):
                raise ConfigError(f"{CONFIG_FILE}: rule glob {rule!r} matches no known rule id")
        elif rule not in known:
            near = difflib.get_close_matches(rule, sorted(known), n=3, cutoff=0.5)
            raise ConfigError(f"{CONFIG_FILE}: unknown rule id {rule!r}" + (f" (did you mean {', '.join(near)}?)" if near else ""))
        cfg["rules"][rule] = severity
    hosts = doc.get("hosts") or []
    if isinstance(hosts, str):
        hosts = [hosts]
    if not isinstance(hosts, list) or not all(isinstance(h, str) and h.strip() for h in hosts):
        raise ConfigError(f"{CONFIG_FILE}: `hosts` must be a list of host names")
    cfg["hosts"] = [h.strip().lower() for h in hosts]
    checks = doc.get("custom_checks") or []
    if isinstance(checks, dict):
        checks = [checks]
    if not isinstance(checks, list):
        raise ConfigError(f"{CONFIG_FILE}: `custom_checks` must be a list")
    for idx, chk in enumerate(checks, 1):
        where = f"{CONFIG_FILE}: custom_checks[{idx}]"
        if not isinstance(chk, dict):
            raise ConfigError(f"{where} must be a mapping")
        paths = chk.get("paths")
        if isinstance(paths, str):
            paths = [paths]
        if not isinstance(paths, list) or not paths or not all(isinstance(x, str) and x.strip() for x in paths):
            raise ConfigError(f"{where}.paths must be a non-empty list of globs")
        pattern = chk.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            raise ConfigError(f"{where}.pattern must be a non-empty regex")
        try:
            compiled = re.compile(pattern)
        except re.error as ex:
            raise ConfigError(f"{where}.pattern does not compile: {ex}")
        severity = chk.get("severity")
        if severity not in SEV_ORDER:
            raise ConfigError(f"{where}.severity must be one of {', '.join(SEV_ORDER)}")
        meaning = chk.get("meaning")
        if not isinstance(meaning, str) or not meaning.strip():
            raise ConfigError(f"{where}.meaning must be a one-sentence reason")
        rid = str(chk.get("id") or f"check-{idx}")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", rid):
            raise ConfigError(f"{where}.id must match [A-Za-z0-9_.-]+")
        cfg["custom_checks"].append({"id": rid, "paths": paths, "pattern": pattern, "_compiled": compiled,
                                     "severity": severity, "meaning": meaning.strip()})
    return cfg


def run_custom_checks(root, checks):
    """Findings from `custom_checks` (paths + regex + severity + meaning), capped per check, path-sorted."""
    findings: list[dict] = []
    root = Path(root)
    for chk in checks:
        matched = 0
        for glob in chk["paths"]:
            for p in sorted(root.glob(glob)):
                if not p.is_file():
                    continue
                text = read_text(p)
                if not text:
                    continue
                for lineno, line in enumerate(text.splitlines(), 1):
                    if not chk["_compiled"].search(line):
                        continue
                    matched += 1
                    if matched <= 20:
                        findings.append(finding("custom", chk["severity"], rel(root, p), lineno,
                                                 f"custom-check: {chk['id']} — {chk['meaning']}",
                                                 line.strip()[:200], chk["meaning"]))
        if matched > 20:
            findings.append(finding("custom", chk["severity"], "(repo)", 0,
                                     f"custom-check: {chk['id']} matched {matched - 20} more line(s)",
                                     f"{matched} matches total",
                                     "Only the first 20 matches are shown per custom check; narrow the pattern or paths."))
    return findings


def _is_own(host, own):
    return any(host == d or host.endswith("." + d) for d in own)


def verdict_consistent(report):
    """True when stored verdict/counts match the findings under the declared profile."""
    v = report.get("verdict")
    meta = report.get("meta") or {}
    prof = meta.get("profile")
    if not v or not prof:
        return True
    fs = [f for f in report.get("findings") or [] if isinstance(f, dict) and not f.get("suppressed")]
    try:
        rv, _, rc = verdict(fs, prof, report.get("ai_review"))
    except Exception:
        return True
    return rv == v and (not report.get("counts") or report.get("counts") == rc)


def privacy_summary_consistent(report):
    """True when the stored privacy_summary matches what the findings imply (skipped for older tool versions)."""
    stored = report.get("privacy_summary")
    if not stored:
        return True
    ver = report.get("version")
    if ver and ver != VERSION:
        return True          # grouping rules may have changed since the report was produced
    findings = [f for f in report.get("findings") or [] if isinstance(f, dict) and not f.get("suppressed")]
    return privacy_summary(findings) == stored


def privacy_mode_consistent(report):
    """True when findings match the declared meta.privacy_mode (only/excluded/full)."""
    mode = (report.get("meta") or {}).get("privacy_mode")
    tools = {f.get("tool") for f in report.get("findings") or [] if isinstance(f, dict)}
    if mode == "only":
        return tools <= {"privacy", "telemetry"}
    if mode == "excluded":
        return not (tools & {"privacy", "telemetry"})
    return True


def toolchain_pins():
    """Scanner versions this install pins: pip scanners from constraints.txt, gitleaks from the Dockerfile ARG.

    Missing files are not an error (an installed wrapper may point at a repo checkout or the image);
    a scanner without a discoverable pin is simply absent from the result.
    """
    base = HERE
    pins = {}
    try:
        for ln in (base / "constraints.txt").read_text(encoding="utf-8").splitlines():
            m = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([0-9][A-Za-z0-9_.+-]*)", ln.strip())
            if m:
                pins[m.group(1).lower()] = m.group(2)
    except OSError:
        pass
    try:
        m = re.search(r"(?m)^ARG GITLEAKS_VERSION=([0-9][A-Za-z0-9_.+-]*)",
                      (base / "Dockerfile").read_text(encoding="utf-8"))
        if m:
            pins["gitleaks"] = m.group(1)
    except OSError:
        pass
    return pins


def toolchain_drift(tools, pins):
    """'name got (pins want)' for scanners whose recorded version differs from this install's pins."""
    if not isinstance(tools, dict) or not isinstance(pins, dict):
        return []
    drift = []
    for name in sorted(pins):
        t = tools.get(name)
        got = t.get("version") if isinstance(t, dict) else None
        if got and str(got) != pins[name]:
            drift.append(f"{name} {got} (pins {pins[name]})")
    return drift


def privacy_profile(summary):
    """One-line counts for the report header; details stay in privacy_summary."""
    if not summary:
        return ""
    tr = summary.get("trackers") or {}
    trackers = sum(len(v) for v in tr.values())
    hosts = [h for h in (summary.get("network") or []) if "." in h]
    pii = len(summary.get("pii") or [])
    perms = len(summary.get("permissions") or [])
    consent = len(summary.get("consent") or [])
    bits = [f"{trackers} tracker vendor(s)", f"{len(hosts)} third-party host(s)", f"{pii} PII item(s)"]
    if summary.get("vendor"):
        bits.append(f"{len(summary['vendor'])} vendor config(s)")
    if perms:
        bits.append(f"{perms} permission scope(s)")
    if consent:
        bits.append(f"{consent} consent signal(s)")
    if summary.get("identity"):
        bits.append(f"{len(summary['identity'])} identity-sharing call(s)")
    return "Privacy profile: " + ", ".join(bits)


def privacy_summary(findings):
    """Structured 'what kind' overview of privacy findings, for the report and JSON."""
    groups: dict[str, Any] = {"trackers": {}, "pii": [], "permissions": [], "fingerprinting": [], "storage": [],
              "consent": [], "vendor": [], "first_party": [], "network": [], "retention": [], "uploads": [],
              "transparency": [], "identity": [], "masking": []}

    def add(group, value):
        if value and value not in groups[group]:
            groups[group].append(value)

    permissions = {"android-permission", "android-feature", "extension-permission", "extension-resource",
                   "extension-connectable", "macos-entitlement", "ios-tracking", "ios-tracking-domain",
                   "ios-api-category", "ios-data-type", "ios-purpose-string", "ios-tracking-declaration",
                   "browser-capability", "android-queries"}
    storage = {"cookie-write", "cookie-flags", "cookie-lifetime", "browser-storage", "tracking-cookie", "client-id",
               "import-time-storage"}
    consent = {"consent-manager", "consent-gating", "consent-order", "consent-mode", "consent-state", "dnt-respect"}
    network = {"insecure-endpoint", "external-endpoint", "referrer-policy", "permissions-policy", "iframe-allow",
               "android-cleartext", "ios-cleartext", "import-time-network", "tracking-params", "form-method"}
    transparency = {"privacy-doc", "store-disclosure", "undisclosed-vendor"}
    for f in findings:
        if f.get("tool") not in ("telemetry", "privacy"):
            continue
        rule = _rule_of(f)
        key = (f["title"].partition(": ")[2] or rule).replace(" (transitive)", "")
        if rule == "telemetry-identify":
            add("identity", key)
        elif rule.startswith("telemetry-"):
            kind = rule[len("telemetry-"):]
            vals = groups["trackers"].setdefault(kind, [])
            if key not in vals:
                vals.append(key)
        elif rule.startswith("pii-") or rule == "ip-logging":
            add("pii", key)
        elif rule == "session-replay-mask":
            add("masking", key)
        elif rule in permissions:
            add("permissions", key)
        elif rule == "fingerprint":
            add("fingerprinting", key)
        elif rule in storage:
            add("storage", key)
        elif rule in consent:
            add("consent", key)
        elif rule in ("vendor-pii",):
            add("vendor", key)
        elif rule == "first-party-endpoint":
            add("first_party", key)
        elif rule in network or rule.startswith("third-party-"):
            add("network", key)
        elif rule == "data-retention":
            add("retention", key)
        elif rule.startswith("upload-"):
            add("uploads", key)
        elif rule in transparency:
            add("transparency", key)
    return {k: v for k, v in groups.items() if v}


def verdict(findings, profile, ai):
    prof = PROFILES[profile]
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
    at_least = lambda s: sum(c for k, c in counts.items() if SEV_ORDER[k] >= SEV_ORDER[s])
    v = "GREEN"
    if at_least(prof["yellow"]): v = "YELLOW"
    for s, n in prof["red"]:
        if at_least(s) >= n: v = "RED"
    if ai and ai.get("intent") == "malicious" and float(ai.get("confidence", 0) or 0) >= 0.6:
        v = "RED"
    elif ai and ai.get("intent") == "suspicious" and v == "GREEN":
        v = "YELLOW"
    top = sorted(findings, key=lambda f: -SEV_ORDER[f["severity"]])
    if v == "RED":
        why = ("the AI review set the verdict (no scanner findings)" if not top else
               f"{counts['critical']} critical / {counts['high']} high findings, e.g. "
               f"{top[0]['title']} ({top[0]['file']}:{top[0]['line']})")
    elif v == "YELLOW":
        why = f"No critical issues; {counts['high']} high, {counts['medium']} medium, {counts['low']} low findings worth a look"
    else:
        why = "No significant findings from any scanner"
    return v, why, counts


def _explain_rule(f):
    """Stable rule id of a stored finding ('rule' is recorded by current reports; older titles are parsed)."""
    return str(f.get("rule") or str(f.get("title") or "?").split(":")[0].split(" (")[0])


def _explain_counts(findings):
    c = {s: sum(1 for f in findings if f.get("severity") == s) for s in SEV_ORDER}
    return ", ".join(f"{k} {c[k]}" for k in SEV_ORDER if c[k]) or "none"


def planner_apply(findings, patterns):
    """Splits findings by accepted rule ids or globs (same fnmatch semantics as .repobeagleignore)."""
    keep, drop = [], []
    for f in findings:
        rule = _explain_rule(f)
        if any(fnmatchcase(rule, p) or fnmatchcase(str(f.get("title") or ""), p) for p in patterns):
            drop.append(f)
        else:
            keep.append(f)
    return keep, drop


def planner_rules(findings):
    """Whole-rule groups, least severe first (lowest worst severity, then largest, then id)."""
    groups: dict[str, list[dict]] = {}
    for f in findings:
        groups.setdefault(_explain_rule(f), []).append(f)
    return sorted(groups.items(), key=lambda kv: (max(SEV_ORDER.get(f.get("severity"), 0) for f in kv[1]),
                                                 -len(kv[1]), kv[0]))


def _planner_pressure(findings, profile, ai=None):
    """Distance to the target tier: (verdict rank, findings above the binding threshold)."""
    v, _, counts = verdict(findings, profile, ai)
    rank = {"GREEN": 0, "YELLOW": 1, "RED": 2}[v]
    prof = PROFILES[profile]
    at_least = lambda s: sum(n for k, n in counts.items() if SEV_ORDER[k] >= SEV_ORDER[s])
    if v == "RED":
        for s, n in prof["red"]:
            if at_least(s) >= n:
                return rank, at_least(s) - n + 1
    elif v == "YELLOW":
        return rank, at_least(prof["yellow"])
    return rank, 0


def planner_plan(findings, profile, ai, target):
    """Accepts whole rules, each step the one that moves the verdict closest to the target; lighter rules win ties."""
    rank = {"GREEN": 0, "YELLOW": 1, "RED": 2}
    target = str(target).upper()
    remaining, plan = list(findings), []
    groups = planner_rules(findings)
    while rank[verdict(remaining, profile, ai)[0]] > rank[target]:
        best = None
        for rule, fs in groups:
            cand = [f for f in remaining if _explain_rule(f) != rule]
            if len(cand) == len(remaining):
                continue                       # already accepted
            score = _planner_pressure(cand, profile, ai) + (
                max(SEV_ORDER.get(f.get("severity"), 0) for f in fs), rule)
            if best is None or score < best[0]:
                best = (score, rule, fs)
        if best is None:
            break
        plan.append((best[1], best[2]))
        remaining = [f for f in remaining if _explain_rule(f) != best[1]]
    return plan, remaining, verdict(remaining, profile, ai)[0]


def write_suppressions(path, rules, reason=""):
    """Appends one rule id per line with a reason comment to the ignore file. Returns (added, already present)."""
    p = Path(path)
    try:
        existing = p.read_text(encoding="utf-8") if p.exists() else ""
    except OSError:
        existing = ""
    have = {ln.split("#", 1)[0].strip() for ln in existing.splitlines()}
    add = [r for r in rules if r and r not in have]
    if not add:
        return 0, len(rules)
    reason = " ".join(str(reason or "").split()) or "reviewed with repobeagle explain"
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        if existing and not existing.endswith("\n"):
            fh.write("\n")
        fh.write(f"# accepted by `repobeagle explain --write`: {reason}\n" + "\n".join(add) + "\n")
    return len(add), len(rules) - len(add)


def explain_report(d, accept=(), target=None, write=False, ignore_file=None, reason=""):
    """Explains a stored report's verdict from its counts and profile, including the margin. Pure: never re-scans."""
    meta = d.get("meta") if isinstance(d.get("meta"), dict) else {}
    prof_name = meta.get("profile")
    if prof_name not in PROFILES:
        print(f"explain: no known profile in the report (found {prof_name!r})", file=sys.stderr)
        return 1
    findings = [f for f in d.get("findings") or [] if isinstance(f, dict) and not f.get("suppressed")]
    counts = d.get("counts")
    if not isinstance(counts, dict) or not counts:
        counts = {s: sum(1 for f in findings if f.get("severity") == s) for s in SEV_ORDER}
    prof = PROFILES[prof_name]

    def at_least(sev):
        return sum(n for k, n in counts.items() if SEV_ORDER.get(k, 0) >= SEV_ORDER[sev])

    stored = d.get("verdict")
    rv, why, _ = verdict(findings, prof_name, d.get("ai_review"))
    print(f"report {d.get('version', '?')}  |  profile {prof_name}  |  verdict {stored or '?'}")
    print("counts: " + (", ".join(f"{k} {counts[k]}" for k in SEV_ORDER if counts.get(k)) or "none"))
    if stored and stored != rv:
        print(f"warning: stored verdict {stored} does not match the findings under {prof_name} ({rv})", file=sys.stderr)
    print("thresholds:")
    for sev, n in prof["red"]:
        got = at_least(sev)
        print(f"  RED    {sev}+ >= {n}: {got} present {'(met)' if got >= n else '(not met)'}")
    ysev, ygot = prof["yellow"], at_least(prof["yellow"])
    print(f"  YELLOW {ysev}+ >= 1: {ygot} present {'(met)' if ygot else '(not met)'}")
    print(f"decision: {rv}" + (f" ({why})" if why else ""))
    if rv == "RED":
        for sev, n in prof["red"]:
            got = at_least(sev)
            if got >= n:
                print(f"to leave RED: remove {got - n + 1} finding(s) at {sev}+ (at most {n - 1} may remain)")
                break
    elif rv == "YELLOW":
        print(f"to reach GREEN: remove all {ygot} finding(s) at {ysev}+")
    else:
        room = [f"{max(0, n - 1 - at_least(sev))} more {sev}+" for sev, n in prof["red"]]
        print("headroom: " + ", ".join(room) + f", {max(0, 1 - ygot)} more {ysev}+ (then YELLOW/RED)")
    rules: dict[str, int] = {}
    for f in findings:
        rule = _rule_of(f)
        rules[rule] = rules.get(rule, 0) + 1
    top = sorted(rules.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
    if top:
        print("largest contributors: " + ", ".join(f"{r} x{n}" for r, n in top))
    if accept or target:
        rank = {"GREEN": 0, "YELLOW": 1, "RED": 2}
        fs = [f for f in d.get("findings") or [] if isinstance(f, dict) and not f.get("suppressed")
              and f.get("severity") in SEV_ORDER]
        patterns = list(accept or [])
        if patterns:
            keep, dropped = planner_apply(fs, patterns)
            matched = sorted({_explain_rule(f) for f in dropped})
            unmatched = [p for p in patterns if not any(fnmatchcase(_explain_rule(f), p) for f in dropped)]
            print("planner:")
            print(f"  accepted: {len(dropped)} finding(s) from {len(matched)} rule(s)"
                  + (f" ({', '.join(matched)})" if matched else "")
                  + (f"; unmatched: {', '.join(unmatched)}" if unmatched else ""))
            print(f"  after accepting: {verdict(keep, prof_name, d.get('ai_review'))[0]}"
                  f"  (remaining findings: {_explain_counts(keep)})")
        else:
            keep, dropped = list(fs), []
            print("planner:")
        planned, remaining, v_plan = planner_plan(keep, prof_name, d.get("ai_review"), target) if target else ([], keep, None)
        if target:
            if not planned:
                print(f"  target {target}: already satisfied by the accepted rules"
                      if patterns else f"  target {target}: already satisfied")
            else:
                print("  planned (each step the rule that moves the verdict closest to the target): "
                      + ", ".join(f"{r} ({len(g)} finding(s))" for r, g in planned))
                reached = rank[v_plan] <= rank[str(target).upper()]
                print(f"  after the plan: {v_plan}  (remaining findings: {_explain_counts(remaining)})")
                print(f"  target {target}: {'reached' if reached else 'NOT reached'}"
                      + ("" if reached else " (the AI review sets the verdict independently of the findings)"))
        if write:
            rules_to_write = sorted({r for r, _ in planned} | {_explain_rule(f) for f in dropped})
            if not rules_to_write:
                print("  write: nothing to add")
            else:
                ipath = ignore_file or SUPPRESS_FILE
                added, skipped = write_suppressions(ipath, rules_to_write, reason)
                print(f"  write: {added} rule(s) appended to {ipath}" + (f", {skipped} already present" if skipped else ""))
    return 0


REMEDIATION = [
    (r"(?i)^Download-and-execute", "pin a version and verify a checksum; avoid `curl … | sh` in install hooks and scripts"),
    (r"(?i)^npm lifecycle script", "run `npm ci --ignore-scripts`, or review the script; `postinstall` runs automatically on every install"),
    (r"(?i)^Code reads secrets/credentials", "keep the secret out of the path that also reaches the network, or make that call opt-in"),
    (r"(?i)^gha-pwn-request", "use `pull_request` (read-only token) or stop checking out the PR head in `pull_request_target`"),
    (r"(?i)^gha-unpinned-action", "pin `uses:` to a full 40-character commit SHA"),
    (r"(?i)^gha-write-permissions", "add a least-privilege `permissions:` block to the workflow"),
    (r"(?i)^gha-secret-echo", "stop echoing secrets; rely on masking and scope `env:` to the step that needs it"),
    (r"(?i)^gha-privileged-trigger", "prefer `pull_request`, and check who can push to `workflow_run` upstream branches"),
    (r"(?i)^gha-curl-pipe-shell", "download to a file, verify a checksum, then execute it (avoid `curl … | sh` in workflows)"),
    (r"(?i)^typosquat-dep", "verify the package name against the registry before adding it"),
    (r"(?i)^(install|import)-time-(network|storage)", "move the side effect out of module scope or gate it behind a flag"),
    (r"(?i)^install-time-fetch", "vendor the artifact into the repo, or make the build step explicit and reproducible"),
    (r"(?i)^install-hook", "review the hook; run installs with scripts disabled where the tool allows it"),
    (r"(?i)^insecure-endpoint", "use https:// / wss://"),
    (r"(?i)^(android|ios)-cleartext", "use TLS, or scope the cleartext exception to the hosts that need it"),
    (r"(?i)^cookie-flags", "set `Secure; HttpOnly; SameSite=Lax` (or Strict) when writing the cookie"),
    (r"(?i)^cookie-write", "prefer HttpOnly cookies set by the server when the value is not needed in JS"),
    (r"(?i)^cookie-lifetime: cookie lifetime > 1 year", "shorten `Max-Age`/`Expires` to what the identifier actually needs"),
    (r"(?i)^(android-permission|android-feature)", "request the permission at first use, and add `android:maxSdkVersion` if only old versions need it"),
    (r"(?i)^android-queries", "declare only the packages you resolve, or prefer explicit intents over package visibility"),
    (r"(?i)^extension-permission", "narrow the host match pattern, or move the permission to `optional_*`"),
    (r"(?i)^extension-connectable", "replace `<all_urls>` in `externally_connectable` with the origins you actually message"),
    (r"(?i)^extension-resource", "narrow the `web_accessible_resources` match patterns"),
    (r"(?i)^macos-entitlement", "drop the entitlement or add a per-use prompt (camera, microphone, location)"),
    (r"(?i)^telemetry-session-replay", "load the replay SDK only after consent, and enable input/text masking"),
    (r"(?i)^session-replay-mask", "enable input/text masking in the replay SDK, or load it only after consent"),
    (r"(?i)^telemetry-", "gate the SDK behind consent, or disable it with its documented opt-out"),
    (r"(?i)^(third-party-|tracking-cookie|client-id|fingerprint)", "self-host the asset, or document and gate the host behind consent"),
    (r"(?i)^consent-(gating|mode|order|state)", "load the tracker only after consent, and keep the consent decision server-side where possible"),
    (r"(?i)^data-retention", "set an explicit retention period and delete the data when it ends"),
    (r"(?i)^dnt-respect", "read `navigator.doNotTrack`/`Sec-GPC` before starting analytics, not only your own opt-out"),
    (r"(?i)^referrer-policy", "send `Referrer-Policy: strict-origin-when-cross-origin` (or `no-referrer`)"),
    (r"(?i)^permissions-policy", "send a `Permissions-Policy` header that disables features you do not use"),
    (r"(?i)^iframe-allow", "narrow the iframe's `allow=` to the permissions that frame needs"),
    (r"(?i)^browser-storage", "clear client storage on logout, or keep only non-identifying values there"),
    (r"(?i)^browser-capability", "feature-detect and request permission before using the capability"),
    (r"(?i)^form-method", "use POST for forms carrying user data, or keep the query string out of logs/referrers"),
    (r"(?i)^(ios-api-category|ios-data-type|ios-purpose-string|ios-tracking)", "align the privacy manifest and purpose strings with what the code actually does"),
    (r"(?i)^privacy-doc: no privacy policy", "add a PRIVACY.md/policy (or link one) and state what is collected"),
    (r"(?i)^store-disclosure", "fill the store's data-collection disclosure (`data_collection_permissions`)"),
    (r"(?i)^undisclosed-vendor", "name the vendor in the privacy docs, or gate it behind consent"),
    (r"(?i)^upload-limit", "state and enforce the upload size/type limit"),
    (r"(?i)^upload-surface", "check where the uploaded file is stored and who can read it"),
    (r"(?i)^vendor-pii", "disable `sendDefaultPii`, or list the fields the vendor receives"),
    (r"(?i)^pii-(email|phone|address|postcode|ssn|card)", "move the value to config/env, or mark it as an example so the rule can ignore it"),
    (r"(?i)^(pii-log|ip-logging)", "log an id instead of the object; truncate/hash the address before logging"),
    (r"(?i)^(pii-in-url|tracking-params)", "strip the parameter before it reaches logs/referers, or use a POST body instead"),
    (r"(?i)^coverage-low", "inspect the large or unsupported files manually; the verdict does not cover them"),
    (r"(?i)^MALICIOUS package", "remove or replace the package; check the registry advisory"),
    (r"(?i)^Vulnerable dependency", "upgrade to a version past the advisory range"),
    (r"(?i)^Hardcoded secret", "rotate the credential, remove it from the file and ignore that file; git history still has the old value"),
    (r"(?i)^Bandit B113", "pass an explicit `timeout=` to the `requests` call"),
    (r"(?i)^Bandit B310", "allowlist the schemes passed to `urlopen`, or use `requests` with a fixed scheme"),
    (r"(?i)^Bandit ", "read the bandit rule documentation for the flagged call and fix the call site"),
    (r"(?i)^GuardDog ", "read the flagged package behaviour; pin a version you reviewed, or replace the package"),
    (r"(?i)^(Asks the agent to act silently)", "state the action in visible text, or explicitly allow it to act without asking"),
    (r"(?i)^Dangerous flag enabled", "drop `dangerouslySkipPermissions`; approve actions per call, or scope the sandbox"),
    (r"(?i)^Over-broad tool permission", "replace `*` / `Bash(*)` with the specific tools the agent needs"),
    (r"(?i)^Remote MCP/plugin server", "confirm the endpoint host over TLS, or run the server locally"),
    (r"(?i)^MCP server auto-installs", "pin the package (`pkg@1.2.3`) or pre-install it and run the lockfile binary"),
    (r"(?i)^MCP/plugin server runs", "prefer a protocol-speaking server, or pin the download and verify a checksum"),
    (r"(?i)^Filesystem access to root/home", "narrow the allowed paths to the repository, or mount the home directory read-only"),
    (r"(?i)^Instructions to read and send secrets", "point the instruction at a file inside the repo, or say which env vars are safe to read"),
    (r"(?i)^Invisible Unicode TAG characters|^Zero-width characters|^Bidirectional control characters",
     "strip the invisible characters (U+200B–U+200F, U+2060–U+2064, U+00AD, or tag characters) unless they are deliberate"),
    (r"(?i)^go-generate-fetch", "vendor the generated output or make the fetch reproducible (pin a version/checksum)"),
    (r"(?i)^high-entropy-blob", "confirm the blob's origin (generated asset, certificate, embedded binary), or move it out of the source tree"),
    (r"(?i)^magic-mismatch", "rename the file to its real type, or check it out with the tool that produced it; the extension is lying"),
    (r"(?i)^make-just-hooks", "review the Make/just recipe; build targets should build, not download or open sockets"),
    (r"(?i)^minified-outside-dist", "move minified files under dist/build, or keep the readable source next to them"),
    (r"(?i)^(node-gyp-action|pip-build-hook|rust-build-rs)", "review the build script/backend; it runs at install or build time"),
    (r"(?i)^md-", "move the instruction to visible text, or keep it if it is intentionally written for agents"),
]


# Rules where no single action is right, with the reason. The coverage test requires every
# rule id seen in the fixtures to appear in REMEDIATION or here.
NO_REMEDIATION = [
    (r"(?i)^external-endpoint", "inventory: a reachable host, nothing to change"),
    (r"(?i)^first-party-endpoint", "inventory: a first-party API call, nothing to change"),
    (r"(?i)^consent-manager", "positive signal: a consent manager is present"),
    (r"(?i)^privacy-doc", "positive signal: the policy exists; read it for what it admits"),
    (r"(?i)^cookie-lifetime", "informational: a session, short, expired or deletion lifetime is fine"),
]


_REMEDIATION_RE = [(re.compile(p), text) for p, text in REMEDIATION]


_NO_REMEDIATION_RE = [(re.compile(p), text) for p, text in NO_REMEDIATION]


def remediation_for(f):
    """One deterministic, well-understood next action per finding, or None when none is obvious."""
    title = str(f.get("title") or "")
    for rx, text in _REMEDIATION_RE:
        if rx.search(title) or rx.search(_rule_of(f)):
            return text
    if str(f.get("tool") or "") == "semgrep":
        return "fix what the rule message describes (the rule id is the title; its registry page has an example)"
    return None


def no_remediation_reason(f):
    """Why a finding deliberately carries no remediation (the coverage test rejects rules with neither)."""
    title = str(f.get("title") or "")
    for rx, text in _NO_REMEDIATION_RE:
        if rx.search(title) or rx.search(_rule_of(f)):
            return text
    return None


def remediation_audit(findings):
    """Coverage review per rule id: every finding must have an action or a documented no-action.

    `mixed` is legitimate where one rule family has informational and actionable variants (for
    example `privacy-doc` present vs missing); `uncovered` fails the coverage test.
    """
    out: dict[str, set[str]] = {"fixed": set(), "documented_none": set(), "mixed": set(), "uncovered": set()}
    groups: dict[str, list[str | None]] = {}
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        state = "fixed" if remediation_for(f) else "none" if no_remediation_reason(f) else None
        groups.setdefault(_rule_of(f), []).append(state)
    for rule, states in groups.items():
        if None in states:
            out["uncovered"].add(rule)
        elif len(set(states)) > 1:
            out["mixed"].add(rule)
        else:
            out["fixed" if states[0] == "fixed" else "documented_none"].add(rule)
    return {k: sorted(v) for k, v in out.items()}


def _rule_of(f):
    return str(f.get("rule") or f.get("title", "").split(":")[0].split(" (")[0] or "?")


def diff_reports(old, new):
    """Compares two reports at (rule, file) granularity so line drift is not a change. Returns added, removed, counts."""
    def active(d):
        return [f for f in (d.get("findings") or [])
                if isinstance(f, dict) and not f.get("suppressed") and f.get("severity") in SEV_ORDER]
    def index(d):
        out: dict[tuple[str, str], list[dict]] = {}
        for f in active(d):
            out.setdefault((_rule_of(f), f.get("file") or "?"), []).append(f)
        return out
    o, n = index(old), index(new)
    order = lambda f: (-SEV_ORDER[f["severity"]], f.get("file") or "", f.get("line") or 0)
    added = sorted((fs[0] for k, fs in n.items() if k not in o), key=order)
    removed = sorted((fs[0] for k, fs in o.items() if k not in n), key=order)
    return added, removed, sum(len(v) for v in o.values()), sum(len(v) for v in n.values())


def gate_findings(old, new, min_severity):
    """Added findings at/above the gate severity (rule + file matching), plus the diff counters."""
    added, removed, old_n, new_n = diff_reports(old, new)
    thr = SEV_ORDER.get(min_severity, SEV_ORDER["medium"])
    return [f for f in added if SEV_ORDER.get(f["severity"], 0) >= thr], added, removed, old_n, new_n


# Normalized determinism comparison: see "Determinism" in README.md for the guarantee and
# its exact scope. Only these finding fields are compared; timings, host paths, the scan
# order and the OSV/trust network stages are deliberately not part of the normalized core.
NORMALIZED_FINDING_FIELDS = ("tool", "severity", "rule", "file", "line", "title", "meaning",
                             "snippet", "suppressed", "remediation")


NETWORK_TOOLS = ("osv-scanner", "trust")


def normalize_findings(findings, offline_only=False):
    """Order-independent, stable view of findings: documented fields only, sorted by a total key."""
    out = []
    for f in findings or []:
        if not isinstance(f, dict) or f.get("severity") not in SEV_ORDER:
            continue
        if offline_only and f.get("tool") in NETWORK_TOOLS:
            continue
        out.append({k: f[k] for k in NORMALIZED_FINDING_FIELDS if k in f})
    key = lambda f: (str(f.get("tool") or ""), str(f.get("severity") or ""), str(f.get("rule") or ""),
                     str(f.get("file") or ""), int(f.get("line") or 0), str(f.get("title") or ""),
                     str(f.get("snippet") or ""), bool(f.get("suppressed")), str(f.get("meaning") or ""))
    return sorted(out, key=key)


def report_fingerprint(d, offline_only=False):
    """SHA-256 of the normalized core; equal for equal reports on any host or architecture.

    Excludes timings, the scan target path, and (with offline_only) the host-side OSV/trust stages.
    """
    meta = d.get("meta") if isinstance(d.get("meta"), dict) else {}
    tools = d.get("tools") if isinstance(d.get("tools"), dict) else meta.get("tools") or {}
    versions = {str(k): (v or {}).get("version") for k, v in tools.items()
                if isinstance(v, dict) and not (offline_only and k in NETWORK_TOOLS)}
    core = {
        "findings": normalize_findings(d.get("findings"), offline_only=offline_only),
        "ruleset": meta.get("ruleset"),
        "profile": meta.get("profile"),
        "privacy_mode": meta.get("privacy_mode"),
        "tool_versions": versions,
        "capabilities": d.get("capabilities") or meta.get("capabilities"),
        "coverage": d.get("coverage") or meta.get("coverage"),
    }
    return hashlib.sha256(json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def rescan_difference(signed, fresh, offline_only=True):
    """(match, added, removed) between a signed report and a fresh scan of the same commit."""
    if report_fingerprint(signed, offline_only=offline_only) == report_fingerprint(fresh, offline_only=offline_only):
        return True, [], []
    added, removed, _, _ = diff_reports(
        {"findings": normalize_findings(signed.get("findings"), offline_only=offline_only)},
        {"findings": normalize_findings(fresh.get("findings"), offline_only=offline_only)})
    return False, added, removed


def _trend_epoch(value):
    """Epoch seconds for an ISO-8601 timestamp, or None when absent/unparsable."""
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


SUPPRESS_FILE = ".repobeagleignore"


REDACT_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


REDACT_CARD_RE = re.compile(r"(?<![\d.])(?:\d{4}[ -]?){3}\d{3,4}(?![\d.])")


REDACT_PHONE_RE = re.compile(r"(?<![A-Za-z0-9+])\+\d[\d ().-]{6,14}\d|"
                        r"(?<!\d)(?:\(\d{3}\)\s?|\d{3}[-. ])\d{3}[-.]\d{4}(?!\d)")


def redact_pii(s):
    """Masks emails, phones, card numbers and US SSNs in a report line, so badges don't republish the PII they found."""
    if not s:
        return s
    def email(m):
        local, _, domain = m.group(0).partition("@")
        return (local[:1] + "***@" + domain) if len(local) > 1 else "***@" + domain
    s = REDACT_EMAIL_RE.sub(email, s)
    s = re.sub(r"\b\d{3}-\d{2}-(\d{4})\b", r"***-**-\1", s)
    def card(m):
        d = re.sub(r"\D", "", m.group(0))
        return f"{d[:4]} **** **** {d[-4:]}" if len(d) >= 15 else f"{d[:2]}****{d[-2:]}"
    s = REDACT_CARD_RE.sub(card, s)
    s = REDACT_PHONE_RE.sub(lambda m: m.group(0)[:4] + "****" + m.group(0)[-3:], s)
    return s


SUPPRESS_DATE_RE = re.compile(r"(?:^|\s)@(\d{4}-\d{2}-\d{2})$")


def parse_suppression(line, lineno=0):
    """Parse `rule [# reason] [@YYYY-MM-DD]`; bare rule ids stay valid. Returns None for blank/comment lines."""
    body = line.strip()
    if not body:
        return None
    reason = ""
    if "#" in body:
        body, reason = (part.strip() for part in body.split("#", 1))
    until = None
    for field, value in (("reason", reason), ("rule", body)):
        m = SUPPRESS_DATE_RE.search(value)
        if m:
            until = m.group(1)
            if field == "reason":
                reason = value[:m.start()].rstrip()
            else:
                body = value[:m.start()].rstrip()
            break
    if not body:
        return None
    return {"rule": body, "reason": reason, "until": until, "line": lineno}


def _today():
    """Today's date; BEAGLE_TODAY=YYYY-MM-DD pins it for deterministic tests and airgapped runs."""
    raw = os.environ.get("BEAGLE_TODAY")
    if raw:
        try:
            return date.fromisoformat(raw)
        except ValueError:
            pass
    return date.today()


def suppression_status(entry, today=None):
    """'active', 'expired' or 'invalid' (an unparseable @date keeps the suppression active and is warned about)."""
    until = (entry or {}).get("until")
    if not until:
        return "active"
    try:
        when = date.fromisoformat(until)
    except ValueError:
        return "invalid"
    return "expired" if when < (today or _today()) else "active"


def load_suppressions(src):
    """Reads <repo>/.repobeagleignore: one `rule [# reason] [@YYYY-MM-DD]` per line. Never executes anything."""
    try:
        raw = (Path(src) / SUPPRESS_FILE).read_text(errors="replace")
    except OSError:
        return []
    out = []
    for n, line in enumerate(raw.splitlines(), 1):
        entry = parse_suppression(line, n)
        if entry:
            out.append(entry)
    return out


def apply_suppressions(findings, entries):
    """Marks findings matching an active entry (`suppressed: true` plus the reason/expiry).

    Expired entries re-activate the finding and are returned so the report can warn about them.
    Returns (active, suppressed, expired_entries_that_matched).
    """
    by_status: dict[str, list[dict]] = {"active": [], "expired": [], "invalid": []}
    for entry in entries:
        by_status[suppression_status(entry)].append(entry)
    keep = by_status["active"] + by_status["invalid"]
    def matches(f, entry):
        rule = _rule_of(f)
        short = rule.split(" (")[0]           # older titles have no "rule: detail" prefix
        return (fnmatchcase(rule, entry["rule"]) or fnmatchcase(short, entry["rule"])
                or fnmatchcase(f["title"], entry["rule"]))
    active, suppressed, expired = [], [], []
    for f in findings:
        entry = next((e for e in keep if matches(f, e)), None)
        if entry:
            f["suppressed"] = True
            f["suppression"] = {"rule": entry["rule"], "reason": entry.get("reason") or "",
                                 "until": entry.get("until"), "line": entry.get("line"),
                                 "status": suppression_status(entry)}
            suppressed.append(f)
            continue
        stale = next((e for e in by_status["expired"] if matches(f, e)), None)
        if stale:
            f["suppression_expired"] = {"rule": stale["rule"], "reason": stale.get("reason") or "",
                                        "until": stale["until"], "line": stale.get("line")}
            if stale not in expired:
                expired.append(stale)
        active.append(f)
    return active, suppressed, expired


def suppression_notes(entries, expired):
    """Warning notes for expired or invalid .repobeagleignore entries (auditability of the lifecycle)."""
    notes = [f"suppression for {e['rule']} expired on {e['until']}; finding re-activated" for e in expired]
    for e in entries or []:
        if suppression_status(e) == "invalid":
            notes.append(f"suppression for {e['rule']} has an invalid date {e['until']!r}; treated as active")
    return notes


def suppression_meta(entries, today=None):
    """meta.suppressions: rule, reason, until and status for every parsed entry (empty when none)."""
    return [{"rule": e["rule"], "reason": e.get("reason") or "", "until": e.get("until"),
             "status": suppression_status(e, today), "line": e.get("line")} for e in entries or []]


def _atomic_write(path, data):
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)

TEST_PATH = re.compile(r"(?i)(^|/)(tests?|testing|spec|__tests__|fixtures?|testdata)/|(^|/)test_[^/]*$|_test\.\w+$|\.spec\.\w+$")

def _json_file(path):
    try:
        return json.loads(Path(path).read_text(errors="replace"))
    except (OSError, ValueError):
        return None

# --- Hard deadline: --max-seconds, partial reports, never a truncated GREEN -----------------
def _file_seconds():
    try:
        return max(0.0, float(os.environ.get("BEAGLE_FILE_SECONDS", "10")))
    except ValueError:
        return 10.0

SCAN_FILE_SECONDS = _file_seconds()   # per-file alarm around the regex parsers (BEAGLE_FILE_SECONDS)

class ScanDeadline(BaseException):
    """The --max-seconds budget expired. A BaseException so broad `except Exception` handlers cannot swallow it."""

def _raise_scan_deadline(signum, frame):
    raise ScanDeadline("deadline reached")

class _scan_alarm:
    """Arm SIGALRM for `seconds` and raise ScanDeadline on expiry (main thread only; no-op elsewhere)."""

    def __init__(self, seconds):
        self.seconds = seconds
        self.armed = False
        self.old = None
        self.old_timer = None

    def __enter__(self):
        if (self.seconds is None or self.seconds <= 0 or not hasattr(signal, "setitimer")
                or getattr(signal, "SIGALRM", None) is None
                or threading.current_thread() is not threading.main_thread()):
            return self
        self.old = signal.getsignal(signal.SIGALRM)
        signal.signal(signal.SIGALRM, _raise_scan_deadline)
        self.old_timer = signal.setitimer(signal.ITIMER_REAL, float(self.seconds))
        self.armed = True
        return self

    def __exit__(self, *exc):
        if self.armed:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, self.old if self.old is not None else signal.SIG_DFL)
            if self.old_timer and self.old_timer[0] > 0:
                signal.setitimer(signal.ITIMER_REAL, self.old_timer[0], self.old_timer[1])
        return False

def _deadline_left(deadline):
    """Seconds until the deadline (negative once passed), or None when there is no deadline."""
    return None if deadline is None else deadline - time.monotonic()

ARCHIVE_EXT = (".zip", ".7z", ".rar", ".tar", ".tar.gz", ".tgz", ".tar.xz", ".tar.bz2", ".gz", ".xz", ".bz2", ".zst")

BINARY_EXT = {".exe", ".dll", ".so", ".dylib", ".node", ".pyc", ".jar", ".whl", ".bin", ".scr", ".msi", ".deb", ".rpm", ".apk", ".dmg"}

def zip_encrypted(p):
    """Reads only zip local-file headers (no extraction): general-purpose flag bit 0 = encrypted. 7z/rar: unknown -> None."""
    try:
        with open(p, "rb") as fh:
            head = fh.read(64)
        if head[:4] == b"PK\x03\x04":
            import zipfile  # reads the central directory only; never extracts
            try:
                with zipfile.ZipFile(p) as z:
                    return any(i.flag_bits & 1 for i in z.infolist())
            except Exception:
                return bool(int.from_bytes(head[6:8], "little") & 1)
        if head[:6] == b"7z\xbc\xaf\x27\x1c" or head[:4] == b"Rar!":
            return None
    except OSError:
        pass
    return False
