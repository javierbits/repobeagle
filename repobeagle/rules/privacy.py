import argparse, base64, concurrent.futures, difflib, hashlib, hmac, json, os, platform, queue, re, shlex, shutil, signal, subprocess, sys, tempfile, threading, time, unicodedata, uuid, zipfile
import urllib.error, urllib.parse, urllib.request
from datetime import date, datetime, timezone
from fnmatch import fnmatchcase
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from pathlib import Path


# --- cross-module imports ---

from ..core import ACTION_ATTR_RE, ANDROID_IGNORE, ANDROID_PERMS, AUTHORS_FILE_RE, CODE_EXT, CONSENT_RE, COOKIE_EXPIRES_RE, COOKIE_MAXAGE_RE, COOKIE_WRITE_RE, CREDENTIALLESS_RE, CSS_IMPORT_RE, DATA_ATTR_RE, DOC_EXT, EMBED_RE, ENDPOINT_EXT, ENDPOINT_NAMES, EXT_HIGH, EXT_INFO, FORM_RE, GENERATED_DIR_RE, HREF_ATTR_RE, I18N_FILE_RE, JS_IMPORT_URL_RE, LICENSE_FILE_RE, LINK_TAG_RE, MEDIA_RE, NON_NET_HOSTS, PACKAGE_MANAGER_RE, PERMISSIONS_POLICY_RE, POSTER_RE, PROSE_EXT, REFERRER_POLICY_RE, REFERRER_UNSAFE_RE, REL_ATTR_RE, SANDBOX_RE, SCRIPT_RE, SET_COOKIE_RE, SET_COOKIE_READ_RE, SRCSET_RE, SRC_ATTR_RE, STORAGE_RE, TEST_FILE_RE, TEST_PATH, TEST_SRC_RE, THIRD_PARTY_CDN, URL_HOST_RE, _endpoint_noise, _expiry_days, _host_of, _iframe_allow_perms, _in_line_comment, _is_comment, _is_own, _known_host, _line_of, _priv_add, finding, rel








# ----------------------------------------------------------------------------
# Privacy: telemetry, analytics, crash reporting, OTEL exporters
# ----------------------------------------------------------------------------
LOCKFILE_RE = re.compile(r"(?i)(^|/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|"
                         r"Cargo\.lock|poetry\.lock|Pipfile\.lock|uv\.lock|go\.sum|composer\.lock|Gemfile\.lock|gradle\.lockfile|"
                         r"pubspec\.lock|mix\.lock|Package\.resolved|packages\.lock\.json)$")


def _telem_rx(p): return re.compile(p, re.I)


# (kind, severity, vendor, regex). kind is the rule id in the finding title.
# Severity is privacy impact: session replay and ad pixels see what you do; analytics and
# crash reporting ship identifiers/payloads; APM/tracing reports timings; dev tools report usage.
TELEMETRY_RULES = [
    # advertising / attribution pixels
    ("ads", "high", "Meta (Facebook) Pixel", _telem_rx(r"connect\.facebook\.net|\bfbq\s*\(|\bfacebook-pixel\b")),
    ("ads", "high", "TikTok Pixel", _telem_rx(r"analytics\.tiktok\.com|\bttq\.(load|page)\b|tiktok-pixel")),
    ("ads", "high", "LinkedIn Insight Tag", _telem_rx(r"snap\.licdn\.com|linkedin\.com/li|_linkedin_partner_id")),
    ("ads", "high", "X/Twitter Pixel", _telem_rx(r"static\.ads-twitter\.com|\btwq\s*\(")),
    ("ads", "high", "Pinterest Tag", _telem_rx(r"ct\.pinterest\.com|\bpintrk\s*\(|\bpinterest-tag\b")),
    ("ads", "high", "Reddit Pixel", _telem_rx(r"redditstatic\.com|\brdt\s*\(")),
    ("ads", "high", "Microsoft Advertising UET", _telem_rx(r"bat\.bing\.com|\buetq\b")),
    ("ads", "high", "Google AdSense", _telem_rx(r"pagead2\.googlesyndication\.com|\badsbygoogle\b|ca-pub-\d+")),
    ("ads", "high", "Google Ad Manager", _telem_rx(r"securepubads\.g\.doubleclick\.net|\bgoogletag\.|/gpt\.js")),
    ("ads", "high", "Criteo", _telem_rx(r"\bcriteo\b")),
    ("ads", "high", "Taboola", _telem_rx(r"\btaboola\b")),
    ("ads", "high", "Outbrain", _telem_rx(r"\boutbrain\b")),
    ("ads", "high", "Amazon Ads", _telem_rx(r"amazon-adsystem")),
    ("ads", "high", "AdRoll", _telem_rx(r"adroll\.com|adroll_adv_id|adroll_current_session")),
    ("ads", "high", "Quora Pixel", _telem_rx(r"quora\.com/_/ad|\bqpixel\b")),
    ("ads", "high", "Snap Pixel", _telem_rx(r"sc-static\.net|\bsnaptr\b")),
    ("ads", "medium", "Google Ads conversion", _telem_rx(r"googleadservices\.com|/pagead/conversion")),
    ("ads", "high", "AppsFlyer", _telem_rx(r"appsflyer")),
    ("ads", "high", "Adjust", _telem_rx(r"adjust\.com|@adjust/|adjust[_-]sdk")),
    ("ads", "medium", "Branch", _telem_rx(r"app\.branch\.io|branch\.io/v1|@branch/")),
    # session replay / recording
    ("session-replay", "high", "Microsoft Clarity", _telem_rx(r"clarity\.ms|@microsoft/clarity|clarity-analytics")),
    ("session-replay", "high", "Hotjar", _telem_rx(r"\bhotjar\b")),
    ("session-replay", "high", "FullStory", _telem_rx(r"\bfullstory\b")),
    ("session-replay", "high", "LogRocket", _telem_rx(r"\blogrocket\b")),
    ("session-replay", "high", "Smartlook", _telem_rx(r"\bsmartlook\b")),
    ("session-replay", "high", "Mouseflow", _telem_rx(r"\bmouseflow\b")),
    ("session-replay", "high", "Lucky Orange", _telem_rx(r"\bluckyorange\b")),
    ("session-replay", "high", "Highlight.io", _telem_rx(r"highlight\.io|highlight-run")),
    ("session-replay", "high", "OpenReplay", _telem_rx(r"\bopenreplay\b")),
    ("session-replay", "high", "Datadog RUM/Replay", _telem_rx(r"@datadog/browser|datadoghq\.com|datadog-rum|\bdd-rum\b")),
    ("session-replay", "high", "Contentsquare", _telem_rx(r"contentsquare|content-square")),
    ("session-replay", "high", "Quantum Metric", _telem_rx(r"quantummetric|quantum-metric")),
    ("session-replay", "high", "rrweb", _telem_rx(r"\brrweb\b|@rrweb/")),
    ("session-replay", "high", "Sentry Replay", _telem_rx(r"replaysSessionSampleRate|replaysOnErrorSampleRate|replayIntegration")),
    ("session-replay", "high", "PostHog Replay", _telem_rx(r"disable_session_recording\s*[:=]\s*false|session_recording\s*:\s*\{")),
    ("session-replay", "high", "Glassbox", _telem_rx(r"\bglassbox\b")),
    ("session-replay", "medium", "Medallia", _telem_rx(r"\bmedallia\b")),
    # product / web analytics
    ("analytics", "medium", "Google Tag Manager", _telem_rx(r"googletagmanager\.com|\bGTM-[A-Z0-9]{4,}\b")),
    ("analytics", "medium", "Google Analytics", _telem_rx(r"google-analytics\.com|\bgtag\s*\(|\bUA-\d{4,}-\d+\b|"
                                                          r"\bG-(?=[A-Z0-9]{6,}\b)(?=[A-Z0-9]*\d)[A-Z0-9]+\b")),
    ("analytics", "medium", "Plausible", _telem_rx(r"plausible\.io|@plausible/|plausible-analytics")),
    ("analytics", "medium", "Umami", _telem_rx(r"umami\.is|umami-analytics|data-website-id")),
    ("analytics", "medium", "Matomo/Piwik", _telem_rx(r"matomo|piwik|\b_paq\b")),
    ("analytics", "medium", "Fathom", _telem_rx(r"usefathom|fathom\.com|fathom-analytics")),
    ("analytics", "medium", "GoatCounter", _telem_rx(r"goatcounter")),
    ("analytics", "medium", "Simple Analytics", _telem_rx(r"simpleanalytics")),
    ("analytics", "medium", "Cloudflare Web Analytics", _telem_rx(r"static\.cloudflareinsights|cloudflareinsights")),
    ("analytics", "medium", "Vercel Analytics", _telem_rx(r"@vercel/analytics|vercel/analytics")),
    ("analytics", "medium", "Vercel Speed Insights", _telem_rx(r"@vercel/speed-insights|vercel/speed-insights")),
    ("analytics", "medium", "Segment", _telem_rx(r"segment\.io|@segment/analytics|analytics-node|cdn\.segment\.com")),
    ("analytics", "medium", "Mixpanel", _telem_rx(r"\bmixpanel\b")),
    ("analytics", "medium", "Amplitude", _telem_rx(r"api2?\.amplitude|\bamplitude\.(init|getInstance|track)|@amplitude/")),
    ("analytics", "medium", "PostHog", _telem_rx(r"\bposthog\b")),
    ("analytics", "medium", "Firebase Analytics", _telem_rx(r"firebase[_-]analytics|firebase/analytics")),
    ("analytics", "medium", "Heap Analytics", _telem_rx(r"heap\.io|heap-analytics|\bheap\.track\(")),
    ("analytics", "medium", "Countly", _telem_rx(r"\bcountly\b")),
    ("analytics", "medium", "Adobe Analytics", _telem_rx(r"omtrdc\.net|adobedtm|\bappmeasurement\b")),
    ("analytics", "medium", "Yandex Metrica", _telem_rx(r"mc\.yandex\.ru|\bym\s*\(\s*\d")),
    ("analytics", "medium", "Baidu Tongji", _telem_rx(r"hm\.baidu\.com")),
    ("analytics", "medium", "WordPress Stats", _telem_rx(r"stats\.wp\.com")),
    ("analytics", "medium", "Snowplow", _telem_rx(r"\bsnowplow\b|@snowplow/")),
    ("analytics", "medium", "RudderStack", _telem_rx(r"rudderstack|@rudderstack/")),
    ("analytics", "medium", "Pendo", _telem_rx(r"\bpendo\b")),
    ("analytics", "medium", "Optimizely", _telem_rx(r"\boptimizely\b")),
    ("analytics", "medium", "VWO", _telem_rx(r"vwo\.com|visualwebsiteoptimizer|_vwo_code")),
    ("analytics", "medium", "HubSpot", _telem_rx(r"hs-scripts\.com|hsforms\.(?:net|com)|hubspotutk|@hubspot/|\bhubspot(?=[\"'/>.)-])")),
    ("analytics", "medium", "Klaviyo", _telem_rx(r"\bklaviyo\b")),
    ("analytics", "medium", "Braze", _telem_rx(r"\bbraze\b|appboy")),
    ("analytics", "medium", "OneSignal", _telem_rx(r"\bonesignal\b")),
    ("analytics", "medium", "Customer.io", _telem_rx(r"(?<![\w-])customer\.io|\bcustomerio\b")),
    ("analytics", "medium", "Tealium", _telem_rx(r"\btealium\b|tiq\.js")),
    ("analytics", "medium", "Mailchimp", _telem_rx(r"mailchimp|chimpstatic")),
    ("analytics", "medium", "Intercom", _telem_rx(r"intercom\.(?:io|com)|intercom-")),
    ("analytics", "low", "Tracking pixel", _telem_rx(r"1x1\.(gif|png)|pixel\.gif|\btracking[ -]pixel\b|"
                                                        r"width\s*=\s*[\"']?1[\"']?\s+height\s*=\s*[\"']?1[\"']?|"
                                                        r"height\s*=\s*[\"']?1[\"']?\s+width\s*=\s*[\"']?1[\"']?|"
                                                        r"width:\s*1px[^\"']*height:\s*1px")),
    # crash / error reporting
    ("crash", "medium", "Sentry", _telem_rx(r"sentry\.io|@sentry/|sentry_sdk|sentry\.properties|\bsentry\b")),
    ("apm", "medium", "Sentry Tracing", _telem_rx(r"tracesSampleRate|tracesSampler|@sentry/tracing")),
    ("crash", "medium", "Bugsnag", _telem_rx(r"\bbugsnag\b")),
    ("crash", "medium", "Rollbar", _telem_rx(r"\brollbar\b")),
    ("crash", "medium", "Raygun", _telem_rx(r"\braygun\b")),
    ("crash", "medium", "Honeybadger", _telem_rx(r"\bhoneybadger\b")),
    ("crash", "medium", "Airbrake", _telem_rx(r"\bairbrake\b")),
    ("crash", "medium", "Exceptionless", _telem_rx(r"exceptionless")),
    ("crash", "medium", "Firebase Crashlytics", _telem_rx(r"crashlytics|firebase[_-]crash")),
    ("crash", "medium", "Application Insights", _telem_rx(r"applicationinsights|application-insights|appinsights|azure-monitor")),
    ("crash", "medium", "Instabug", _telem_rx(r"\binstabug\b")),
    ("crash", "medium", "Embrace", _telem_rx(r"embrace\.io|@embrace-io/")),
    ("crash", "medium", "Backtrace", _telem_rx(r"\bbacktrace\.io|@backtrace/")),
    ("crash", "medium", "TrackJS", _telem_rx(r"\btrackjs\b")),
    ("crash", "medium", "Bugsplat", _telem_rx(r"\bbugsplat\b")),
    # APM / tracing
    ("apm", "medium", "OpenTelemetry (OTEL)", _telem_rx(r"opentelemetry|\botel\b|\botel[._/-]|\botlp\b")),
    ("apm", "low", "Datadog (APM)", _telem_rx(r"datadoghq|dd-trace|\bddtrace\b|datadog")),
    ("apm", "low", "New Relic", _telem_rx(r"newrelic|new-relic|nr-data\.net")),
    ("apm", "low", "Elastic APM", _telem_rx(r"elastic-apm|@elastic/apm|elastic_apm")),
    ("apm", "low", "Honeycomb", _telem_rx(r"honeycomb\.io|honeycombio|libhoney")),
    ("apm", "low", "Dynatrace", _telem_rx(r"dynatrace|ruxit")),
    ("apm", "low", "Instana", _telem_rx(r"\binstana\b")),
    ("apm", "low", "AppSignal", _telem_rx(r"appsignal")),
    ("apm", "low", "Grafana Faro", _telem_rx(r"@grafana/faro|grafana.*faro")),
    # developer-tool / CLI telemetry
    ("devtool", "low", "Next.js telemetry", _telem_rx(r"NEXT_TELEMETRY_DISABLED|next telemetry")),
    ("devtool", "low", "Nuxt telemetry", _telem_rx(r"NUXT_TELEMETRY_DISABLED")),
    ("devtool", "low", "Astro telemetry", _telem_rx(r"ASTRO_TELEMETRY_DISABLED")),
    ("devtool", "low", "Gatsby telemetry", _telem_rx(r"GATSBY_TELEMETRY_DISABLED")),
    ("devtool", "low", "Turbo telemetry", _telem_rx(r"TURBO_TELEMETRY_DISABLED|turbo telemetry")),
    ("devtool", "low", "Angular CLI analytics", _telem_rx(r"NG_CLI_ANALYTICS")),
    ("devtool", "low", ".NET CLI telemetry", _telem_rx(r"DOTNET_CLI_TELEMETRY_OPTOUT|dotnet telemetry")),
    ("devtool", "low", "Homebrew analytics", _telem_rx(r"HOMEBREW_NO_ANALYTICS|brew analytics")),
    ("devtool", "low", "HashiCorp checkpoint", _telem_rx(r"CHECKPOINT_DISABLE")),
    ("devtool", "low", "Scarf package analytics", _telem_rx(r"scarf\.sh|\bscarf\b")),
]


TELEMETRY_MEANING = {
    "ads": "Advertising/attribution pixel: reports page views and a per-browser/session ID to the vendor.",
    "session-replay": "Session replay: can record clicks, keystrokes, forms and page content, not just counts.",
    "analytics": "Product/web analytics: page views, events and a persistent identifier leave the device.",
    "crash": "Crash/error reporting: stack traces and payloads (often file paths, env and request data) are uploaded.",
    "apm": "APM/tracing: spans, logs or metrics are exported; OTEL only sends if an exporter endpoint is configured.",
    "devtool": "Developer-tool telemetry: the CLI/build tool reports usage; usually disabled with an env var.",
}


TELEMETRY_OPTOUT_RE = re.compile(
    r"(?i)(DO_NOT_TRACK|NEXT_TELEMETRY_DISABLED|NUXT_TELEMETRY_DISABLED|ASTRO_TELEMETRY_DISABLED|GATSBY_TELEMETRY_DISABLED|"
    r"TURBO_TELEMETRY_DISABLED|DOTNET_CLI_TELEMETRY_OPTOUT|HOMEBREW_NO_ANALYTICS|CHECKPOINT_DISABLE|"
    r"NG_CLI_ANALYTICS\s*[=:]\s*(false|off)|telemetry\s*[=:]\s*(false|off)|disable[_-]?telemetry|no[_-]?telemetry|"
    r"analytics\s*[=:]\s*(false|off)|TELEMETRY_OPTOUT|DISABLE_TELEMETRY|NO_?TELEMETRY|--no-?telemetry|disable[_-]?analytics|"
    r"optOutCapturing|opt_out_capturing|setOptOut|set_opt_out|disableTracking|disable_tracking|"
    r"trackingEnabled\s*[=:]\s*false|analytics\.disable\s*\()")


DNT_RE = re.compile(r"(?i)(navigator\.doNotTrack|\bdoNotTrack\b|globalPrivacyControl|\bGPC\b|\bDNT\b|Sec-GPC)")


TELEMETRY_PACKAGES = [
    ("crash", "Sentry", ("sentry", "sentry-sdk", "sentry-go", "sentry-", "sentry_", "@sentry/")),
    ("analytics", "Firebase Analytics", ("firebase-analytics", "firebase_analytics", "firebase/analytics")),
    ("apm", "OpenTelemetry (OTEL)", ("opentelemetry", "opentelemetry-", "@opentelemetry/", "go.opentelemetry.io/otel", "otel")),
    ("analytics", "Heap Analytics", ("heap-analytics", "heap-js", "@heap/")),
    ("analytics", "Countly", ("countly-sdk-web", "countly-sdk-", "@countly/")),
    ("analytics", "Pendo", ("pendo-", "@pendo/")),
    ("analytics", "Optimizely", ("optimizely-", "@optimizely/")),
    ("analytics", "VWO", ("vwo-", "@vwo/")),
    ("analytics", "HubSpot", ("@hubspot/", "hubspot-")),
    ("analytics", "Klaviyo", ("klaviyo-", "@klaviyo/")),
    ("analytics", "Braze", ("braze-", "@braze/")),
    ("analytics", "OneSignal", ("onesignal-", "@onesignal/")),
    ("analytics", "Customer.io", ("customerio-", "@customerio/")),
    ("analytics", "Tealium", ("@tealium/", "tealium-")),
    ("analytics", "Mailchimp", ("@mailchimp/", "mailchimp-")),
    ("analytics", "Intercom", ("intercom-", "@intercom/")),
    ("analytics", "PostHog", ("posthog", "posthog-js", "posthog-python", "posthog_")),
    ("analytics", "Segment", ("@segment/", "analytics-node", "segment")),
    ("analytics", "Mixpanel", ("mixpanel", "mixpanel-", "mixpanel_")),
    ("analytics", "Amplitude", ("amplitude", "amplitude_", "@amplitude/")),
    ("analytics", "Google Analytics", ("react-ga", "react-ga4", "ga-", "@google-analytics/", "gtag")),
    ("analytics", "Plausible", ("plausible", "plausible-", "@plausible/")),
    ("analytics", "Vercel Speed Insights", ("@vercel/speed-insights",)),
    ("ads", "AdRoll", ("@adroll/", "adroll-")),
    ("crash", "Instabug", ("@instabug/", "instabug-", "instabug_flutter")),
    ("crash", "Embrace", ("@embrace-io/", "embrace-")),
    ("analytics", "Umami", ("umami", "umami-")),
    ("session-replay", "Hotjar", ("hotjar", "react-hotjar", "@hotjar/")),
    ("session-replay", "FullStory", ("fullstory", "@fullstory/")),
    ("session-replay", "LogRocket", ("logrocket", "logrocket-")),
    ("session-replay", "Smartlook", ("smartlook",)),
    ("session-replay", "Microsoft Clarity", ("@microsoft/clarity", "clarity-js")),
    ("crash", "Bugsnag", ("bugsnag", "@bugsnag/")),
    ("crash", "Rollbar", ("rollbar", "rollbar-")),
    ("crash", "Firebase Crashlytics", ("@react-native-firebase/crashlytics", "firebase-crashlytics", "crashlytics")),
    ("apm", "Datadog", ("ddtrace", "dd-trace", "dd-trace-", "@datadog/", "datadog")),
    ("apm", "New Relic", ("newrelic", "@newrelic/", "newrelic-")),
    ("apm", "Elastic APM", ("elastic-apm", "@elastic/apm-rum")),
    ("apm", "Honeycomb", ("libhoney", "honeycomb", "@honeycombio/")),
    ("apm", "Dynatrace", ("@dynatrace/", "dynatrace", "ruxit")),
]


def _pkg_is(name, pat):
    return name == pat or (pat.endswith(("/", "-")) and name.startswith(pat))


def lockfile_packages(p, text):
    """Package names only. Reads the manifest text; never resolves or downloads anything."""
    out, name = set(), p.name
    try:
        if name == "package-lock.json":
            d = json.loads(text)
            for k in (d.get("packages") or {}):
                out.add(k[len("node_modules/"):] if k.startswith("node_modules/") else k)
            for sec in ("dependencies", "devDependencies", "optionalDependencies"):
                out.update((d.get(sec) or {}).keys())
        elif name == "yarn.lock":
            for m in re.finditer(r'(?m)^"?(@?[A-Za-z0-9._/-]+)@[^:\s]+:', text):
                out.add(m.group(1))
        elif name == "pnpm-lock.yaml":
            for m in re.finditer(r"(?m)^\s{2,}/?(@?[A-Za-z0-9._/-]+?)(?:@[^:\s]+)?:", text):
                out.add(m.group(1))
        elif name in ("Cargo.lock", "poetry.lock", "uv.lock"):
            out.update(re.findall(r'(?m)^name = "([^"]+)"', text))
        elif name == "go.sum":
            for line in text.split("\n"):
                parts = line.split()
                if len(parts) >= 2:
                    out.add(parts[0])
        elif name == "Gemfile.lock":
            out.update(re.findall(r'(?m)^ {4}([A-Za-z0-9_.-]+) \(', text))
        elif name == "Pipfile.lock":
            d = json.loads(text)
            for sec in ("default", "develop"):
                out.update((d.get(sec) or {}).keys())
        elif name == "pubspec.lock":
            out.update(re.findall(r'(?m)^  ([a-z0-9_]+):', text))
        elif name == "mix.lock":
            out.update(re.findall(r'(?m)^\s*"([^"]+)"\s*:\s*\{:', text))
        elif name == "Package.resolved":
            d = json.loads(text)
            for pin in d.get("pins") or []:
                if isinstance(pin, dict):
                    nm = pin.get("identity") or pin.get("package")
                    if nm:
                        out.add(nm)
        elif name == "packages.lock.json":
            d = json.loads(text)
            for tf in (d.get("dependencies") or {}).values():
                if isinstance(tf, dict):
                    out.update(tf.keys())
        elif name == "composer.lock":
            d = json.loads(text)
            for sec in ("packages", "packages-dev"):
                for pkg in d.get(sec) or []:
                    if isinstance(pkg, dict) and pkg.get("name"):
                        out.add(pkg["name"])
    except Exception:
        return out
    return out


def check_telemetry(root, p, text, telemetry, optouts, optouts_code):
    """Collects one entry per vendor, first seen (file:line). No network, no code execution."""
    r = rel(root, p)
    if LOCKFILE_RE.search(r):          # transitive deps are not evidence of this repo phoning home
        for dep in lockfile_packages(p, text):
            names = {dep, dep.rsplit("/", 1)[-1]}     # go.sum modules and scoped paths
            for kind, vendor, pats in TELEMETRY_PACKAGES:
                if any(_pkg_is(n, pat) for n in names for pat in pats):
                    key = (kind, vendor, "lockfile")
                    t = telemetry.get(key)
                    if t:
                        t["count"] += 1
                    else:
                        telemetry[key] = {"kind": kind, "sev": "low", "vendor": vendor, "file": r,
                                          "line": _line_of(text, dep), "snippet": dep, "count": 1, "src": "lockfile"}
        return
    # Prose mentions vendors without using them ("alternative to Sentry"), so only opt-outs count there.
    prose = (p.suffix.lower() in PROSE_EXT or (p.suffix.lower() == ".txt" and bool(re.search(r"(?i)(^|/)docs?/", r)))
             or bool(AUTHORS_FILE_RE.search(r)) or bool(LICENSE_FILE_RE.search(r)) or p.name == "CODEOWNERS")
    test_src = bool(TEST_SRC_RE.search(r) or TEST_FILE_RE.search(r)) and not r.startswith("tests/fixtures/")
    for i, line in enumerate(text.split("\n"), 1):
        if len(line) > 2000:
            continue
        for m in TELEMETRY_OPTOUT_RE.finditer(line):
            optouts.add(m.group(1))
            if not prose:
                optouts_code.add(m.group(1))
        if DNT_RE.search(line):
            optouts.add("Do-Not-Track")
            if not prose:
                optouts_code.add("Do-Not-Track")
        if prose or _is_comment(line):
            continue          # a comment mentioning a vendor is a note, not a request
        if test_src or I18N_FILE_RE.search(r) or GENERATED_DIR_RE.search(r):
            continue          # test/i18n/generated files list words that happen to match vendor names; shipped behaviour is what matters
        if re.match(r'\s*\("(?:ads|analytics|session-replay|crash|apm|devtool)",', line):
            continue          # a vendor table entry is a definition, not usage
        for kind, sev, vendor, rx in TELEMETRY_RULES:
            if vendor == "Tracking pixel" and p.suffix.lower() not in (
                    ".html", ".htm", ".css", ".scss", ".less", ".js", ".jsx", ".ts", ".tsx",
                    ".vue", ".svelte", ".astro", ".php"):
                if not re.search(r"(?i)(src\s*=|href\s*=|url\(|content\s*=|\bpixel\b|\bbeacon\b|tracking)", line):
                    continue      # a literal like 1x1.png in test data is not a beacon
            key = (kind, vendor, "direct")
            if key in telemetry:
                if rx.search(line):
                    telemetry[key]["count"] += 1
                continue
            if rx.search(line):
                telemetry[key] = {"kind": kind, "sev": sev, "vendor": vendor, "file": r, "line": i,
                                  "snippet": line, "count": 1, "src": "direct"}


def telemetry_findings(telemetry, optouts, optouts_code):
    order = {"ads": 0, "session-replay": 1, "analytics": 2, "crash": 3, "apm": 4, "devtool": 5}
    direct = {vendor for (_, vendor, src) in telemetry if src == "direct"}
    fs = []
    for (kind, vendor, src), t in sorted(telemetry.items(), key=lambda kv: (order.get(kv[1]["kind"], 9), kv[1]["vendor"])):
        if src == "lockfile" and vendor in direct:
            continue              # already reported where the repo itself uses it
        if src == "lockfile":
            meaning = f"Transitive dependency pinned in {t['file']}: the repo ships this telemetry without importing it itself."
        elif t["count"] > 1:
            meaning = f"Seen {t['count']} times; first at {t['file']}:{t['line']}."
        else:
            meaning = "Detected in this file."
        if optouts_code:
            meaning += " Opt-out handled in code: " + ", ".join(sorted(optouts_code)[:4]) + "."
        elif optouts:
            meaning += " Opt-out only documented, no code reference: " + ", ".join(sorted(optouts)[:4]) + "."
        elif kind == "devtool":
            meaning += " Disable with the env var named in the rule."
        else:
            meaning += " No opt-out / disable flag found in the repo."
        title = f"telemetry-{kind}: {vendor}" + (" (transitive)" if src == "lockfile" else "")
        fs.append(finding("telemetry", t["sev"], t["file"], t["line"], title, t["snippet"],
                          TELEMETRY_MEANING[kind] + " " + meaning))
    return fs


def check_privacy(root, p, text, privacy, own=()):
    """Third-party hosts, cookie/storage writes, consent managers and platform permissions. Static only."""
    r, ext = rel(root, p), p.suffix.lower()
    if LOCKFILE_RE.search(r) or ext in PROSE_EXT:
        return
    is_doc = (ext in DOC_EXT and ext not in (".html", ".htm")) or bool(re.search(r"(?i)(^|/)docs?/", r))
    is_i18n = bool(I18N_FILE_RE.search(r))
    test_path = bool(TEST_PATH.search(r) or TEST_FILE_RE.search(r))
    scan_endpoints = ext in ENDPOINT_EXT or p.name in ENDPOINT_NAMES or p.name.startswith(".env")
    web = ext in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte", ".astro", ".html", ".htm")
    is_manifest = p.name == "manifest.json"
    manifest = None
    if is_manifest:
        try: manifest = json.loads(text)
        except Exception: manifest = None
        if not isinstance(manifest, dict) or "manifest_version" not in manifest:
            manifest = None
    lines = text.split("\n")
    if p.name == "AndroidManifest.xml":
        for qb in re.findall(r"(?is)<queries>(.*?)</queries>", text):
            for pm in re.finditer(r'<package[^>]*android:name="([^"]+)"', qb):
                _priv_add(privacy, "android-queries", "info", pm.group(1), r, _line_of(text, pm.group(1)), pm.group(0),
                          "Manifest <queries> lists an installed app this app can see/discover (Android 11 package visibility).")
            for ib in re.findall(r"(?is)<intent>(.*?)</intent>", qb):
                acts = re.findall(r'<action[^>]*android:name="([^"]+)"', ib)
                data = re.findall(r'<data[^>]*android:(?:scheme|host|mimeType)="([^"]+)"', ib)
                for a in acts:
                    _priv_add(privacy, "android-queries", "info", a, r, _line_of(text, a), a,
                              "Manifest <queries> intent filter: this app can discover handlers for "
                              + (", ".join(data) if data else "that intent") + ".")
    for i, line in enumerate(lines, 1):
        if len(line) > 2000:
            continue
        if scan_endpoints:
            hosts = [(um.group(1).lower(), um.group(2).lower(), um.start()) for um in URL_HOST_RE.finditer(line)]
            hosts += [("https", pm.group(1).lower(), pm.start()) for pm in PROTO_REL_RE.finditer(line)]
            for scheme, host, pos in hosts:
                if host in NON_NET_HOSTS or _endpoint_noise(host):
                    continue
                if _in_line_comment(line, pos):
                    continue      # inline comment: "256 # https://dev.mysql.com/..." or "// http://..."

                if any(rx.search(host) for _, _, _, rx in TELEMETRY_RULES):
                    continue          # already reported by the telemetry check
                if _is_comment(line):
                    continue          # a reference URL in a comment is not a request
                xml_ref = re.search(r"(?i)(xmlns|schemaLocation|setFeature|DOCTYPE|noNamespaceSchemaLocation)", line)
                archived = "web.archive.org/web/" in line[:pos]
                url_value = bool(re.search(r"(?i)\bnew\s+URL\(|\bURL\((?:string:)?[\"']|\bURL\s*=\s*[\"']", line))
                tag_ctx = None
                tag_window = line
                if not re.search(r"(?i)<(img|video|source|audio|picture|script|iframe|link)\b", line) and \
                        re.search(r"(?i)\b(?:src|href|srcset|poster|action)\s*=", line):
                    back = "\n".join(lines[max(0, i - 6):i])
                    tag_window = back + "\n" + line + "\n" + "\n".join(lines[i:i + 3])
                    cand = []
                    for pat, ctx in ((r"<(?:img|video|source|audio|picture)\b", "media"), (r"<script\b", "script"),
                                     (r"<iframe\b", "embed"), (r"<link\b", "link"), (r"<form\b", "form")):
                        ms = list(re.finditer(r"(?i)" + pat, back))
                        if ms:
                            cand.append((ms[-1].start(), ctx))
                    if cand:
                        best = max(cand)
                        tag_ctx = best[1]
                        tag_window = back[best[0]:] + "\n" + line + "\n" + "\n".join(lines[i:i + 3])
                    if tag_ctx == "link":
                        relm = re.search(r"(?i)\brel\s*=\s*[\"']([^\"']+)", tag_window)
                        relv = relm.group(1).lower() if relm else ""
                        tag_ctx = ("stylesheet" if "stylesheet" in relv else
                                   "preload" if ("preload" in relv or "prefetch" in relv or "modulepreload" in relv) else
                                   "preconnect" if ("preconnect" in relv or "dns-prefetch" in relv) else None)
                if scheme in ("http", "ws"):
                    requested = re.search(r"(?i)(fetch\s*\(|curl|wget|requests\.|urlopen|src\s*=|href\s*=|action\s*=|XMLHttpRequest|axios|WebSocket|\.get\s*\()", line)
                    _priv_add(privacy, "insecure-endpoint",
                              "info" if (xml_ref or archived or url_value or test_path or is_i18n) or (is_doc and not requested)
                              else ("medium" if requested else "low"),
                              host, r, i, line,
                              f"Plaintext {scheme}:// to {host}: "
                              + ("XML namespace/schema identifier, not a fetched URL." if xml_ref else
                                 "URL value constructed here, not fetched on this line." if url_value else
                                 "historical URL inside a web.archive.org link." if archived else
                                 "requests and metadata are not encrypted in transit." if requested else
                                 "reference URL in docs, not a request." if is_doc else
                                 "translation-string link, not a runtime request." if is_i18n else
                                 "test fixture URL, not a runtime request." if test_path else
                                 "reference URL, not a request in this line."))
                elif _is_own(host, own):
                    _priv_add(privacy, "first-party-endpoint", "info", host, r, i, line,
                              f"Own/related domain {host}: first-party traffic, not a third party.")
                elif re.search(r"url\(\s*[\"']?$", line[:pos]) and not re.match(r"\s*@import", line):
                    _priv_add(privacy, "third-party-media",
                              "info" if (host in THIRD_PARTY_CDN or _known_host(host) or is_doc or test_path) else "low",
                              host, r, i, line,
                              f"CSS url() asset from {host}: it sees your IP and the page URL.")
                elif tag_ctx == "media":
                    _priv_add(privacy, "third-party-media",
                              "info" if (host in THIRD_PARTY_CDN or _known_host(host) or is_doc or test_path) else "low",
                              host, r, i, line,
                              f"Media attribute on a tag opened above loads from {host}: it sees your IP and the page URL.")
                elif tag_ctx == "script":
                    _priv_add(privacy, "third-party-script", "info" if host in THIRD_PARTY_CDN else "low",
                              host, r, i, line,
                              f"Script attribute on a tag opened above loads executable code from {host}.")
                elif tag_ctx == "embed":
                    safe = bool(re.search(r"(?i)\bsandbox\b", tag_window))
                    _priv_add(privacy, "third-party-embed", "info" if safe else "low", host, r, i, line,
                              f"Embed attribute on a tag opened above includes content/code from {host}."
                              + (" Sandboxed, which limits what it can do." if safe else ""))
                    risky = _iframe_allow_perms(tag_window)
                    if risky:
                        _priv_add(privacy, "iframe-allow", "medium", host, r, i, line,
                                  f"iframe delegates {', '.join(risky)} to {host}: the embedded page can use that capability.")
                elif tag_ctx == "stylesheet":
                    _priv_add(privacy, "third-party-stylesheet", "info" if host in THIRD_PARTY_CDN else "low",
                              host, r, i, line,
                              f"Stylesheet attribute on a <link> opened above loads from {host}.")
                elif tag_ctx == "preload":
                    _priv_add(privacy, "third-party-preload", "info" if host in THIRD_PARTY_CDN else "low",
                              host, r, i, line,
                              f"Preload/prefetch on a <link> opened above fetches from {host} early.")
                elif tag_ctx == "preconnect":
                    _priv_add(privacy, "third-party-preconnect", "info" if host in THIRD_PARTY_CDN else "low",
                              host, r, i, line,
                              f"Preconnect/DNS-prefetch on a <link> opened above opens a connection to {host} early.")
                elif tag_ctx == "form":
                    am = ACTION_ATTR_RE.search(tag_window)
                    if am and not _is_own(_host_of(am.group(1)) or "", own):
                        _priv_add(privacy, "third-party-form", "low", host, r, i, line,
                                  f"Form action on a <form> opened above posts user data to {host}.")
                elif host in THIRD_PARTY_CDN:
                    _priv_add(privacy, "third-party-cdn", "info" if (is_doc or test_path) else "low", host, r, i, line,
                              f"Asset requested from {host}: it sees your IP and the page URL (third-party font/CDN)"
                              + (" (docs/test reference)." if (is_doc or test_path) else "."))
                elif _known_host(host):
                    _priv_add(privacy, "external-endpoint", "info", host, r, i, line,
                              f"Network destination {host} (known platform/infrastructure).")
                else:
                    pre = line[max(0, pos - 80):pos]
                    specific = bool(re.search(r"(?i)(?:src|srcset|poster|action|data)\s*=\s*[\"']?$", pre)
                                    or re.search(r"(?i)(?:import|from)\s*\(?\s*[\"']?$", pre)
                                    or re.search(r"url\(\s*[\"']?$", pre)
                                    or (re.search(r"(?i)href\s*=\s*[\"']?$", pre)
                                        and (re.search(r"(?i)<(?:img|source|script|video|audio|picture)\b", line)
                                             or re.search(r"(?i)rel\s*=\s*[\"'][^\"']*(?:stylesheet|preload|prefetch|modulepreload|preconnect|dns-prefetch)", line))))
                    if specific:
                        continue      # the tag/asset rule below reports this host more precisely
                    _priv_add(privacy, "external-endpoint",
                              "info" if (is_doc or test_path or is_i18n or url_value) else "low", host, r, i, line,
                              f"Unknown third-party host {host}: "
                              + ("docs link; not fetched at runtime." if is_doc else
                                 "translation-string link." if is_i18n else
                                 "test fixture URL." if test_path else
                                 "URL value constructed here, not fetched on this line." if url_value else
                                 "verify what it receives and whether it sets cookies/tracks."))
        if COOKIE_WRITE_RE.search(line):
            js_cookie = bool(re.search(r"\bCookies\.(?:set|remove)\s*\(", line))
            _priv_add(privacy, "cookie-write", "low", "js-cookie" if js_cookie else "document.cookie", r, i, line,
                      "JavaScript writes a cookie (persistent client-side identifier; check lifetime and consent)."
                      + (" Detected via the js-cookie library." if js_cookie else ""))
            if js_cookie and "Cookies.remove" not in line:
                window = " ".join(lines[max(0, i - 2):i + 3])
                missing = []
                if not re.search(r"(?i)\bsecure\s*:\s*(?:true|1)", window):
                    missing.append("Secure")
                if not re.search(r"(?i)\bsameSite\s*:", window):
                    missing.append("SameSite")
                if missing:
                    _priv_add(privacy, "cookie-flags", "low", "js-cookie missing " + "/".join(missing), r, i, line,
                              f"js-cookie write without {'/'.join(missing)} in its options: "
                              + ("sent in clear" if "Secure" in missing else "")
                              + ("; " if len(missing) > 1 else "")
                              + ("sent cross-site" if "SameSite" in missing else "") + ".")
                xm = re.search(r"(?i)\bexpires\s*:\s*([0-9]+)\b", window)
                if xm:
                    days = int(xm.group(1))
                    if days == 0:
                        _priv_add(privacy, "cookie-lifetime", "info", "cookie deletion (expires: 0)", r, i, line,
                                  "js-cookie expires:0 deletes the cookie.")
                    elif days > 365:
                        _priv_add(privacy, "cookie-lifetime", "low", "cookie lifetime > 1 year", r, i, line,
                                  f"js-cookie expires:{days} (days) lives over a year: long-lived identifiers outlive their purpose.")
                    else:
                        _priv_add(privacy, "cookie-lifetime", "info", "short-lived cookie", r, i, line,
                                  f"js-cookie expires in {days} days.")
        if STORAGE_RE.search(line):
            _priv_add(privacy, "browser-storage", "info", "localStorage/sessionStorage", r, i, line,
                      "Data stored in the browser: survives reloads (localStorage) and can be used to track the user.")
        if not _is_comment(line) and re.search(r"(?i)\bpartitioned\b", line):
            _priv_add(privacy, "cookie-flags", "info", "Partitioned (CHIPS)", r, i, line,
                      "Partitioned cookie (CHIPS): stored per top-level site, which limits cross-site tracking.")
        if ext == ".xml" and re.search(r'(?i)cleartextTrafficPermitted\s*=\s*"true"', line):
            _priv_add(privacy, "android-cleartext", "medium", "network security config", r, i, line,
                      "Network security config permits cleartext HTTP for these domains.")
        if "__Host-" in line or "__Secure-" in line:
            needs = {"__Host-": ("Secure", "Path=/"), "__Secure-": ("Secure",)}
            for prefix, reqs in needs.items():
                if prefix not in line or not re.search(re.escape(prefix) + r"[\w.-]+", line):
                    continue          # prefix mentioned in prose/an error message, not a cookie name
                if not all(x.lower() in line.lower() for x in reqs):
                    _priv_add(privacy, "cookie-flags", "low", prefix + " prefix without required flags", r, i, line,
                              f"Cookie name {prefix} requires {' and '.join(reqs)}; without them browsers may reject it or it is sent insecurely.")
        if SET_COOKIE_RE.search(line) and not SET_COOKIE_READ_RE.search(line):
            missing = [name for name, pat in (("HttpOnly", r"httponly"), ("Secure", r"secure"), ("SameSite", r"samesite"))
                       if not re.search(pat, line, re.I)]
            if missing:
                _priv_add(privacy, "cookie-flags", "low", "Set-Cookie missing " + "/".join(missing), r, i, line,
                          "Set-Cookie header without " + "/".join(missing)
                          + (" (readable by scripts)" if "HttpOnly" in missing else "")
                          + (" (sent in clear)" if "Secure" in missing else "")
                          + (" (sent cross-site)" if "SameSite" in missing else "") + ".")
        elif COOKIE_API_RE.search(line):
            window = " ".join(lines[max(0, i - 5):i + 10])
            if not COOKIE_FLAG_WORDS.search(window):
                var_arg = COOKIE_VAR_ARG_RE.search(line)
                _priv_add(privacy, "cookie-flags", "info" if var_arg else "low",
                          "set_cookie() flags not visible" if var_arg else "set_cookie() without flags", r, i, line,
                          "Cookie flag arguments are set on the cookie object, not visible here; verify them."
                          if var_arg else
                          "Framework cookie setter without HttpOnly/Secure/SameSite: readable by scripts, sent in clear or cross-site.")
        if (SET_COOKIE_RE.search(line) or COOKIE_WRITE_RE.search(line) or COOKIE_API_RE.search(line)) \
                and not SET_COOKIE_READ_RE.search(line):
            maxage = COOKIE_MAXAGE_RE.search(line)
            expires_m = None if maxage else COOKIE_EXPIRES_RE.search(line)
            days_left = int(maxage.group(1)) // 86400 if maxage else (_expiry_days(expires_m.group(1)) if expires_m else None)
            if days_left is None:
                _priv_add(privacy, "cookie-lifetime", "info", "session cookie", r, i, line,
                          "Cookie without a usable Max-Age/Expires: session-scoped (better for privacy).")
            elif days_left == 0:
                _priv_add(privacy, "cookie-lifetime", "info", "cookie deletion (Max-Age=0)", r, i, line,
                          "Zero lifetime deletes the cookie; a common logout/cleanup pattern.")
            elif days_left > 365:
                _priv_add(privacy, "cookie-lifetime", "low", "cookie lifetime > 1 year", r, i, line,
                          f"Cookie lives {days_left} days: long-lived identifiers outlive their purpose; shorten where possible.")
            elif days_left >= 0:
                _priv_add(privacy, "cookie-lifetime", "info", "short-lived cookie", r, i, line,
                          f"Cookie expires in {days_left} days (under a year).")
            else:
                _priv_add(privacy, "cookie-lifetime", "info", "expired cookie", r, i, line,
                          f"Cookie Expires is {abs(days_left)} days in the past; browsers delete it.")
        if COOKIE_WRITE_RE.search(line) and not re.search(r"(?i)(;\s*secure|;\s*samesite)", line):
            _priv_add(privacy, "cookie-flags", "low", "document.cookie without Secure/SameSite", r, i, line,
                      "JavaScript cookie without Secure/SameSite: sent in clear or cross-site (HttpOnly cannot be set from JS).")
        m = CONSENT_RE.search(line)
        if m:
            _priv_add(privacy, "consent-manager", "info", m.group(1).lower(), r, i, line,
                      "A consent manager (CMP) is present, so tracking should be gated on consent; verify it covers every vendor found.")
        if IP_LOG_RE.search(line) and IP_LOG_SINK_RE.search(line):
            masked = re.search(r"(?i)(mask|anonymi[sz]|truncat|hash|redact|pseudonym)", " ".join(lines[i - 1:i + 2]))
            _priv_add(privacy, "ip-logging", "info" if masked else "low", "IP address in logs/data", r, i, line,
                      ("The IP is masked/hashed here, which is good." if masked else
                       "Request IP is logged or persisted: IPs are personal data in the EU/UK; consider truncating or hashing."))
        if web:
            for key, sev, rx, meaning in BROWSER_CAPABILITIES:
                if re.search(rx, line):
                    _priv_add(privacy, "browser-capability", sev, key, r, i, line, meaning)
        if ext in (".entitlements", ".plist") or p.name.endswith(".entitlements"):
            for m in re.finditer(r"<key>(com\.apple\.security\.[\w.-]+)</key>", line):
                ent = m.group(1)
                if ent in MACOS_ENTITLEMENTS:
                    sev, what = MACOS_ENTITLEMENTS[ent]
                    _priv_add(privacy, "macos-entitlement", sev, ent, r, i, line,
                              f"macOS app entitlement grants {what} ({ent}) without a per-use prompt.")
        if TRACKING_PARAM_RE.search(line):
            _priv_add(privacy, "tracking-params", "low", "utm/campaign parameters", r, i, line,
                      "URL carries campaign/tracking parameters (utm_*, fbclid, gclid, …): links leak referrer and campaign identity.")
        if not _is_comment(line):
            m = VENDOR_PII_SAFE_RE.search(line)
            if m:
                _priv_add(privacy, "vendor-pii", "info", m.group(0).split(":")[0].strip(), r, i, line,
                          "SDK is configured to minimise personal data in its telemetry (good).")
            m = VENDOR_PII_RE.search(line)
            if m:
                _priv_add(privacy, "vendor-pii", "low", m.group(0).split(":")[0].strip(), r, i, line,
                          "SDK configured to attach personal data (IP, user profiles) to its telemetry; check the vendor's defaults.")
        if not _is_comment(line):
            m = PII_URL_RE.search(line)
            if m:
                _priv_add(privacy, "pii-in-url", "low", m.group(1).lower(), r, i, line,
                          "Personal data in the URL query: it leaks via Referer, access logs, proxies and browser history.")
        m = CLIENT_ID_RE.search(line)
        if m and CLIENT_ID_CONTEXT_RE.search(line):
            _priv_add(privacy, "client-id", "low", m.group(0).lower(), r, i, line,
                      "Named persistent client identifier: links sessions or devices without relying on a login.")
        if REFERRER_UNSAFE_RE.search(line):
            _priv_add(privacy, "referrer-policy", "low", "unsafe-url", r, i, line,
                      "Referrer policy is unsafe-url: the full URL (including path and query) is sent to third parties anyway.")
        elif REFERRER_POLICY_RE.search(line):
            _priv_add(privacy, "referrer-policy", "info", "policy", r, i, line,
                      "Referrer policy present: third parties see a reduced URL instead of the full one.")
        if PERMISSIONS_POLICY_RE.search(line):
            _priv_add(privacy, "permissions-policy", "info", "policy", r, i, line,
                      "Permissions-Policy present: browser features can be denied to third parties/iframes.")
        if ext in (".html", ".htm", ".svelte", ".vue", ".jsx", ".tsx", ".astro"):
            for m in EMBED_RE.finditer(line):
                attrs = m.group(2)
                sm = SRC_ATTR_RE.search(attrs) or DATA_ATTR_RE.search(attrs)
                host = _host_of(sm.group(1)) if sm else None
                if not host or _endpoint_noise(host) or host in NON_NET_HOSTS or _is_own(host, own):
                    continue
                sandboxed = bool(SANDBOX_RE.search(attrs))
                credentialless = bool(CREDENTIALLESS_RE.search(attrs))
                safe = sandboxed or credentialless
                _priv_add(privacy, "third-party-embed", "info" if safe else "low", host, r, i, line,
                          f"Embeds content from {host}: it runs third-party code, sees your IP and can set its own cookies."
                          + (" Sandboxed, which limits what it can do." if sandboxed else "")
                          + (" Credentialless: its requests are sent without cookies." if credentialless else ""))
                risky = _iframe_allow_perms(attrs)
                if risky:
                    _priv_add(privacy, "iframe-allow", "medium", host, r, i, line,
                              f"iframe delegates {', '.join(risky)} to {host}: the embedded page can use that capability.")
            for m in SCRIPT_RE.finditer(line):
                host = _host_of(m.group(1))
                if host and not _endpoint_noise(host) and host not in NON_NET_HOSTS and not _is_own(host, own):
                    cdn = host in THIRD_PARTY_CDN
                    _priv_add(privacy, "third-party-script", "info" if cdn else "low", host, r, i, line,
                              f"Loads executable script from {host}: it runs with page privileges and can read cookies/DOM and beacon data.")
            for m in SRCSET_RE.finditer(line):
                for url in re.findall(r"(?:https?:)?//[^\s,]+", m.group(1)):
                    host = _host_of(url)
                    if host and not _endpoint_noise(host) and host not in NON_NET_HOSTS and not _is_own(host, own):
                        _priv_add(privacy, "third-party-media", "info" if host in THIRD_PARTY_CDN or _known_host(host) else "low",
                                  host, r, i, line,
                                  f"Responsive media from {host}: it sees your IP and the page URL.")
            for m in MEDIA_RE.finditer(line):
                host = _host_of(m.group(1))
                if host and not _endpoint_noise(host) and host not in NON_NET_HOSTS and not _is_own(host, own):
                    _priv_add(privacy, "third-party-media", "info" if host in THIRD_PARTY_CDN or _known_host(host) else "low",
                              host, r, i, line,
                              f"Media loaded from {host}: it sees your IP and the page URL, and may set/send cookies or beacons.")
            for m in POSTER_RE.finditer(line):
                host = _host_of(m.group(1))
                if host and not _endpoint_noise(host) and host not in NON_NET_HOSTS and not _is_own(host, own):
                    _priv_add(privacy, "third-party-media", "info" if host in THIRD_PARTY_CDN or _known_host(host) else "low",
                              host, r, i, line,
                              f"Video poster image loaded from {host}: it sees your IP and the page URL.")
            for m in LINK_TAG_RE.finditer(line):
                attrs = m.group(1)
                hm, rm_ = HREF_ATTR_RE.search(attrs), REL_ATTR_RE.search(attrs)
                if not hm or not rm_:
                    continue
                host = _host_of(hm.group(1))
                if not host or _endpoint_noise(host) or host in NON_NET_HOSTS or _is_own(host, own):
                    continue
                relv = rm_.group(1).lower()
                if "stylesheet" in relv:
                    _priv_add(privacy, "third-party-stylesheet", "info" if host in THIRD_PARTY_CDN else "low",
                              host, r, i, line,
                              f"Stylesheet loaded from {host}: it sees your IP/referrer and can pull fonts/images from its own servers.")
                elif "preload" in relv or "prefetch" in relv or "modulepreload" in relv:
                    asm = re.search(r"(?i)\bas\s*=\s*[\"']([^\"']+)", attrs)
                    asv = asm.group(1).lower() if asm else ""
                    if asv == "script":
                        _priv_add(privacy, "third-party-script", "info" if host in THIRD_PARTY_CDN else "low",
                                  host, r, i, line,
                                  f"Script preloaded from {host}: code fetched before it is needed.")
                    elif asv == "style":
                        _priv_add(privacy, "third-party-stylesheet", "info" if host in THIRD_PARTY_CDN else "low",
                                  host, r, i, line,
                                  f"Stylesheet preloaded from {host}: fetched before it is needed.")
                    else:
                        _priv_add(privacy, "third-party-preload", "info" if host in THIRD_PARTY_CDN else "low",
                                  host, r, i, line,
                                  f"Resource preloaded/prefetched from {host}: fetched before it is needed, revealing your IP early.")
                elif "preconnect" in relv or "dns-prefetch" in relv:
                    _priv_add(privacy, "third-party-preconnect", "info" if host in THIRD_PARTY_CDN else "low", host, r, i, line,
                              f"Preconnect/DNS-prefetch to {host}: the browser opens a connection (IP, TLS) before any consent or request.")
            for m in FORM_RE.finditer(line):
                host = _host_of(m.group(1))
                if host and not _endpoint_noise(host) and host not in NON_NET_HOSTS and not _is_own(host, own):
                    _priv_add(privacy, "third-party-form", "low", host, r, i, line,
                              f"Form action posts user data to {host}; verify what it collects and its policy.")
        if ext in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte", ".astro", ".html", ".htm"):
            for m in JS_IMPORT_URL_RE.finditer(line):
                host = _host_of(m.group(1))
                if host and not _endpoint_noise(host) and host not in NON_NET_HOSTS and not _is_own(host, own):
                    _priv_add(privacy, "third-party-script", "info" if host in THIRD_PARTY_CDN else "low",
                              host, r, i, line,
                              f"Module import from {host}: code fetched and executed from a third-party server.")
        if ext in (".css", ".scss", ".sass", ".less"):
            for m in CSS_IMPORT_RE.finditer(line):
                host = _host_of(m.group(1))
                if host and not _endpoint_noise(host) and host not in NON_NET_HOSTS and not _is_own(host, own):
                    _priv_add(privacy, "third-party-stylesheet", "info" if host in THIRD_PARTY_CDN else "low",
                              host, r, i, line,
                              f"CSS @import from {host}: sees your IP/referrer and can chain further requests.")
        if p.name == "AndroidManifest.xml":
            for m in re.finditer(r'<uses-feature[^>]*android:name="(android\.hardware\.[A-Za-z0-9_.]+)"', line):
                feat = m.group(1)
                _priv_add(privacy, "android-feature", "info", feat, r, i, line,
                          f"Manifest declares hardware feature {feat}: the app is expected to use that sensor/capability.")
            if re.search(r'android:usesCleartextTraffic\s*=\s*"true"', line):
                _priv_add(privacy, "android-cleartext", "medium", "usesCleartextTraffic", r, i, line,
                          "App allows plaintext HTTP: requests and metadata can be read or modified on the way.")
            for m in re.finditer(r'<uses-permission(?:-sdk-23)?[^>]*android:name="android\.permission\.([A-Z_0-9]+)"', line):
                perm = m.group(1)
                if perm in ANDROID_IGNORE:
                    continue
                sev, what = ANDROID_PERMS.get(perm, ("low", perm.replace("_", " ").lower()))
                max_sdk = re.search(r'android:maxSdkVersion\s*=\s*"(\d+)"', line)
                sdk_note = ""
                if max_sdk:
                    down = {"high": "medium", "medium": "low", "low": "info"}
                    sev = down[sev] if sev in down else sev
                    sdk_note = f" Only applies up to API {max_sdk.group(1)} (newer Android does not request it)."
                _priv_add(privacy, "android-permission", sev, perm, r, i, line,
                          f"Android app requests {what} ({perm}); the user must grant it and the app can read it.{sdk_note}")
    if manifest:
        groups = {"permissions": "permission", "optional_permissions": "permission",
                  "host_permissions": "host access", "optional_host_permissions": "optional host access"}
        for field, label in groups.items():
            vals = manifest.get(field) or []
            if not isinstance(vals, list):
                continue
            for v in vals:
                if not isinstance(v, str):
                    continue
                broad = v in ("<all_urls>", "*://*/*") or re.match(r"^[a-z*]+://\*/", v) is not None
                benign = v in EXT_INFO
                sev = "info" if benign else ("high" if broad else ("medium" if v in EXT_HIGH else "low"))
                _priv_add(privacy, "extension-permission", sev, v, r, _line_of(text, f'"{v}"'), f'"{v}" ({label})',
                          f"Browser extension requests '{v}': "
                          + ("benign capability (no page/user data)." if benign else
                             "reads every page you visit." if broad else "access to this browser capability."))
        for cs in manifest.get("content_scripts") or []:
            for v in (cs.get("matches") or []) if isinstance(cs, dict) else []:
                if v in ("<all_urls>", "*://*/*"):
                    _priv_add(privacy, "extension-permission", "high", "content_scripts:<all_urls>", r, _line_of(text, v), v,
                              "Content script runs on every page; it can read page content and inject into it.")
        ec = (manifest.get("externally_connectable") or {}).get("matches") or []
        if ec:
            broad = any(v in ("<all_urls>", "*://*/*") for v in ec)
            _priv_add(privacy, "extension-connectable", "low" if broad else "info",
                      "externally_connectable" + (":<all_urls>" if broad else ""), r,
                      _line_of(text, "externally_connectable"), f"matches {ec}",
                      "Websites may send messages to the extension: any site can talk to it (fingerprinting vector)."
                      if broad else "Only listed sites may message the extension.")
        for war in manifest.get("web_accessible_resources") or []:
            matches = (war.get("matches") if isinstance(war, dict) else None) or []
            res = (war.get("resources") if isinstance(war, dict) else None) or []
            broad = any(v in ("<all_urls>", "*://*/*") for v in matches)
            _priv_add(privacy, "extension-resource", "low" if broad else "info",
                      "web_accessible_resources" + (":<all_urls>" if broad else ""), r,
                      _line_of(text, "web_accessible_resources"), f"{len(res)} resource(s), matches {matches}",
                      "Extension files exposed to web pages: any site can load them and detect the extension (fingerprinting vector)."
                      if broad else "Extension files exposed to specific sites; low risk.")
        gecko = ((manifest.get("browser_specific_settings") or {}).get("gecko") or {})
        dcp = gecko.get("data_collection_permissions")
        if dcp:
            _priv_add(privacy, "store-disclosure", "info", "data_collection_permissions", r,
                      _line_of(text, "data_collection_permissions"), json.dumps(dcp)[:140],
                      "Machine-readable data-collection declaration in the extension manifest.")
        else:
            _priv_add(privacy, "store-disclosure", "info", "store-only disclosures", r, _line_of(text, '"permissions"'),
                      "manifest.json without data_collection_permissions", 
                      "No machine-readable data-collection declaration; Chrome Web Store data disclosures live outside the repo.")


FINGERPRINT_RULES = [
    ("fingerprintjs", "high", r"@?fingerprintjs|clientjs|\bbotd\b|@sparticuz/", "Dedicated fingerprinting library: builds a stable ID from device attributes."),
    ("canvas", "medium", r"toDataURL|getImageData|canvas\.getContext\(|textBaseline|WEBGL_debug_renderer_info", "Canvas/WebGL rendering: tiny rendering differences identify GPU, drivers and fonts."),
    ("webgl", "medium", r"WEBGL_debug_renderer_info|getSupportedExtensions\(|getParameter\(gl\.", "WebGL renderer/extension probing: GPU and driver fingerprint."),
    ("audio", "medium", r"AudioContext|OfflineAudioContext|OscillatorNode|AudioBuffer", "Audio stack fingerprint: sample-rate/oscillator quirks are device-specific."),
    ("fonts", "medium", r"measureText|document\.fonts|FontFace\(|font-family.*local\(", "Font metrics/measuring: installed-font sets are device-specific."),
    ("screen", "low", r"screen\.(width|height|colorDepth|pixelDepth)|devicePixelRatio|screen\.avail", "Screen geometry/color depth: display fingerprint."),
    ("user-agent", "low", r"navigator\.userAgent|navigator\.platform|navigator\.hardwareConcurrency|navigator\.deviceMemory|navigator\.plugins|navigator\.languages|navigator\.maxTouchPoints", "Browser/device capabilities: UA, cores, memory, plugins, languages, touch points."),
    ("timezone", "low", r"resolvedOptions\(\)\.timeZone|Intl\.DateTimeFormat\(\s*\)|toLocale(?:String|DateString|TimeString)\(\s*\)", "Timezone/locale: narrows down the user's location and language."),
    ("webrtc", "medium", r"RTCPeerConnection|createDataChannel\s*\(", "WebRTC peers see your public IP and can probe NAT/firewall; connections may be made before consent."),
    ("battery/network", "low", r"navigator\.getBattery|navigator\.connection\b", "Battery/network state narrows the device and can be sampled repeatedly."),
]


FINGERPRINT_MEANING = "Device-fingerprinting signal: combine several and a browser can be recognized without cookies."


IDENTIFY_RE = re.compile(r"(?i)\.(identify|setUser(?:Id|Email|Properties)?|set_user(?:_id|_email|_properties)?|alias)\s*\("
                        r"|\b(Sentry\.setUser|sentry_sdk\.set_user)\b")


MASK_KEYS_RE = re.compile(r"(?i)\b(maskAllInputs|mask_all_inputs|maskInputOptions|maskInputs|maskTextSelector|"
                          r"mask_text_selector|maskAllText|maskTextFn|unmaskAllInputs|mask_?pii|"
                          r"data-hj-suppress|data-clarity-mask|maskTextClass)\b")


PII_LOG_RE = re.compile(r"(?i)(console\.(log|info|warn|error|debug|trace|table|dir)|log(ger)?\.(info|warn|error|debug|exception|critical)|"
                        r"\bprint(?:f)?\b|\bputs\b|fmt\.Print|tracing::(info|warn|error|debug)|log\.\w+|"
                        r"println!|eprintln!|log::(?:info|warn|error|debug)|System\.out\.print|Log\.[dviwe]\s*\(|"
                        r"error_log|print_r|var_dump|\bdd\(|logger\.Log|slog\.\w+|zap\.(?:info|warn|error|debug))")


PII_WORD_RE = re.compile(r"(?i)\b(e-?mail|phone|mobile|mobile_?number|phone_?number|ssn|social security|address|street|zip|zip_?code|postal|"
                         r"username|user_?name|nickname|passport|iban|"
                         r"credit ?card|card_?number|dob|birthday|birth_?date|full_?name|first_?name|last_?name|"
                         r"ip_?address|remote_addr|user_?agent|geo|latitude|longitude)"
                         r"\b")


EMAIL_RE = re.compile(r"[\w.+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+", re.I)


EMAIL_IGNORE = {"git@github.com", "noreply@github.com", "actions@github.com"}


EMAIL_IGNORE_RE = re.compile(r"(?i)@users\.noreply\.github\.com$")


PHONE_RE = re.compile(r"(?<![A-Za-z0-9+])\+\d[\d ().-]{6,14}\d")


PHONE_CONTEXT_RE = re.compile(r"(?i)(?:phone|telephone|mobile|cell|fax)\b|(?<![a-z])tel\b")


PHONE_LOCAL_RE = re.compile(
    r"(?<!\d)(?:"
    r"(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-.]\d{4}"      # US/CA
    r"|0\d{2,3}[ -]?\d{3,4}[ -]?\d{3,4}"                     # UK
    r"|0[45]\d{2}[ -]?\d{3}[ -]?\d{3}"                       # AU mobile
    r"|\(0[2-8]\)[ -]?\d{4}[ -]?\d{4}"                       # AU landline
    r")(?!\d)")


IMPORT_NET_PY = re.compile(r"\b(requests|httpx|urllib3)\.\w+\s*\(|"
                            r"\baiohttp\.(?!ClientTimeout|ClientSession|TCPConnector|FormData)\w+\s*\(|"
                            r"\burlopen\s*\(|socket\.socket\s*\(|\bhttp\.client\.")


IMPORT_NET_JS = re.compile(r"(\bfetch\s*\(|\baxios[.(]|\$\.ajax\s*\(|navigator\.geolocation)")


IP_LOG_RE = re.compile(r"(?i)(req\.ip\b|request\.remote_addr|remote_addr|REMOTE_ADDR|RemoteAddr|X-Forwarded-For|"
                       r"X-Client-IP|CF-Pseudo-IPv4|Fastly-Client-IP|X-Cluster-Client-IP|"
                       r"HTTP_X_FORWARDED_FOR|X_FORWARDED_FOR|X-Real-IP|True-Client-IP|CF-Connecting-IP|client_ip|remoteAddress|\bip_address\b)")


IP_LOG_SINK_RE = re.compile(r"(?i)(log|logger|print|puts|console|info|warn|debug|write|store|save|insert|persist|db|audit)")


PII_URL_RE = re.compile(r"(?i)[?&](e?-?mail(?:_?address)?|phone(?:_?number)?|mobile(?:_?number)?|tel|name|"
                         r"first_?name|last_?name|full_?name|username|user_?name|user_?id|account(?:_?id)?|address|"
                         r"street|zip|zip_?code|postal|ssn|dob|birthdate|birthday|gender)=")


TRACKING_PARAM_RE = re.compile(r"[?&](utm_[a-z_]+|gclid|dclid|gbraid|wbraid|fbclid|msclkid|twclid|ttclid|yclid|"
                               r"li_fat_id|s_kwcid|epik|rb_clickid|wickedid|sc_cid|irclickid|mc_cid|mc_eid|"
                               r"mkt_tok|vero_id|oly_enc_id|_hsenc|_hsmi|srsltid|igshid|si|_ga|_gl|gclsrc|dclsrc|gad_source|gad_campaignid)=")


PRIVACY_DOC_NAMES = {"privacy.md", "privacy.txt", "privacy.rst", "privacy.markdown", "privacy-policy.md",
                      "privacy_policy.md", "privacy_policy.txt", "privacyinfo.xcprivacy"}


PRIVACY_DOC_RE = re.compile(r"(?i)(^|/)(privacy|privacy[-_.]?policy)(\.(md|markdown|txt|rst|html|adoc))?$|\.xcprivacy$")


PRIVACY_LINK_RE = re.compile(r"(?i)\[(?:privacy|data[- ]protection)[^\]]*\]\((https?://[^)\s]+)\)|"
                             r"(https?://[^\s)\"']*(?:privacy|data[-_]protection)[^\s)\"']*)")


PURPOSE_STR_RE = re.compile(r"<key>(NS[A-Za-z]+?(?:UsageDescription|AlwaysUsageDescription|WhenInUseUsageDescription))</key>\s*<string>(.*?)</string>", re.S)


PROTO_REL_RE = re.compile(r"(?<![:/\w])//([a-z0-9][a-z0-9.-]*[a-z0-9])/")


COOKIE_API_RE = re.compile(r"(?i)(\bset_cookie\s*\(|\bres\.cookie\s*\(|\bsetcookie\s*\(|\bsetCookie\s*\()")


COOKIE_VAR_ARG_RE = re.compile(r"(?i)set_?cookie\s*\([^)]*,\s*[A-Za-z_]\w*\s*\)")


COOKIE_FLAG_WORDS = re.compile(r"(?i)(httponly|secure|samesite|same_site|samesite_)")


MACOS_ENTITLEMENTS = {
    "com.apple.security.personal-information.location": ("high", "location"),
    "com.apple.security.personal-information.calendars": ("medium", "calendars"),
    "com.apple.security.personal-information.contacts": ("medium", "contacts"),
    "com.apple.security.personal-information.photos-library": ("high", "photo library"),
    "com.apple.security.device.camera": ("high", "camera"),
    "com.apple.security.device.microphone": ("high", "microphone"),
    "com.apple.security.device.bluetooth": ("medium", "Bluetooth devices"),
    "com.apple.security.device.usb": ("low", "USB devices"),
    "com.apple.security.network.client": ("info", "outgoing network"),
    "com.apple.security.network.server": ("info", "incoming network"),
    "com.apple.security.files.user-selected.read-write": ("low", "user-selected files"),
    "com.apple.security.files.user-selected.read-only": ("low", "user-selected files (read-only)"),
    "com.apple.security.files.downloads.read-only": ("low", "Downloads folder (read-only)"),
    "com.apple.security.files.desktop.read-write": ("low", "Desktop folder"),
    "com.apple.security.files.desktop.read-only": ("low", "Desktop folder (read-only)"),
    "com.apple.security.files.documents.read-write": ("medium", "Documents folder"),
    "com.apple.security.files.documents.read-only": ("low", "Documents folder (read-only)"),
    "com.apple.security.files.downloads.read-write": ("low", "Downloads folder"),
    "com.apple.security.files.all": ("medium", "all files"),
    "com.apple.security.automation.apple-events": ("medium", "Apple Events automation"),
    "com.apple.security.cs.disable-library-validation": ("low", "library validation disabled"),
}


BROWSER_CAPABILITIES = [
    ("clipboard", "medium", r"navigator\.clipboard\.(read|readText)|clipboard\.read\b",
     "Reads the system clipboard: whatever the user copied, including passwords."),
    ("geolocation", "medium", r"navigator\.geolocation|getCurrentPosition\s*\(|watchPosition\s*\(",
     "Asks for precise device location."),
    ("camera/microphone", "medium", r"getUserMedia\s*\(|MediaDevices|enumerateDevices\s*\(",
     "Opens camera/microphone or enumerates local media devices."),
    ("screen capture", "medium", r"getDisplayMedia\s*\(|MediaRecorder\s*\(",
     "Records or streams screen/window content."),
    ("notifications", "low", r"Notification\.requestPermission|new Notification\s*\(",
     "Asks to send notifications (can be used to re-engage the user)."),
    ("browsing history", "low", r"history\.(pushState|replaceState|length)",
     "Reads or influences browser history (length / pushState / replaceState)."),
    ("usb/serial/bluetooth", "low", r"navigator\.(usb|serial|bluetooth)\b|BluetoothDevice",
     "Talks to local devices over USB/serial/Bluetooth."),
    ("storage access", "low", r"document\.hasStorageAccess|requestStorageAccess\s*\(",
     "Cross-site cookie/storage access."),
    ("file picking", "low", r"showOpenFilePicker|showSaveFilePicker|showDirectoryPicker",
     "Asks the user for local files/directories (chosen files are read by the page)."),
    ("payment", "medium", r"\bPaymentRequest\b|ApplePaySession|requestPayment\s*\(",
     "Reads payment details/instrument data from the browser's autofill."),
    ("service worker", "low", r"navigator\.serviceWorker|serviceWorker\.register\s*\(",
     "Registers a service worker that persists and can intercept requests."),
    ("share sheet", "low", r"navigator\.share\s*\(",
     "Hands content to another app chosen by the user."),
]


CLIENT_ID_RE = re.compile(r"(?i)\b(client_?id|device_?id|visitor_?id|anonymous_?id|distinct_?id|installation_?id)\b")


CLIENT_ID_CONTEXT_RE = re.compile(r"(?i)(localStorage|sessionStorage|document\.cookie|cookie|uuid|randomUUID|nanoid|v4\s*\(|guid)")


ADDRESS_RE = re.compile(r"(?<!\w)\d{1,6}[A-Za-z]?\s+[A-Z][\w.'-]*(?:\s+[A-Z][\w.'-]*){0,4}\s+"
                        r"(?i:street|st|road|rd|avenue|ave|boulevard|blvd|lane|ln|drive|dr|way|court|ct|place|pl|square|sq)\b")


ADDRESS_INTL_RE = re.compile(r"(?<![\w.-])(?:"
                             r"[A-Z][\w.'-]*(?i:stra(?:ß|ss)e|str\.|weg|platz|gasse|allee|laan)\s+\d{1,5}[a-z]?|"
                             r"(?:Rue|Via|Calle|Avenida|Rua|Ulica)\s+[A-Z][\w.'-]*(?:\s+[A-Z][\w.'-]*){0,3}\s+\d{1,5}|"
                             r"P\.?\s?O\.?\s?Box\s+\d{1,8})(?![\w])")


RETENTION_RE = re.compile(r"(?i)\b(data[_-]?retention|retention[_-]?(?:days|period|policy)?|log[_-]?retention|retain(?:ed)?|"
                           r"ttl[_-]?(?:seconds|secs|days)?|expir(?:y|es|ation)|purge[_-]?after|delete[_-]?after)\b"
                           r"\s*[:=]?\s*\d")


UPLOAD_SINK_RE = re.compile(r"(?i)(multipart/form-data|UploadFile|FileUpload|MultipartFile|req\.files\b|request\.FILES|multer|"
                            r"formidable|busboy|\bupload\b|files\[\])")


UPLOAD_LIMIT_RE = re.compile(r"(?i)(max[_-]?(?:file|upload|content|body)[_-]?(?:size|length)?|client_max_body_size|"
                             r"MAX_CONTENT_LENGTH|limits?\s*[:=]|fileSizeLimit|maxBytes|sizeLimit|body[_-]?limit|"
                             r"LimitRequestBody)")


IOS_DATA_TYPE_RE = re.compile(r"NSPrivacyCollectedDataType([A-Z][A-Za-z]+)")


IOS_DATA_TYPE_NAMES = {
    "Name": "name", "EmailAddress": "email", "PhoneNumber": "phone number", "PhysicalAddress": "postal address",
    "Health": "health data", "PaymentInfo": "payment info", "CreditInfo": "credit info", "PreciseLocation": "precise location",
    "CoarseLocation": "coarse location", "SensitiveInfo": "sensitive info", "Contacts": "contacts", "Photos": "photos",
    "AudioData": "audio", "Messages": "messages", "SearchHistory": "search history", "BrowsingHistory": "browsing history",
    "DeviceID": "device ID", "UserID": "user ID", "PurchaseHistory": "purchase history", "ProductInteraction": "product interaction",
    "AdvertisingData": "advertising data", "OtherUsageData": "usage data", "CrashData": "crash data",
    "PerformanceData": "performance data", "OtherDiagnosticData": "diagnostic data", "Fitness": "fitness",
    "GameplayContent": "gameplay content", "CustomerSupport": "customer support", "FitnessData": "fitness data",
}


TRACKER_INIT_RE = re.compile(r"(?i)(\bgtag\s*\(|\bfbq\s*\(|posthog\.init|\b_paq\.|\bym\s*\(|mixpanel\.init|"
                            r"amplitude\.getInstance|hotjar\.|\bclarity\s*\(|Sentry\.init|datadogRum\.init)")


CMP_LOAD_RE = CONSENT_RE


def _in_url_authority(line, pos):
    """True when pos falls inside scheme://userinfo@host (so it is not an email)."""
    scheme = line.rfind("://", 0, pos)
    return scheme >= 0 and "/" not in line[scheme + 3:pos]


PII_OBJECT_RE = re.compile(r"(?i)\b(user|users|account|customer|profile|session|member|subscriber|person|lead|contact|"
                           r"request|response|body|payload|form|form_?data|req)\b(?=\.\w|[([{,:_\-})])")


CONSENT_MODE_RE = re.compile(r"(?i)(\b(?:analytics|ad|functionality|personalization)_storage\b|consent_?mode|ad_user_data|ad_personalization)")


CONSENT_STATE_RE = re.compile(r"(?i)(?<![\w.-])(OptanonConsent|OptanonAlertBoxClosed|CookieConsentV2|CookieConsent|"
                               r"cookieyes-consent|cc_cookie|borlabs-cookie|euconsent-v2|didomi_token|usprivacy|"
                               r"__cmpconsent|_iub_cs[\w-]*)(?=[=;'\"\s,)]|$)")


TRACKING_COOKIE_RE = re.compile(r"(?i)(?<![\w.])(_ga_[A-Z0-9]+|_gac_[A-Za-z0-9]+|_ga|_gid|_gat|_gcl_au|_gcl_aw|"
                                r"_fbp|_fbc|_hj\w*|ajs_\w*(?==)|__utm[a-z]|__hstc|__hssc|__hssrc|hubspotutk|intercom-[\w-]+|mp_\w+(?==)|"
                                r"amplitude_id\w*|ph_\w+(?==)|_clck|_clsk|_uetvid|_uetsid|_ttp|_rdt_uuid|li_sugr|"
                                r"bcookie|lidc|_pin_unauth|_epik|_scid|\bfr(?==)|personalization_id|guest_id|__gads|__gpi|_tt_enable_cookie|IDE|NID)(?=[=;'\"\s,)]|$)")


VENDOR_PII_RE = re.compile(r"(?i)(send_?default_?pii\s*[:=]\s*true|person_?profiles\s*[:=]\s*[\"']always[\"']|"
                            r"anonymize_?ip\s*[:=]\s*false|store_?ip\s*[:=]\s*true|track_?ip\s*[:=]\s*true)")


VENDOR_PII_SAFE_RE = re.compile(r"(?i)(send_?default_?pii\s*[:=]\s*false|person_?profiles\s*[:=]\s*[\"'](?:never|identified_only)[\"']|"
                                r"anonymize_?ip\s*[:=]\s*true|store_?ip\s*[:=]\s*false|track_?ip\s*[:=]\s*false)")


ZIP_CONTEXT_RE = re.compile(r"(?i)\b(zip|zip[_-]?code|postal|postcode|postleitzahl|plz)\b")


ZIP_RE = re.compile(r"\b(\d{5}(?:-\d{4})?|[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2})\b")


PII_ROLE_RE = re.compile(r"(?i)^(no-?_?reply|do-?not-?reply|bounce|notifications?|news|events|hr|recruiting|partners|support|info|hello|hi|hey|team|security|admin|contact|"
                         r"sales|press|jobs|careers|billing|legal|privacy|dpo|abuse|postmaster|webmaster|mail|"
                         r"office|help|feedback|newsletter|marketing|dev|developers)([+._-].*)?$")


TRACKING_COOKIE_VENDORS = [
    ("_ga_", "Google Analytics"), ("_gac_", "Google Ads"), ("_ga", "Google Analytics"),
    ("_gid", "Google Analytics"), ("_gat", "Google Analytics"),
    ("_gcl_au", "Google Ads"), ("_gcl_aw", "Google Ads"), ("IDE", "Google DoubleClick"), ("NID", "Google"),
    ("_fbp", "Meta Pixel"), ("_fbc", "Meta Pixel"), ("_hjid", "Hotjar"), ("_hjsession", "Hotjar"),
    ("ajs_", "Segment"), ("__hstc", "HubSpot"), ("hubspotutk", "HubSpot"), ("intercom-", "Intercom"),
    ("mp_", "Mixpanel"), ("amplitude_id", "Amplitude"), ("ph_", "PostHog"), ("_clck", "Microsoft Clarity"),
    ("_clsk", "Microsoft Clarity"), ("_uetvid", "Microsoft Ads"), ("_uetsid", "Microsoft Ads"), ("_ttp", "TikTok"),
    ("__utm", "Google Analytics (legacy)"), ("_hj", "Hotjar"),
    ("_rdt_uuid", "Reddit"), ("li_sugr", "LinkedIn"), ("bcookie", "LinkedIn"), ("lidc", "LinkedIn"),
    ("_pin_unauth", "Pinterest"), ("_epik", "Pinterest"), ("__hssc", "HubSpot"), ("__hssrc", "HubSpot"),
    ("_scid", "Snapchat"), ("fr", "Meta Pixel"), ("personalization_id", "X/Twitter"),
    ("guest_id", "X/Twitter"), ("__gads", "Google Ads"), ("__gpi", "Google Ads"),
    ("_tt_enable_cookie", "TikTok"),
]


SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


TEL_LINK_RE = re.compile(r"(?i)href\s*=\s*[\"'](tel|sms):([+0-9 ().-]+)")


MAILTO_RE = re.compile(r"(?i)href\s*=\s*[\"']mailto:([^\"?\s]+)")


CARD_RE = re.compile(r"(?<![\d.])(?:\d{13,19}|\d{4}(?:[ ]\d{4}){3}|\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}|\d{4}[ -]\d{6}[ -]\d{5})(?![\d.])")


HASHY_RE = re.compile(r"(?i)(sha\d*|md5|hash|uuid|commit|0x[0-9a-f]+)")


PII_SKIP_EXT = {".svg", ".sfd", ".glif", ".css", ".scss", ".map", ".lock", ".woff", ".woff2"}


def _luhn_ok(s):
    ds = [int(c) for c in s if c.isdigit()]
    if not 13 <= len(ds) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(ds)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


CARD_IIN_RE = re.compile(r"^(4|5[1-5]|2[2-7]|3[0-9]|6[0245]|62)")


def _card_number_ok(s):
    """Luhn plus an issued card IIN prefix/length: excludes timestamps, IDs and arbitrary digit runs."""
    ds = re.sub(r"\D", "", s)
    n = len(ds)
    if n == 15:                       # Amex
        return ds[:2] in ("34", "37") and _luhn_ok(ds)
    if n == 14:                       # Diners
        return ds[:2] in ("30", "36", "38", "39") and _luhn_ok(ds)
    if n not in (13, 16, 19):
        return False
    return bool(CARD_IIN_RE.match(ds)) and _luhn_ok(ds)


def _tracking_cookie_vendor(name):
    lname = name.lower()
    for prefix, vendor in TRACKING_COOKIE_VENDORS:
        if lname.startswith(prefix.lower()):
            return vendor
    return None


def check_privacy_signals(root, p, text, privacy, masks):
    """Fingerprinting, PII in logs/source, import-time network, IP logging, tracking params. Static only."""
    r, ext = rel(root, p), p.suffix.lower()
    if LOCKFILE_RE.search(r):
        return
    if (ext in PROSE_EXT or ext == ".po" or AUTHORS_FILE_RE.search(r) or LICENSE_FILE_RE.search(r)
            or TEST_PATH.search(r) or (ext == ".txt" and re.search(r"(?i)(^|/)docs?/", r))):
        # docs/contributors/licences/tests: contacts and links, not runtime traffic
        docs_emails = set()
        docs_addresses = set()
        for i, line in enumerate(text.split("\n"), 1):
            if TRACKING_PARAM_RE.search(line):
                _priv_add(privacy, "tracking-params", "info", "utm/campaign parameters", r, i, line,
                          "Link carries campaign/tracking parameters (utm_*, fbclid, gclid, …).")
            m = PII_URL_RE.search(line)
            if m:
                _priv_add(privacy, "pii-in-url", "info", m.group(1).lower() + " (docs link)", r, i, line,
                          "Example link puts personal data in the URL query: fine in docs, leaks via Referer/logs when used at runtime.")
            for m in EMAIL_RE.finditer(line):
                addr = m.group(0)
                if (m.start() and line[m.start() - 1] in "/:") or _in_url_authority(line, m.start()):
                    continue          # srcset densities and URL userinfo such as user:pass@host
                if not addr.split("@", 1)[0].strip(".-"):
                    continue          # Ruby ranges/instance vars: (..@notifications.first.id)
                if m.start() and line[m.start() - 1] == "@":
                    continue          # fediverse handle @user@instance, not an email
                if addr.lower() in EMAIL_IGNORE or EMAIL_IGNORE_RE.search(addr):
                    continue
                domain = addr.rsplit("@", 1)[-1]
                if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", domain):
                    continue
                if re.search(r"(?i)\.(png|jpe?g|gif|svg|webp|pdf|ico|icns)$", domain):
                    continue          # Xcode asset names like "Icon@2x.png", not emails
                if addr.lower().endswith((".example", ".invalid", ".local")):
                    continue
                if line[max(0, m.start() - 7):m.start()].lower() == "mailto:":
                    continue          # already reported as a mailto: link
                docs_emails.add(addr.lower())
            m = PHONE_RE.search(line)
            if m:
                _priv_add(privacy, "pii-phone", "info", "docs:" + m.group(0).strip(), r, i, line,
                          "Docs publish a phone number (contact info by design).")
            m = ADDRESS_RE.search(line) or ADDRESS_INTL_RE.search(line)
            if m:
                docs_addresses.add(m.group(0).strip())
        if docs_addresses:
            shown = "; ".join(sorted(docs_addresses)[:3])
            _priv_add(privacy, "pii-address", "info", f"docs: {len(docs_addresses)} address(es) in {r}", r, 1, shown,
                      "Docs publish these postal addresses (contact info); confirm they are meant to be public.")
        if docs_emails:
            shown = ", ".join(sorted(docs_emails)[:4]) + (f", +{len(docs_emails) - 4}" if len(docs_emails) > 4 else "")
            _priv_add(privacy, "pii-email", "info", f"docs: {len(docs_emails)} address(es) in {r}", r, 1, shown,
                      "Docs publish these email addresses (contact/maintainer info); confirm they are meant to be public.")
        return
    is_js = ext in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".html", ".htm", ".vue", ".svelte", ".astro")
    lines = text.split("\n")
    tracker_at = cmp_at = storage_at = None
    for i, line in enumerate(lines, 1):
        if len(line) > 2000:
            continue
        comment = _is_comment(line)
        if is_js and not comment:
            for key, sev, rx, meaning in FINGERPRINT_RULES:
                if re.search(rx, line):
                    _priv_add(privacy, "fingerprint", sev, key, r, i, line, FINGERPRINT_MEANING)
            m = CONSENT_MODE_RE.search(line)
            if m:
                _priv_add(privacy, "consent-mode", "info", m.group(1).lower(), r, i, line,
                          "Google Consent Mode signals: analytics/ad storage can be denied until the user consents.")
            if TRACKER_INIT_RE.search(line) and tracker_at is None:
                tracker_at = i
            if CMP_LOAD_RE.search(line) and cmp_at is None:
                cmp_at = i
            if (COOKIE_WRITE_RE.search(line) or STORAGE_RE.search(line)) and storage_at is None:
                storage_at = i
        if not comment and PII_LOG_RE.search(line):
            masked = re.search(r"(?i)(redact|mask|scrub|hash|anonymi[sz]|truncat|partial)", line)
            if PII_WORD_RE.search(line):
                _priv_add(privacy, "pii-log", "info" if masked else "low", "log line with PII", r, i, line,
                          ("The log line already masks/redacts the value." if masked else
                           "A log/print statement names personal data: it can end up in log files, log shippers and crash reports."))
            elif PII_OBJECT_RE.search(line):
                _priv_add(privacy, "pii-log", "info" if masked else "low", "logged object likely containing PII", r, i, line,
                          ("The logged object is already masked/redacted." if masked else
                           "The logged argument name suggests personal data (user/account/profile/…); verify the destination and retention."))
        if not comment:
            mk = MASK_KEYS_RE.search(line)
            if mk:
                masks.add(mk.group(1))
            for m in IDENTIFY_RE.finditer(line):
                name = m.group(1) or m.group(2).split(".")[-1]
                _priv_add(privacy, "telemetry-identify", "low", name, r, i, line,
                          f"Call to {name}() sends a user identifier/attributes to the analytics or crash SDK; "
                          "check what the payload includes and whether the user can opt out.")
        if not comment and not re.match(r"\s*\(", line):
            for m in TRACKING_COOKIE_RE.finditer(line):
                name = m.group(1)
                if name.upper() in ("IDE", "NID") and not re.search(r"(?i)cookie", line):
                    continue      # IDE/NID are words on their own; require cookie context
                vendor = _tracking_cookie_vendor(name)
                if vendor:
                    _priv_add(privacy, "tracking-cookie", "low", vendor, r, i, line,
                              f"Cookie '{name}' belongs to {vendor}: it persists an identifier on the device.")
            m = CONSENT_STATE_RE.search(line)
            if m:
                vendor = {"optanonconsent": "OneTrust", "optanonalertboxclosed": "OneTrust",
                          "cookieyes-consent": "CookieYes", "cc_cookie": "CookieConsent",
                          "euconsent-v2": "IAB TCF", "didomi_token": "Didomi",
                          "borlabs-cookie": "Borlabs", "usprivacy": "IAB US Privacy",
                          "__cmpconsent": "IAB TCF", "_iub_cs": "Iubenda"}.get(
                              m.group(1).lower() if not m.group(1).lower().startswith("_iub_cs") else "_iub_cs")
                key = f"{m.group(1)} ({vendor})" if vendor else m.group(1)
                _priv_add(privacy, "consent-state", "info", key, r, i, line,
                          "Consent state is stored client-side in this cookie: changing it controls the CMP.")
            m = SSN_RE.search(line)
            if m and ext not in PII_SKIP_EXT:
                _priv_add(privacy, "pii-ssn", "low", m.group(0), r, i, line,
                          "US Social Security number in source/config (personal data).")
            if not HASHY_RE.search(line) and ext not in PII_SKIP_EXT:
                for m in CARD_RE.finditer(line):
                    if _card_number_ok(m.group(0)):
                        _priv_add(privacy, "pii-card", "low", m.group(0).strip(), r, i, line,
                                  "Payment card number that passes the Luhn check: personal data in source/config.")
                        break
            version_string = bool(PACKAGE_MANAGER_RE.search(line))   # "yarn@4.18.1" is a version, not an email
            for m in EMAIL_RE.finditer(line):
                if version_string:
                    break
                addr = m.group(0)
                if not addr.split("@", 1)[0].strip(".-"):
                    continue          # Ruby ranges/instance vars: (..@notifications.first.id)
                if m.start() and line[m.start() - 1] == "@":
                    continue          # fediverse handle @user@instance, not an email
                if (m.start() and line[m.start() - 1] in "/:") or _in_url_authority(line, m.start()):
                    continue          # srcset densities and URL userinfo such as user:pass@host
                if addr.lower() in EMAIL_IGNORE or EMAIL_IGNORE_RE.search(addr):
                    continue
                domain = addr.rsplit("@", 1)[-1]
                if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", domain):
                    continue          # user@10.0.0.2 is an SSH login, not an email
                if re.search(r"(?i)\.(png|jpe?g|gif|svg|webp|pdf|ico|icns)$", domain):
                    continue          # Xcode asset names like "Icon@2x.png", not emails
                if m.end() < len(line) and line[m.end()] == ":" and addr.split("@", 1)[0].lower() in ("git", "ssh", "hg"):
                    continue          # git@host:repo scp syntax
                if addr.lower().endswith((".example", ".invalid", ".local")):
                    continue
                if re.search(r"(?i)@(example\.(com|org|net)|(?:[\w-]+\.)*sentry\.io)$", addr):
                    continue          # example domains and Sentry DSNs are not personal emails
                role = PII_ROLE_RE.match(addr.split("@", 1)[0])
                metadata = p.name in ("package.json", "composer.json", "pyproject.toml", "Cargo.toml") or ext == ".gemspec"
                _priv_add(privacy, "pii-email", "info" if (role or metadata) else "low", addr.lower(), r, i, line,
                          ("Role mailbox (support@, noreply@, …): not personal data." if role else
                           "Package metadata email: published by design on the registry." if metadata else
                           "Hardcoded email address (a person's PII or a DSN); check it is intended to be public."))
                break
            m = MAILTO_RE.search(line)
            if m:
                _priv_add(privacy, "pii-email", "info", "mailto:" + m.group(1).lower(), r, i, line,
                          "mailto: link exposes an email address by design (contact info, not a leak).")
            m = TEL_LINK_RE.search(line)
            if m:
                _priv_add(privacy, "pii-phone", "info", f"{m.group(1).lower()}:" + m.group(2).strip(), r, i, line,
                          f"{m.group(1).lower()}: link exposes a phone number by design (contact info, not a leak).")
            m = PHONE_RE.search(line)
            if m and ext not in (".css", ".scss", ".sass", ".less", ".map"):
                _priv_add(privacy, "pii-phone", "low", m.group(0).strip(), r, i, line,
                          "Hardcoded phone number in source/config (personal data); check it is intentional.")
            elif ext not in (".css", ".scss", ".sass", ".less", ".map") and PHONE_CONTEXT_RE.search(line):
                lm = PHONE_LOCAL_RE.search(line)
                if lm:
                    _priv_add(privacy, "pii-phone", "low", lm.group(0).strip(), r, i, line,
                              "Local-format phone number next to a phone/tel keyword (personal data); check it is intentional.")
            m = ADDRESS_RE.search(line) or ADDRESS_INTL_RE.search(line)
            if m:
                _priv_add(privacy, "pii-address", "low", m.group(0).strip(), r, i, line,
                          "Postal address in source/config (personal data); check it is intended to be public.")
            if ZIP_CONTEXT_RE.search(line):
                m = ZIP_RE.search(line)
                if m:
                    _priv_add(privacy, "pii-postcode", "low", m.group(1), r, i, line,
                              "Postal/ZIP code next to a postal keyword: narrows down where the user is.")
            m = RETENTION_RE.search(line)
            if m:
                _priv_add(privacy, "data-retention", "info", m.group(1).lower(), r, i, line,
                          "A retention/expiry window is configured; verify it applies to the collected data.")
            if ext in CODE_EXT or ext in (".yml", ".yaml", ".toml", ".json", ".env", ".ini", ".conf", ".tf"):
                if UPLOAD_SINK_RE.search(line):
                    _priv_add(privacy, "upload-surface", "info", "file upload", r, i, line,
                              "Accepts user-supplied files or request bodies: data enters the service.")
                if UPLOAD_LIMIT_RE.search(line):
                    _priv_add(privacy, "upload-limit", "info", "size cap", r, i, line,
                              "A request/upload size cap is set (data-minimization guard).")
    if ext in (".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte", ".astro", ".php"):
        for fm in re.finditer(r"(?is)<form\b([^>]*)>", text):
            if not re.search(r"(?i)\bmethod\s*=\s*[\"']?get\b", fm.group(1)):
                continue
            end = text.find("</form>", fm.end())
            body = text[fm.end(): end if end >= 0 else fm.end() + 3000]
            if re.search(r"(?i)\btype\s*=\s*[\"']?(?:password|email|tel)\b", body):
                _priv_add(privacy, "form-method", "low", "GET form with user data", r,
                          text[:fm.start()].count("\n") + 1, fm.group(0)[:120],
                          "Form uses method=GET with password/email/phone inputs: values end up in the URL (Referer, logs, history).")
    # import-time network and IP logging: line-scoped, cheap enough to do in one more pass
    for i, line in enumerate(text.split("\n"), 1):
        if not line or line[0] in " \t" or _is_comment(line):
            continue
        if line.lstrip().startswith(("import ", "from ", "export ")):
            continue
        if ext == ".py" and IMPORT_NET_PY.search(line):
            _priv_add(privacy, "import-time-network", "medium", "python module scope", r, i, line,
                      "Network call at module scope: importing this library already contacts a server, before you call anything.")
        elif is_js and IMPORT_NET_JS.search(line) and not line.lstrip().startswith(("import ", "export ")):
            _priv_add(privacy, "import-time-network", "low", "javascript module scope", r, i, line,
                      "Network call at module top level: runs when the module loads (startup page views, update checks).")
        if is_js and (COOKIE_WRITE_RE.search(line) or STORAGE_RE.search(line)):
            _priv_add(privacy, "import-time-storage", "low", "javascript module scope", r, i, line,
                      "Cookie/localStorage write at module top level: runs on load, before any user interaction or consent.")
    if tracker_at and cmp_at and tracker_at < cmp_at:
        _priv_add(privacy, "consent-order", "low", "tracker before consent manager", r, tracker_at, lines[tracker_at - 1],
                  "A tracker initialises before the consent manager in this file; verify it does not fire before consent.")
    if storage_at and cmp_at and storage_at < cmp_at:
        _priv_add(privacy, "consent-order", "low", "cookie/storage write before consent manager", r, storage_at, lines[storage_at - 1],
                  "A cookie/localStorage write happens before the consent manager loads in this file; verify it is consent-gated.")
    if ext == ".xcprivacy" or p.name.endswith(".xcprivacy"):
        if re.search(r"<key>NSPrivacyTracking</key>\s*<true\s*/>", text):
            _priv_add(privacy, "ios-tracking", "low", "NSPrivacyTracking", r, _line_of(text, "NSPrivacyTracking"), "NSPrivacyTracking",
                      "The app's privacy manifest declares that it tracks users (Apple's definition: linking data to identity/location/ads).")
        for dom in re.findall(r"<key>NSPrivacyTrackingDomains</key>\s*<array>(.*?)</array>", text, re.S):
            for host in re.findall(r"<string>([^<]+)</string>", dom):
                _priv_add(privacy, "ios-tracking-domain", "info", host.strip(), r, _line_of(text, host), host.strip(),
                          "Domain the app declares as a tracking endpoint in PrivacyInfo.xcprivacy.")
        for m in re.finditer(r"NSPrivacyAccessedAPICategory([A-Za-z]+)", text):
            cat = m.group(1)
            tail = text[m.end():m.end() + 400]
            end = tail.find("</dict>")
            reasons = re.findall(r"<string>([A-Z0-9.]+)</string>", tail[:end if end >= 0 else len(tail)])
            why = f" Reasons: {', '.join(reasons)}." if reasons else ""
            _priv_add(privacy, "ios-api-category", "info", cat, r, _line_of(text, cat), f"NSPrivacyAccessedAPICategory{cat}",
                      "Apple required-reason API declared in PrivacyInfo.xcprivacy: the app explains why it uses it." + why)
        for block in re.findall(r"<dict>(.*?)</dict>", text, re.S):
            m = re.search(r"<key>NSPrivacyCollectedDataType</key>\s*<string>NSPrivacyCollectedDataType([A-Za-z]+)</string>", block)
            if not m:
                continue
            name = m.group(1)
            flags = []
            if re.search(r"<key>NSPrivacyCollectedDataTypeLinked</key>\s*<true\s*/>", block):
                flags.append("linked to identity")
            if re.search(r"<key>NSPrivacyCollectedDataTypeTracking</key>\s*<true\s*/>", block):
                flags.append("used for tracking")
            purposes = [re.sub(r"(?<=[a-z])(?=[A-Z])", " ", p).lower()
                        for p in re.findall(r"NSPrivacyCollectedDataTypePurpose([A-Z][A-Za-z]+)", block)]
            human = IOS_DATA_TYPE_NAMES.get(name, name.replace("Data", " data").lower())
            bits = flags + ([f"purposes: {', '.join(purposes)}"] if purposes else [])
            suffix = f" ({'; '.join(bits)})" if bits else ""
            _priv_add(privacy, "ios-data-type", "info", human + suffix, r, text[:m.start()].count("\n") + 1,
                      f"NSPrivacyCollectedDataType{name}",
                      "Declared in PrivacyInfo.xcprivacy: this data category is collected"
                      + (f" and {', '.join(flags)}" if flags else "")
                      + (f" for {', '.join(purposes)}" if purposes else "") + ".")
    if ext in (".plist", ".entitlements") or p.name.endswith(".plist"):
        ats = re.search(r"<key>NS(?:AllowsArbitraryLoads|ExceptionAllowsInsecureHTTPLoads)(?:InWebContent|InMedia)?</key>\s*<true\s*/>", text)
        if ats:
            _priv_add(privacy, "ios-cleartext", "medium", "ATS disabled", r, text[:ats.start()].count("\n") + 1,
                      ats.group(0), "App Transport Security allows plaintext HTTP (NSAllowsArbitraryLoads): cleartext requests are permitted.")
        for m in PURPOSE_STR_RE.finditer(text):
            key, body = m.group(1), re.sub(r"\s+", " ", m.group(2)).strip()
            _priv_add(privacy, "ios-purpose-string", "info", key, r, text[:m.start()].count("\n") + 1, body[:140],
                      "Apple purpose string: the user-facing reason shown when this capability is requested.")


PRIVACY_RULE_ORDER = {
        "fingerprint": 0, "import-time-network": 1, "import-time-storage": 2, "ip-logging": 3,
        "pii-log": 4, "pii-email": 5, "pii-phone": 6, "pii-address": 7, "pii-ssn": 8, "pii-card": 9,
        "pii-in-url": 10, "tracking-cookie": 11, "tracking-params": 12, "browser-capability": 13,
        "macos-entitlement": 14, "client-id": 15, "ios-tracking": 16, "ios-tracking-domain": 17,
        "ios-api-category": 18, "ios-data-type": 19, "ios-purpose-string": 20, "dnt-respect": 21,
        "consent-gating": 22, "consent-order": 23, "consent-mode": 24, "consent-state": 25, "vendor-pii": 26,
        "data-retention": 26, "upload-surface": 27, "upload-limit": 28, "store-disclosure": 29,
        "insecure-endpoint": 30, "external-endpoint": 31, "first-party-endpoint": 32, "third-party-cdn": 33,
        "third-party-script": 34, "third-party-stylesheet": 35, "third-party-media": 36,
        "third-party-preconnect": 37, "third-party-preload": 38, "third-party-embed": 39, "third-party-form": 40,
        "cookie-flags": 41, "cookie-write": 42, "cookie-lifetime": 43, "browser-storage": 44,
        "consent-manager": 45, "referrer-policy": 46, "permissions-policy": 47, "iframe-allow": 48,
        "extension-permission": 49, "extension-resource": 50, "extension-connectable": 51,
        "android-permission": 52, "android-feature": 53, "undisclosed-vendor": 54, "privacy-doc": 55,
        "telemetry-identify": 56, "session-replay-mask": 57,
        "android-cleartext": 58, "ios-cleartext": 59, "ios-tracking-declaration": 60,
        "android-queries": 61, "form-method": 62,
    }


RULESET = hashlib.sha256(" ".join(sorted(PRIVACY_RULE_ORDER)).encode()).hexdigest()[:12]


def privacy_findings(privacy):
    order = PRIVACY_RULE_ORDER
    down = {"high": "medium", "medium": "low", "low": "info"}
    fs = []
    for (rule, key), t in sorted(privacy.items(), key=lambda kv: (order.get(kv[1]["rule"], 9), kv[1]["key"])):
        sev = t["sev"]
        if TEST_PATH.search(t["file"]):    # fixtures contain fake hosts and deliberately bad cookies
            sev = down.get(sev, sev)
        meaning = t["meaning"] + (f" Seen {t['count']} times." if t["count"] > 1 else "")
        fs.append(finding("privacy", sev, t["file"], t["line"], f"{rule}: {t['key']}", t["snippet"], meaning))
    return fs