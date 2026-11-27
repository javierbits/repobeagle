# RepoBeagle feature backlog

A scored backlog for RepoBeagle, derived from reading `repobeagle.py`, `install.sh`,
`tools/make_badge.py`, `.github/workflows/{image,scan}.yml` and `tests/`.

## How to read this

**Impact (1–10)** measures the expected effect on the project's three goals — verdict
correctness, adoption, usability — weighted by whether the change is actually shippable
and used.

| Score | Meaning |
|---|---|
| 10 | Changes the trust model or the audience |
| 8–9 | Removes a blocker for adoption or a class of wrong verdicts |
| 6–7 | Material for people already using it |
| 4–5 | Polish; ship when adjacent work lands |
| ≤3 | Not listed unless cheap |

**Effort** is engineering time for one competent contributor, including tests:
S ≤ 2 days, M ≤ 1 week, L > 1 week.

**Already strong** (do not re-propose): read-only non-root container with
`--network none`, sparse blobless clone with hooks and protocol restrictions, Sigstore
signed reports with an identity-pinned `verify`, deterministic verdicts, suppression,
three severity profiles, privacy-only mode with redaction, shields.io badge publishing,
multi-arch image.

---

## Master list (passes 1–3)

| ID | Feature | Axis | Impact | Effort | Depends on |
|---|---|---|---|---|---|
| T1 | Hosted attestation service + public scan API | Trust, reach | 10 | L | R12, R13, T10 |
| T2 | GitHub App that scans PRs and comments | Reach | 9 | M | U5, T3 |
| T3 | SARIF output + native CI/editor integration | Reach, usability | 8 | S–M | — |
| T4 | `repobeagle mcp` server | Reach | 8 | S | T1 (optional) |
| T5 | Capability / blast-radius map | Trust, reach | 8 | M | R8 |
| T6 | `--trace`: syscall-verified capabilities | Trust | 8 | L | T5 |
| T7 | `repobeagle web <url>` page audit | Reach | 8 | M | — |
| T8 | Public precomputed index of popular repos | Reach | 7 | M | R12, R13, T1 |
| T9 | Provenance signals (signing, forks, committers) | Trust | 6 | S | — |
| T10 | `repobeagle trend` over published reports | Trust | 6 | S–M | — |
| R1 | Baseline / diff gate (`--baseline`) | Robustness | 8 | S–M | R4 |
| R2 | Harden the toolchain's own supply chain | Robustness | 8 | M | — |
| R3 | Enforced CI: suite, fuzz, typecheck, rule fixtures | Robustness | 8 | M | — |
| R4 | Rule registry, package split, golden snapshots | Maintainability | 6 | L | R3 |
| R5 | Ref/commit pinning + reproducible re-scan | Robustness | 7 | M | — |
| R6 | Offline OSV database mode | Robustness | 7 | M | — |
| R7 | Precision corpus + per-rule scoreboard | Robustness, reach | 7 | M–L | R3 |
| R8 | Coverage report (what was not inspected) | Robustness | 7 | M | — |
| R9 | Hard deadline + partial reports | Robustness | 6 | M | R8 |
| R10 | Submodules + dependency-supply-chain rules | Robustness | 6 | S–M | — |
| R11 | Transitive dependency risk attribution | Trust | 6 | M | — |
| R12 | Batch / parallel scanning | Throughput | 6 | M | — |
| R13 | Content-addressed result cache | Throughput | 5 | S–M | — |
| U1 | `.repobeagle.yml` policy-as-config | Usability | 7 | L | R4 |
| U2 | Persona profiles (consumer / agent-operator / CI) | Usability | 7 | M | R4 |
| U3 | Rule packs + fixture SDK | Reach, robustness | 7 | M | R4 |
| U4 | Non-Docker distribution (pipx, brew, macOS) | Usability, reach | 7 | M | — |
| U5 | PR-scoped scan (`--since`, changed files) | Usability, CI | 7 | M | — |
| U6 | `repobeagle fix` auto-PR for mechanical rules | Reach, usability | 7 | M | R4 |
| U7 | `repobeagle head` triage + chat unfurl | Reach | 6 | S–M | — |
| U8 | Suppression lifecycle (reason, expiry, `ignore`) | Usability, auditability | 6 | S | — |
| U9 | Per-finding remediation text | Usability | 6 | S | R4 |
| U10 | Verdict transparency + triage planner | Usability, trust | 5 | S | R4 |
| U11 | `repobeagle init`, self-badge, HTML report | Usability, reach | 5 | S | — |
| U12 | CycloneDX SBOM export | Reach (enterprise) | 5 | S–M | — |
| U13 | Redacted feedback loop | Precision, growth | 5 | S | — |

---

## T1 — Hosted attestation service + public scan API · 10 · L

**What.** A service that runs the pinned image on demand, caches per `(repo, sha)`, and
signs with its own workflow identity. `GET /v1/scan/<owner>/<repo>/<sha>` returns the
existing `report.json` schema; permalink pages at `/o/<owner>/<repo>`.

**Why.** The README states the hole: *"For a fully independent verdict, someone else must
run the scan (or a future hosted service)."* Every badge today is self-attested: a repo
owner can simply not run the workflow.

**Design.** Reuse `VERSION`-pinned image, `run_in_docker` flags unchanged; queue with a
per-IP and per-repo budget; immutable results per SHA. `repobeagle verify` already accepts
`--identity-regexp`; add the service identity to the default allowlist.
`tools/make_badge.py` renders the page block.

**Acceptance.** A scan fetched from the service verifies with `repobeagle verify`; the
same commit scanned twice yields identical findings; a rate-limited client gets 429, not
a wrong verdict.

**Risk.** The only recurring cost and uptime obligation. Additive: local scans and the
existing badge workflow keep working.

## T2 — GitHub App that scans PRs and comments · 9 · M

**What.** Webhook on `pull_request`/`push` → scan → one collapsing comment + a check run.

**Why.** `.github/workflows/scan.yml` is `workflow_call`: every adopter must add YAML,
grant `contents`/`statuses`/`id-token` write, and pick `tools-ref`. That is the funnel.
The App removes all of it.

**Design.** Extract the scan logic from `scan.yml` into `tools/scan_repo.sh` so workflow
and App cannot drift. Comment: verdict, top findings, link to the signed report. Use U5
to scan the diff only and R1 to report regressions.

**Acceptance.** Install → open a PR touching one file → check run + exactly one comment,
updated on each push; no PR head code is executed (nothing is executed at all).

**Risk.** App review and permissions; guard against comment spam by editing one comment.

## T3 — SARIF output + native integration · 8 · S–M

**What.** `--format sarif|json|markdown`; findings mapped to `ruleId`, `level`
(critical/high → error, medium → warning, low/info → note), `artifactLocation.uri`,
`region.startLine`, and `partialFingerprints` over `(rule, file, normalised snippet)`.

**Why.** JSON-only means findings never appear inline on a PR diff. GitHub code scanning,
Azure DevOps, GitLab and VS Code all consume SARIF.

**Design.** Emit from the merged finding list after `dedupe`; validate against the SARIF
schema in CI (R3). Add `--since <ref>` for pre-commit via `fetch()`'s existing clone.

**Acceptance.** `upload-sarif` accepts the file; alerts dedupe across runs; `--format
json` remains byte-identical to today.

**Risk.** SARIF is easy to get subtly invalid; schema validation is mandatory.

## T4 — `repobeagle mcp` server · 8 · S

**What.** stdio MCP server exposing `scan_repo(url, profile)`, `verify_badge(slug)`,
`explain_rule(id)`.

**Why.** The tool exists to audit MCP servers (`check_mcp`, tool-poisoning checks) yet
does not expose itself to agents — the audience that runs `npx -y` without looking.

**Design.** Local scan by default; T1 when `BEAGLE_SERVICE` is set. Return
`{verdict, counts, top_findings, report_url}`. ~150 LOC over existing functions.

**Acceptance.** An MCP client lists the three tools and receives a verdict for
`tests/fixtures/trap-npm`; a service-backed call returns the attestation URL.

**Risk.** None material; the JSON contract exists.

## T5 — Capability / blast-radius map · 8 · M

**What.** The inverse of a findings list: network hosts contacted, files/paths and env
vars read, subprocesses spawned, install hooks that fire automatically, storage written,
permissions requested.

**Why.** `finding()` is issue-shaped; users must assemble the model themselves.
`privacy_summary`, `SENSITIVE`, `SINK_RE`, `READ_RE` and `check_install_hooks` already
produce the raw material.

**Design.** `repobeagle map <target> [--json]`, adding
`capabilities{network,filesystem,processes,hooks,storage,permissions}` to the report. No
verdict change, exit 0. Group reads by prefix, cap per section.

**Acceptance.** `trap-npm` map shows `~/.ssh/id_rsa`, a POST sink and `postinstall`;
`control-clean` shows no network and no hooks; ordering deterministic.

**Risk.** `open()` sites are noisy; dedupe by resolved path prefix.

## T6 — `--trace`: syscall-verified capabilities · 8 · L

**What.** Opt-in run of the install phase inside the existing hardened container with
`strace -f -e trace=connect,execve,openat`, feeding the map from T5 with
`verified: true, source: trace`.

**Why.** "Never runs repo code" is the selling point, but it leaves every capability
claim inferred from text. Verification is the remaining differentiator, and
`run_in_docker()` already gives isolation (`--read-only`, non-root, `HOME=/tmp`,
`--network none` when tracing is off).

**Design.** Detect the install command from manifests; run only install, never tests or
builds; per-target timeout; keep the static map as the default. Document that host
secrets are structurally unreachable (`HOME=/tmp`, nothing mounted), so the trace proves
network/subprocess/filesystem-in-container behavior, not credential reads.

**Acceptance.** `trap-npm --trace` records the postinstall host connection and the node
subprocess; `control-clean --trace` records no outbound connect; findings schema
unchanged, `meta.trace = true`.

**Risk.** Install steps need the network and minutes; keep it out of the default CI gate.

## T7 — `repobeagle web <url>` · 8 · M

**What.** Run the privacy/telemetry rules against a live page: `third-party-*`,
`telemetry-*`, `cookie-*`, `tracking-cookie`, `pii-*`, `referrer-policy`,
`permissions-policy`, consent managers.

**Why.** Every rule already parses HTML/CSS/inline JS; the repo is just a container.
"What does this site phone home to?" has a far larger audience and reuses the hosted
service's fetch path.

**Design.** One GET with timeout and size cap; optionally follow same-origin
`<script src>`/`<link rel=stylesheet>` (`--assets N`, default 0). `meta.mode = web`;
privacy-only verdict; no OSV/trust.

**Acceptance.** A page with GTM and an iframe → YELLOW with `telemetry-analytics` and
`third-party-embed`; static docs → GREEN; offline test via `file://` on
`tests/fixtures/trap-privacy`.

**Risk.** Scope creep — one page, no crawling, privacy-only.

## T8 — Public precomputed index · 7 · M

**What.** Weekly job over a curated set of popular repos and agent-skill/MCP registries →
static `results/<slug>@<sha>.json` + searchable Pages index.

**Why.** "Paste any popular repo and see a verdict" without installing; permalinks for
SEO; seeds the cache the service needs.

**Design.** Refresh by SHA only; parallelize with R12; skip unchanged SHAs; every page
links its signed report.

**Acceptance.** 1k repos in under 4 h with 20 parallel jobs; every published page verifies
with `repobeagle verify`.

**Risk.** Runner minutes; config-driven cap, nightly cadence.

## T9 — Provenance signals · 6 · S

**What.** Commit and tag signature presence, release immutability, committer association
on the default branch, fork relation (`N commits ahead, M files changed vs upstream`).

**Why.** `trust_findings` uses age, stars, forks, contributors and renames only. Most
malicious forks are "upstream plus three changed workflow files"; `compare` is one API
call and more informative than stars.

**Design.** Extend `trust_findings`; all findings LOW/INFO so they never flip a verdict
alone. Unsigned commits are the norm → `info`.

**Acceptance.** Unit tests with mocked API payloads; no network in CI.

**Risk.** Rate limits — reuse the existing degrade-to-note path.

## T10 — `repobeagle trend` · 6 · S–M

**What.** Read the per-SHA reports already published on the badge branch and produce a
verdict/rule time series: first RED, regressions per rule, current streak.

**Why.** `scan.yml` writes `report-<sha>.json` on every push and nothing consumes them
historically. "Getting safer or riskier?" costs no new scans.

**Design.** List branch contents via API, read `meta`/findings, emit table + sparkline
data; skip reports whose `meta.ruleset` or `version` differ.

**Acceptance.** Three or more reports produce ordered verdicts; malformed reports are
ignored, not fatal.

**Risk.** Rule renames distort history — pair with R4's stable ids.

---

## R1 — Baseline / diff gate · 8 · S–M

**What.** `--baseline report.json` and `repobeagle diff old.json new.json
--fail-on new`, matching findings by `(rule, file)` with line drift tolerance.

**Why.** `fail-on-red` is the only gate, and the README admits *"YELLOW on big honest
repos is normal"*. "No new findings" is the only stable CI signal.

**Design.** Classify added/fixed/unchanged; exit 1 only on additions at or above
`--min-severity`; `scan.yml` can self-baseline from the badge branch.

**Acceptance.** Re-scanning a fixture with one added `curl|sh` yields exit 1 and exactly
one added finding; unchanged tree yields 0.

**Risk.** Rule renames break matching; depends on stable ids (R4).

## R2 — Harden the toolchain's own supply chain · 8 · M

**What.** Pinned versions and SHA-256 for `gitleaks`, `osv-scanner`, `cosign`; image
pulled by digest with `cosign verify`; SLSA provenance on the image build.

**Why.** A security scanner that trusts `curl | tar` is a bad look. `install.sh` resolves
versions from the live GitHub API, downloads release binaries without checksums, and runs
whatever mutable tag `VERSION` points at.

**Design.** `checksums.txt` in the repo, verified before install; digest recorded in
`meta.image_digest` (already collected); keep `BEAGLE_IMAGE` as an escape hatch but
verify when a checksum exists.

**Acceptance.** A tampered binary fails the install; a mutated tag is detected; offline
build from `--build-local` still works.

**Risk.** Breaks "just pull latest"; document the tag→digest resolution.

## R3 — Enforced CI · 8 · M

**What.** `ci.yml` running `tests/run_tests.sh --offline` on PRs, the full suite nightly,
plus `ruff`, `mypy`, and a Hypothesis/Atheris pass over the pure parsers.

**Why.** `tests/run_tests.sh` is thorough but no workflow invokes it; `image.yml` runs one
`trap-npm` smoke test. A 3390-line regex-heavy module has no lint, types, or fuzz.

**Design.** Fuzz targets: `check_unicode`, `check_markdown_hidden`, `decode_tags`,
`redact_pii` — assert termination and no exception on random unicode/HTML/bytes. Add a
guard that every rule id fired by a fixture has a positive and a negative fixture.

**Acceptance.** A deliberately catastrophic regex fixture times out loudly instead of
hanging CI; a PR lowering coverage fails.

**Risk.** Network-dependent tests stay in the nightly job.

## R4 — Rule registry, package split, golden snapshots · 6 · L

**What.** `repobeagle/{cli,report,fetch,rules/agent,rules/privacy,scanners}.py`,
`repobeagle.py` as a thin shim, explicit
`Rule(id, severity, meaning, remediation, docs)`, and byte-stable `report.json`
snapshots per fixture.

**Why.** Rule ids are recovered by splitting titles (`f["title"].split(":")[0]`); that
string surgery blocks U1, U2, U3, U6, U9, U10 and R1. Maintainability is now the
constraint on features.

**Design.** Behavior-preserving and mechanical; one dedicated change with zero rule
edits; snapshots strip `seconds`/`run_url`; `import repobeagle` must work and the image
build must stay unchanged.

**Acceptance.** Snapshot suite byte-identical before/after; `mypy` clean.

**Risk.** Churn while features land; do it after R3 exists.

## R5 — Ref/commit pinning + reproducible re-scan · 7 · M

**What.** `--ref <branch|tag|sha>`, plus `verify --rescan` that re-runs the pinned image
on the reported SHA and diffs findings.

**Why.** `fetch()` hardcodes a default-branch shallow clone; you cannot scan a tag, a PR
merge ref, or re-scan the exact commit in a report.

**Design.** `git init` + `fetch --depth 1 <url> <ref>` for pinned refs; record
`meta.scanned_sha`; `--rescan` compares rule sets and files.

**Acceptance.** Scanning a tag and its SHA yields identical findings; a doctored report
fails the rescan diff.

**Risk.** Full `git init` path needs its own tests; verify against a large repo.

## R6 — Offline OSV database · 7 · M

**What.** `repobeagle db update` → `osv-scanner --download-offline-databases` into
`$PREFIX/osv-db`; `--offline-vulnerabilities`; `meta.osv_db_date`.

**Why.** The README calls it *"a possible later improvement"*, but online OSV means the
report is not actually reproducible and airgapped runners cannot use it.

**Design.** Dated DB + `meta` timestamp makes "re-run the pinned image and diff" a real
claim; cache the DB in CI.

**Acceptance.** Offline scan matches the online one for a fixed DB date; missing DB is a
clear error, not a silent skip.

**Risk.** DB size; make the download explicit and cacheable.

## R7 — Precision corpus + scoreboard · 7 · M–L

**What.** `tests/corpus.yml` with ~40 real repos pinned by SHA, expected verdict/rule
sets; nightly run publishes per-rule precision on an honest cohort and detection on a
malicious cohort.

**Why.** Nine fixtures, no false-positive tracking; precision is the product risk.
Several recent commits are exactly this class of fix.

**Design.** Fail CI when a rule regresses; count budgets on honest repos; pin SHAs.

**Acceptance.** `control-clean` stays GREEN under strict; an honest-repo median finding
count does not increase across a rule change.

**Risk.** Network in CI — nightly only.

## R8 — Coverage report · 7 · M

**What.** `meta.coverage{files_total, files_scanned, bytes_scanned_pct,
skipped{oversize,binary,archive,symlink}, unscanned_extensions}` plus a
`coverage-low` finding below 60 % of source bytes.

**Why.** GREEN implies "inspected", but `MAX_FILE`, `SKIP_DIRS`, symlink skipping,
archives/binaries and unsupported languages are silent blind spots.

**Design.** Derive from `iter_files`/`read_text` outcomes and `skipped.json`; print a
`Coverage:` line next to `Privacy profile:`.

**Acceptance.** `trap-binary` reports its archive/binary counts; a `.sol`-only repo shows
0 % and `coverage-low`.

**Risk.** Do not force YELLOW on low coverage; a finding plus a printed line is enough.

## R9 — Hard deadline + partial reports · 6 · M

**What.** `--max-seconds`, a per-file alarm around the regex parsers, checkpoints after
each phase, and `meta.complete: false` with a verdict floor of YELLOW.

**Why.** `inner()` guards the four external scanners but not `run_agent_checks`; JSON is
written only at the end. One pathological file loses the whole scan.

**Design.** Reuse `_run`'s timeout pattern for the agent phase; `scan.yml` distinguishes
"crashed" from "incomplete"; never let a truncated scan look green.

**Acceptance.** A synthetic slow check yields a partial report with the note and YELLOW,
exit code 1, not a traceback.

**Risk.** Partial results must be visibly partial in the badge too (badge text).

## R10 — Submodules + dependency supply-chain rules · 6 · S–M

**What.** `submodule-unpinned`, `submodule-host`, `submodule-uninspected`,
`dockerfile-base-unpinned`, `dependency-confusion` (`pip --extra-index-url`, npm `http://`
tarballs, `resolutions` overrides).

**Why.** Two documented misses ("Submodules, which are not fetched") plus a classic
attack class not covered: dependencies from a lookalike index.

**Design.** `.gitmodules` and Dockerfiles are text, so no clone behavior changes; cap
Dockerfile pinning at `low` because it fires on most real repos.

**Acceptance.** Fixture with a branch-ref submodule and an unpinned `FROM` yields both
rules exactly once.

**Risk.** Noise on real Dockerfiles; severity low + remediation text.

## R11 — Transitive dependency risk attribution · 6 · M

**What.** Attach the dependency path (`app → next → postcss`) to OSV findings when the
lockfile carries edges (npm v3, pip-compile).

**Why.** OSV says `package@version` + advisories, not why it is in the tree. "You ship it
because X" converts a name into a decision.

**Design.** Build edges from lockfiles already parsed for telemetry; fall back to
direct/transitive when unavailable; no network.

**Acceptance.** A transitive vulnerability in a fixture shows a path to the manifest;
direct deps show depth 1.

**Risk.** Cargo sparse index has no edges; say so instead of guessing.

## R12 — Batch / parallel scanning · 6 · M

**What.** `--jobs N` across targets; concurrent external scanners inside a target.

**Why.** `inner()` runs gitleaks → semgrep → guarddog → bandit sequentially and
`cmd_scan` handles one target. Orgs, T8 and T1 all need throughput.

**Design.** `ThreadPoolExecutor` over targets; the four scanners are independent
subprocesses with separate output files; `run_agent_checks` stays serial (GIL); sort
findings after merge for determinism.

**Acceptance.** Three targets at `--jobs 3` produce identical JSON to sequential runs
minus `seconds`; wall time below 45 %.

**Risk.** Docker daemon contention; default 4.

## R13 — Content-addressed result cache · 5 · S–M

**What.** Cache keyed on `sha256(tree + ruleset digest + image digest + osv_db_date)`,
stored under `$XDG_CACHE_HOME/repobeagle/`, `meta.cache = hit|miss`.

**Why.** Repeat scans of the same SHA (verification, index refresh, PR + push) redo all
work; results are deterministic modulo timings.

**Design.** Cache raw findings, filter by profile/privacy mode after reading.

**Acceptance.** Second identical scan is a hit; `--profile` change re-filters correctly;
cache never serves across image digests.

**Risk.** Stale cache if a scanner is upgraded without an image bump — part of the key.

---

## U1 — `.repobeagle.yml` policy-as-config · 7 · L

**What.** Per-repo `profile`, per-rule severity overrides, host allowlists, and
`custom_checks` (paths + regex + severity + meaning).

**Why.** README: *"To change the thresholds, edit `PROFILES` in `repobeagle.py`."*
`.repobeagleignore` accepts bare globs with no reasons.

**Design.** Parse once, validate against the R4 registry, fail loudly on an unknown rule
id; precedence: repo config > persona > profile.

**Acceptance.** Overriding `telemetry-devtool` to `info` flips a fixture from YELLOW to
GREEN; a typo in a rule id is an error, not a silent no-op.

**Risk.** Depends on R4; keep the defaults identical when the file is absent.

## U2 — Persona profiles · 7 · M

**What.** `--as consumer|agent-operator|ci|maintainer`, applying rule-id severity deltas
before `verdict()`.

**Why.** `PROFILES` only moves thresholds; `trap-gha` is YELLOW under the default while
an agent operator cares about exactly that class.

**Design.** Persona table over rule ids; `--list-personas`; header prints the persona.

**Acceptance.** `trap-gha --as ci` RED; `trap-skill --as agent-operator` RED;
`trap-telemetry --as maintainer` GREEN/YELLOW.

**Risk.** Two policy dimensions confuse; document precedence and forbid ambiguous
combinations.

## U3 — Rule packs + fixture SDK · 7 · M

**What.** `rules/*.yaml` packs `{id, paths, regex, severity, meaning, remediation,
fixtures}`, `repobeagle rules lint|test`, versioned artifact.

**Why.** Agent checks are Python-only and hardcoded; `rules/custom.yml` is Semgrep-only.
The most common contribution is "you missed X", which today means editing a 3390-line
file.

**Design.** Compile packs into the same `finding()` shape; require ≥1 positive and ≥1
negative fixture per rule in CI.

**Acceptance.** A catastrophic or unanchored regex fails lint; positive fixtures fire
the exact rule id; negatives do not.

**Risk.** Regex packs cannot express context-sensitive logic; additive only.

## U4 — Non-Docker distribution · 7 · M

**What.** `pyproject.toml` + `pipx install repobeagle`, Homebrew formula, macOS support,
PyInstaller one-file build for airgapped hosts.

**Why.** Install needs git, python3, Docker and Linux. `install.sh` maps `uname -m` to
*Linux* binaries, so macOS silently downloads `gitleaks_linux_*`.

**Design.** Single-module entry point; macOS branch via `brew install gitleaks cosign
osv-scanner`; keep the image the recommended hardened path.

**Acceptance.** `pipx install . && repobeagle scan tests/fixtures/trap-npm --no-docker`
works on macOS arm64 with host tools installed.

**Risk.** A second install path to support; document it as the light mode.

## U5 — PR-scoped scan · 7 · M

**What.** `--since <rev>` / `--changed-only`, `meta.scope = changed`.

**Why.** Whole-tree scans on a monorepo PR are slow and drown the one new finding among
hundreds of pre-existing ones.

**Design.** `git diff --name-only --diff-filter=AM <merge-base>` before checkout; pass an
allowlist to `iter_files`; keep context-dependent checks but attribute only changed
files; refuse to print "safe" without a scope note.

**Acceptance.** A one-file change yields only that file's findings; runtime drops
proportionally; `meta.scope == "changed"`.

**Risk.** A changed file importing a bad module stays hidden; the printed note must carry
that.

## U6 — `repobeagle fix` · 7 · M

**What.** Auto-fix and open a PR for mechanical rules: unpinned action → resolved SHA,
missing `permissions:` → least privilege.

**Why.** A report that only says "no" gets ignored; a PR that pins `actions/checkout`
gets merged.

**Design.** Start with 2–3 rules; `--dry-run` prints the diff; never touch rules that
need judgement (`curl|sh`, PII); the App opens `repobeagle/fix-<sha>`.

**Acceptance.** `trap-gha` gets two workflow files rewritten, re-scan improves, dry-run
mutates nothing.

**Risk.** YAML rewriting breaks CI; parse with `yaml.safe_load` and only write when the
resolved SHA exists.

## U7 — `repobeagle head` + chat unfurl · 6 · S–M

**What.** Metadata-only triage via the GitHub contents API (manifests, workflows,
`SKILL.md`, `mcp.json`, README) in seconds; unfurl card for Slack/Discord.

**Why.** The fast path still needs git, docker and a writable temp dir; a 2 s HTTP-only
path can run in a Worker or a chat bot. The Grok bot exists; chat unfurl does not.

**Design.** `meta.scope = metadata`; token env + per-slug cache; degrade to a note on
rate limit, never a wrong verdict.

**Acceptance.** `head` on `trap-npm` flags `postinstall`; on `trap-gha` flags unpinned
actions; unauthenticated limits produce a note.

**Risk.** 60 req/h unauthenticated — cache and degrade.

## U8 — Suppression lifecycle · 6 · S

**What.** `rule  # reason @2026-06-01`; expired entries unsuppress with a warning;
`meta.suppressed` carries `{rule, reason, until}`; `repobeagle ignore`.

**Why.** `load_suppressions()` strips everything after `#`, so a silenced finding has no
reason, owner or expiry — a repo can suppress `pii-*` forever.

**Design.** Backwards compatible: bare lines stay valid; JSON keeps `suppressed: true`.

**Acceptance.** An expired line re-activates its finding and prints a warning; `ignore`
appends a parseable line.

**Risk.** None; additive.

## U9 — Per-finding remediation · 6 · S

**What.** `remediation` per rule id, rendered as a `fix:` line and in JSON.

**Why.** `meaning` says why; `ACTIONS[v]` is generic per verdict. A user seeing
`cookie-flags` wants the exact flags to add.

**Design.** Populated from the R4 registry; only deterministic advice, never "consider
reviewing".

**Acceptance.** Snapshot test for the top 10 rules; every finding with a remediation has
it in both output modes.

**Risk.** Wrong advice is worse than none; keep it to well-understood rules.

## U10 — Verdict transparency + triage planner · 5 · S

**What.** Explain exactly which counts crossed which threshold and the margin
("1 medium away from RED"), and simulate accepting rules to reach a target verdict,
writing `.repobeagleignore` lines with reasons.

**Why.** `verdict()` is three lines; users still ask why, and a YELLOW repo with 40
findings needs a plan, not a list.

**Design.** Pure function over a report; no re-scan; `--write` appends suppressions.

**Acceptance.** Expected transition table on `trap-privacy` matches the recomputed
verdicts.

**Risk.** Suppression advice can hide real issues; always print the count that remains.

## U11 — `init`, self-badge, HTML report · 5 · S

**What.** `repobeagle init` writes the documented workflow and prints the shields lines;
`--html out.html` self-contained findings table; this repo shows its own badge.

**Why.** Setup is copy-paste YAML, and the README has no badge on itself. Dogfooding also
exercises `verify` in CI.

**Design.** Template the workflow from `scan.yml` inputs; HTML from the merged findings
with redaction preserved.

**Acceptance.** `init` in an empty repo creates a workflow that runs green; the rendered
badge links a valid signed report.

**Risk.** Trivial.

## U12 — CycloneDX SBOM export · 5 · S–M

**What.** `--sbom out.json` emitting CycloneDX 1.6 from the lockfiles already parsed.

**Why.** Enterprises require an SBOM next to a vulnerability report; it makes the OSV
findings auditable.

**Design.** Map packages to purls; include the verdict as a metadata property.

**Acceptance.** npm/pip/cargo fixtures validate against the CycloneDX schema in CI.

**Risk.** Schema drift; pin the schema version.

## U13 — Redacted feedback loop · 5 · S

**What.** `repobeagle feedback --false-positive|--miss` opens a prefilled issue with
version, ruleset, rule id, `file:line`, and an already-redacted snippet.

**Why.** Precision is the product risk, yet there is no path from a frustrated user to a
fixed rule.

**Design.** Never attach the full report unless `--attach`; truncate snippets to keep the
URL under GitHub's limit.

**Acceptance.** Body contains no raw email/card even from a `--no-redact` scan.

**Risk.** Low; the issue text must be pasteable without the report.

---

## Pass 4 — features that change behavior, not just reports

These came after passes 1–3 and are not in the master list above. They target the two
places RepoBeagle is currently absent: the moment of install, and the registry the user
actually downloads from.

| ID | Feature | Axis | Impact | Effort | Depends on |
|---|---|---|---|---|---|
| U14 | `repobeagle run` install interceptor | Safety, ease | 8 | M | U7, R13 |
| T11 | Registry release-drift & provenance checks | Trust | 7 | M | T9 |
| R14 | Safe archive scanning (`scan ./x.zip`) | Robustness | 7 | M | — |
| U15 | Registry/marketplace gate action | Reach | 7 | M | R12, R13, R1 |
| R15 | Workspace / monorepo-aware scanning | Robustness | 6 | M | — |
| R16 | Fix availability on vulnerable dependencies | Usability | 6 | M | — |
| T12 | Rule-level evidence ledger (negative results) | Trust | 6 | M | R4 |
| U16 | Report freshness policy (`verify --max-age`) | Trust | 4 | S | — |
| U17 | `explain` with real-world examples | Usability | 4 | S | R7, R4 |

## U14 — `repobeagle run` install interceptor · 8 · M

**What.** `repobeagle run -- npx -y @scope/tool`, `pipx run`, `uvx`, `cargo install`:
resolve the package from the command, fetch its repo, scan it, then execute or refuse.

**Why.** The dangerous moment is install, and the scanner is not in that path. `npx -y`
fetches and runs code before anyone can paste a URL. This is the only feature that
prevents an incident rather than reporting one.

**Design.** Map binary → ecosystem → registry lookup (npm/PyPI/crates JSON) → repository
URL; use U7 for registry metadata and R13 for caching; GREEN runs, YELLOW prompts on a
TTY and fails in CI, RED refuses unless `--force`. `run --` form only, so no shell
parsing. Pass the wrapped command's exit code through unchanged.

**Acceptance.** `run -- npx -y <fixture-package>` resolves the repo and scans; `--yes`
skips the prompt only on GREEN; RED exits 1 without running the command.

**Risk.** Adoption needs a shell habit change (`alias npx='repobeagle run -- npx'`); the
wrapper must never alter the command's output or exit status, or users will remove it.

## T11 — Registry release-drift & provenance checks · 7 · M

**What.** For published packages, compare the release tag's tarball with the registry
artifact: manifests, `scripts`, dependency sets, file-list deltas, plus npm
`dist.attestations` / PyPI provenance presence.

**Why.** A clean repo does not prove the published package was built from it. A malicious
publish survives a repo scan completely, and `release-drift` is currently invisible.

**Design.** `repobeagle release <slug>`; resolve the tag (T9) → registry tarball; emit
`release-drift` (high) on added install hooks or dependency sets that differ, and
`no-provenance` (low/info). Generated/minified files legitimately differ, so compare
semantics, not bytes, and say so in the finding.

**Acceptance.** A fixture whose registry tarball injects a `postinstall` absent from the
repo produces a high `release-drift`; identical releases produce none.

**Risk.** Heuristic comparison will have false positives; keep the finding text explicit
about what differed.

## R14 — Safe archive scanning · 7 · M

**What.** `repobeagle scan ./foo.zip` (and `--release-assets` for GitHub releases):
extract into the temp dir under strict limits, then scan the contents.

**Why.** Archives are currently listed in `skipped.json` and never inspected — a
documented blind spot, and users download zips from releases more often than they clone.

**Design.** `safe_extract()` for zip/tar: reject absolute paths and `..`, never follow or
create symlinks, cap per-entry size, total size, entry count, and nesting depth 1; 7z/rar
stay flagged as uninspectable; encrypted zips keep their existing finding. Extracted
content is scanned as a normal tree and `meta.archives` records what was expanded.

**Acceptance.** A zip-slip fixture cannot write outside the temp dir; a 10 GB archive of
5 MB text scans only the text within the budget; a symlink entry is recorded, not
followed.

**Risk.** Decompression bombs — enforce size caps before and during extraction, stop at
N entries.

## U15 — Registry/marketplace gate · 7 · M

**What.** A reusable workflow plus CLI mode that scans every entry listed by a directory
(MCP registry, agent-skill catalogs) and emits per-entry verdicts for the directory's CI.

**Why.** T2 is opt-in per repo; directories are where users actually discover skills, and
a directory can enforce the scan centrally. One integration covers thousands of listings.

**Design.** Input file of slugs; batch with R12 and cache with R13; fail only on new RED
(R1); mark unfetchable entries `unknown`, never GREEN.

**Acceptance.** A 200-entry fixture list completes offline; a deleted repo yields
`unknown`; a newly published listing with a `curl|sh` turns the job red.

**Risk.** Directory CI minutes; make it incremental by SHA and cache aggressively.

## R15 — Workspace / monorepo-aware scanning · 6 · M

**What.** Detect npm/pnpm yarn workspaces, Cargo workspaces, Go multi-module and Python
monorepos; attribute findings and first-party inference per package.

**Why.** `own_domains()` reads root manifests, so a sibling workspace's host can be
classified first-party (or a real first-party host as third-party) and package boundaries
vanish in the report.

**Design.** Parse workspace manifests, scan each package with its own root, cap package
count, and label findings with `package:`; cross-workspace dependencies stay attributed
to the referencing package.

**Acceptance.** A two-workspace fixture does not let package A's `CNAME` mark package B's
third-party host as first-party; per-package counts sum to the total.

**Risk.** Huge monorepos; cap and report the cap.

## R16 — Fix availability on vulnerable dependencies · 6 · M

**What.** When the advisory lists fixed versions (OSV `affected.ranges` → `fixed`
events), annotate `fixed_in`; otherwise say "no fixed version listed".

**Why.** "You have CVE-X" gets postponed; "upgrade `lodash` 4.17.19 → 4.17.21" gets
merged. The data is often in the OSV response already.

**Design.** Parse `fixed` events; surface as `remediation`/`meaning`; no extra network
when present, at most one registry lookup otherwise.

**Acceptance.** A fixture advisory with a fixed event yields `fixed_in`; an advisory
without one states it explicitly instead of guessing.

**Risk.** Range parsing; only trust explicit `fixed` events from OSV.

## T12 — Rule-level evidence ledger · 6 · M

**What.** For each rule: evaluated or not, files examined, hits, and the negative
assertion ("no `pull_request_target`", "no plaintext endpoints").

**Why.** Coverage (R8) is file-level; users also want to know the *checks* that passed.
A report that shows its work is trusted more than a color.

**Design.** Each check family returns `evaluated: {rule: {files, hits}}` even at zero;
print a `Checks run:` summary; cap the JSON size on large repos. Start with the top 10
rules, not all of them.

**Acceptance.** `control-clean` lists the rules evaluated with zero hits; the JSON grows
by a bounded amount on a 100k-file repo.

**Risk.** Touches every check; do it incrementally via the R4 registry.

## U16 — Report freshness policy · 4 · S

**What.** `verify --max-age 30d` → exit 2; badge text shows scan age.

**Why.** A signed report can be months old while HEAD is unchanged; freshness is part of
the claim, and stale must never read as valid.

**Design.** Parse the scan timestamp from `meta`; default unlimited for compatibility;
print `scanned Nd ago` in the badge and `verify` output.

**Acceptance.** A 40-day-old report with `--max-age 30d` exits 2; a current one exits 0.

**Risk.** None; additive.

## U17 — `explain` with real-world examples · 4 · S

**What.** `repobeagle explain <rule>`: severity, meaning, remediation, and up to three
real positive examples from the precision corpus (R7) as `repo@sha:file:line`.

**Why.** Rule ids appear in issues and PR comments with no teaching material; examples
make a rule actionable for contributors and reviewers.

**Design.** Generated from the R4 registry and the corpus index; unknown id exits 2.

**Acceptance.** Every documented rule id resolves; examples link to the exact line.

**Risk.** Depends on the corpus; fall back to fixture examples.

## Pass 5 — update review, evidence quality, and org scale

These target what passes 1–4 leave open: reviewing a *change* rather than a snapshot, proving
*how* a finding was established, and the unit a security team actually buys (the org).

| ID | Feature | Axis | Impact | Effort | Depends on |
|---|---|---|---|---|---|
| U18 | `repobeagle diff repo@tagA repo@tagB` version review | Ease, trust | 7 | M | R5 |
| T13 | Workflow data-flow analysis (expressions into `run:`/`uses:`) | Robustness | 6 | M | U3 |
| U19 | `repobeagle org <owner>` fleet scan | Reach, ease | 6 | M | R12, R13, R1 |
| T14 | Compliance mapping (GDPR / CCPA / SOC2 evidence) | Reach (enterprise) | 6 | M | U1 |
| T15 | Evidence tiers on findings (`static`/`manifest`/`api`/`trace`) | Trust | 6 | M | R4, T6 |
| T16 | Signed policy waivers | Trust | 5 | M | U8, U16 |
| U20 | Watch subscriptions (webhook/RSS on verdict change) | Reach | 5 | M | T1, T10 |

## U18 — Version-to-version review · 7 · M

**What.** `repobeagle diff github.com/o/r@v1.2 github.com/o/r@v1.3`: scan both refs and report
only what changed — new network hosts, new permissions, new install hooks, new subprocesses,
new findings, and anything removed.

**Why.** Agent skills and MCP servers update silently under a stable name; the dangerous
change is the diff, not either snapshot. The report format has no concept of a baseline (R1),
and refs are not selectable yet (R5). This is the review that a user should run before
`git pull`-equivalent for a tool they already trust.

**Design.** Reuse R5 refs and R1 matching; emit a change-classified report (`added`,
`removed`, `changed`) over findings *and* the T5 capability map; exit 1 on new additions at
or above `--min-severity`. `--json` keeps both sides' metadata.

**Acceptance.** Between two fixture tags, a newly added `curl|sh` and a new third-party host
appear as additions exactly once; unchanged refs produce an empty diff and exit 0.

**Risk.** Renamed files shift line numbers; match on `(rule, path-without-line)` and state
when a path moved.

## T13 — Workflow data-flow analysis · 6 · M

**What.** Resolve `env:`, `matrix:`, `inputs:` and step outputs into `run:` and `uses:`
references, so `uses: ${{ matrix.action }}` and `run: ${{ inputs.cmd }}` are judged on their
possible values; flag secrets interpolated into third-party actions or shell strings.

**Why.** The `gha-*` checks match text. A workflow can build an unpinned action name from a
matrix, or pass `${{ secrets.NPM_TOKEN }}` to a third-party action, and the literal scan sees
nothing. Workflows are the highest-privilege surface most repos have.

**Design.** Parse YAML, build the expression→values map for the trigger's matrix/inputs,
expand only when the value set is finite; emit `gha-expression-unpinned` (low/medium),
`gha-secret-to-third-party` (medium), `gha-secret-in-run` (info). Never evaluate arbitrary
expression functions — unknown means "assume worst" with an explicit note.

**Acceptance.** A matrix-built `uses:` with one unpinned entry fires; a pinned matrix does
not; a secret passed to `actions/checkout` stays quiet.

**Risk.** YAML anchors/`!` tags and complex expressions; keep the expansion bounded and
degrade to today's literal behavior.

## U19 — `repobeagle org <owner>` fleet scan · 6 · M

**What.** Enumerate an owner's repos (token-scoped), scan all, rank by severity-weighted
findings and verdicts, output JSON/CSV, incremental by SHA.

**Why.** Security teams adopt tools per-organization, not per-repo; T8 indexes *public
popular* repos, not *your* repos. One command produces the board a reviewer actually needs.

**Design.** `--jobs` from R12, cache from R13, baseline gate from R1 to report only new risk
since the last run; private repos require `BEAGLE_GITHUB_TOKEN` and never leave the host
except as the same OSV/GitHub calls a single scan makes.

**Acceptance.** Against a test org with 3 repos, the output is complete and ordered; a repo
added mid-run appears as `unknown`, never omitted silently; a second run with `--since`
reports deltas only.

**Risk.** API rate limits and runner minutes; require a token, paginate explicitly, cap the
repo count with a visible note.

## T14 — Compliance mapping · 6 · M

**What.** Map privacy findings to control references: GDPR Art. 5/6/13/30/44 (lawfulness,
notice, records, transfers), CCPA opt-out and disclosure duties, SOC2 CC6/CC7 evidence.

**Why.** `repobeagle privacy` already produces the raw facts privacy officers need (vendors,
consent, retention, PII in logs, cross-border hosts); they are expressed in engineer terms.
A static mapping turns the same JSON into an audit appendix — the cheapest enterprise
differentiator available.

**Design.** A data file `rules/compliance.yml` mapping `rule → [{framework, control, note}]`,
rendered by `repobeagle compliance [--framework gdpr]`; it never invents evidence — a
control is `met` only when a positive signal exists (e.g. `consent-manager`), `unmet` when
the corresponding risk rule fires, `unknown` otherwise.

**Acceptance.** The trap-privacy fixture yields a report where each mapped control has a
state and cites `file:line`; an unmapped rule is listed, not silently dropped.

**Risk.** Editorial: keep the mapping short, cite article/control numbers, mark it "signals,
not legal advice".

## T15 — Evidence tiers on findings · 6 · M

**What.** Add `evidence: static | manifest | dependency | api | trace` to every finding, and
`--require-evidence` to gate a verdict on the strongest tier present.

**Why.** Two findings look identical today although one is a regex hit in a comment and the
other was confirmed by a traced `connect()`. Honest confidence is the difference between a
scanner and a linter, and it lets T6 integrate without a schema fork.

**Design.** Default `static`; `manifest` for lockfile-derived telemetry, `dependency` for
OSV/GuardDog, `api` for trust/provenance, `trace` for T6. Publish the field in the JSON
schema and count it in `meta`; `verify` rejects reports whose declared tier is unsupported
by the tool version.

**Acceptance.** `--json` findings carry a tier; `--require-evidence trace` on a static-only
report returns a clear "insufficient evidence" rather than RED.

**Risk.** Consumers keying on findings are unaffected (additive), but the verdict semantics
of `--require-evidence` must be documented once.

## T16 — Signed policy waivers · 5 · M

**What.** A `.repobeagle-policy.json` listing accepted rule ids with rationale, signed by a
reviewer (cosign keyless or a key), verifiable by downstream consumers and by `verify`.

**Why.** U8 gives suppressions reasons and expiry but no signature: anyone with commit
access can silence a rule, and a badge reader cannot see who accepted what. For org use,
"accepted by a known reviewer" is the missing attestation layer on top of the signed report.

**Design.** Reuse the `verify` identity mechanism (`--identity-regexp`) for waiver
signatures; `meta.waivers` in the report, `suppressed` findings keep both reason and signer;
unsigned waivers work locally and degrade to `unattested` in badges.

**Acceptance.** A waiver signed by a non-allowlisted identity fails verification with a clear
message; an expired waiver (U16 semantics) re-activates its finding.

**Risk.** Key distribution/rotation; keep the unsigned path identical for single developers.

## U20 — Watch subscriptions · 5 · M

**What.** Subscribe a repo to verdict-change notifications (webhook, RSS/JSON feed, Slack)
via T1; notify only on transitions (GREEN→YELLOW, YELLOW→RED, new rule hits), never on a
re-scan of an unchanged SHA.

**Why.** A security signal that requires visiting a URL is not a signal. Maintainers can show
monitoring, and downstream consumers get an event instead of polling. It also converts the
public index (T8) from a static list into a live feed.

**Design.** Server-side subscriptions keyed by `(repo, channel)`; the change detector is T10
diff logic; signed payloads so receivers can verify; unsubscribe link in every message.

**Acceptance.** A fixture repo moved from clean to a `curl|sh` triggers exactly one webhook
with the added findings and a verifiable signature; re-scanning the same SHA sends nothing.

**Risk.** Notification fatigue; transitions only, and per-repo throttling.

## Pass 6 — reproducible builds, tiered speed, and team routing

Small, high-confidence additions; the backlog is now near saturation (see the note at the
end of this section).

| ID | Feature | Axis | Impact | Effort | Depends on |
|---|---|---|---|---|---|
| R17 | Pin and attest the scanner build; record tool versions | Robustness | 7 | S–M | R2 |
| T17 | Opt-in AI triage per finding (advisory, cited) | Precision | 7 | M | — |
| U21 | `--fast` tier with declared reduced scope | Ease, speed | 6 | S–M | R4 |
| U22 | `repobeagle hook install` (pre-commit scan of the staged diff) | Ease | 5 | S | U5 |
| R18 | Owner routing from CODEOWNERS | Usability | 5 | S | R4 |

## R17 — Pin and attest the scanner build · 7 · S–M

**What.** Pin `python:3.12-slim` by digest and `semgrep`/`guarddog`/`bandit` via a
constraints file (or hashed requirements); record the resolved versions of every scanner in
`meta.tools` (name, version, findings, seconds, ok).

**Why.** `Dockerfile` runs `pip install --no-cache-dir semgrep guarddog bandit` unpinned and
starts from a floating base image, while `image.yml` rebuilds weekly. Reports therefore
depend on the build date, not just the commit — which weakens the strongest claim in the
README ("anyone can re-run the pinned image on the same commit and diff the findings"). A
report also cannot currently prove which scanner version produced a finding.

**Design.** Constraints file committed and hashed; `--build-local` uses the same; version
strings captured at build time into a file the image reads, so `meta.tools.*.version` is
factual. Pair with R6 so a scan is reproducible on `(sha, image digest, osv db date)`.

**Acceptance.** Two builds of the same commit report identical scanner versions; bumping a
constraint changes `meta.tools` and the image digest; `verify` warns when a report's
scanner versions are older than the current image.

**Risk.** Pinned scanners stop receiving rule updates — the weekly rebuild remains the
deliberate update channel, now explicit in the digest.

## T17 — Opt-in AI triage per finding · 7 · M

**What.** With `BEAGLE_LLM_URL` set, ask the model to classify each top finding as
`real`/`benign`/`uncertain` with a one-line cited reason, stored as an advisory `ai` field
per finding; `--ai-demote` is the only mode that lets it lower the printed severity.

**Why.** Precision is the product risk, and the existing AI review only judges repo *intent*
from key files. Context-sensitive false positives (a `.env` mention in a comment, a security
tool's own regex) are exactly what a model can settle with the surrounding code — the top
recurring class of recent fix commits.

**Design.** Batch findings, send only redacted snippets plus the few surrounding lines;
`ai` never affects the signed verdict unless `--ai-demote`, and then the report records
`meta.ai_demoted` so `verify` can reject silent changes. Deterministic fallback: no model,
no annotations, same report.

**Acceptance.** A fixture with a comment-only `.env` reference is annotated `benign` with a
reason; the verdict is unchanged without `--ai-demote`; the JSON stays valid with the model
unreachable.

**Risk.** Non-determinism in a deliberately deterministic tool; keep it advisory and
clearly labeled.

## U21 — `--fast` tier · 6 · S–M

**What.** A declared-reduced scan: agent checks plus privacy/telemetry from text, no
semgrep/guarddog/bandit/OSV. `meta.tiers = {mode: fast, skipped: [...]}`, verdict labeled
`FAST` everywhere (report, JSON, badge).

**Why.** A full scan is minutes; the dev loop and U14's interceptor need seconds. Without a
tier, people install a weaker tool rather than wait.

**Design.** Reuse the existing `--privacy-only` skip machinery; forbid `--fast` in the badge
publishing workflow unless explicitly requested, so a public badge never claims full scope.

**Acceptance.** `--fast` on a fixture finishes in seconds and names every skipped stage;
`verify` rejects a report whose `tiers.mode` is fast but whose badge lacks the label.

**Risk.** Users read FAST/GREEN as safe; the label must be unmissable and documented.

## U22 — `hook install` · 5 · S

**What.** `repobeagle hook install` writes a `.git/hooks/pre-commit` that scans the staged
diff (`U5` scope) and blocks new findings at or above `--min-severity high`; `--uninstall`
removes only our block.

**Why.** The scan exists at three points: badge CI (after the fact), the CLI (on demand), and
nothing at commit time. The third is the cheapest habit change and reuses U5 as-is.

**Design.** Marker-delimited block appended to an existing hook; fail-open on missing image
with a one-line notice, never silently skip; `--no-docker` respected.

**Acceptance.** A staged `curl|sh` blocks the commit once; unstaged changes do not; a
pre-existing hook still runs; `--uninstall` restores it byte-for-byte.

**Risk.** Hooks are local and skippable (`--no-verify`); pair with CI, don't rely on it.

## R18 — Owner routing from CODEOWNERS · 5 · S

**What.** Attach `owner` to findings using the repo's `CODEOWNERS` patterns and add
`--group-by owner` / `--only-owner`, plus per-owner summaries in JSON.

**Why.** Findings already exclude `CODEOWNERS`/`AUTHORS` from prose checks, so the file is
parsed anyway; without routing, a 40-finding report is a single undifferentiated list for a
team. This is the cheapest way to make the report act like a ticket queue.

**Design.** Last-match-wins semantics as GitHub implements them; unmatched findings get
`unowned`; never guess an owner from git blame (history is shallow).

**Acceptance.** A fixture CODEOWNERS routes a finding to the right pattern; a malformed file
degrades to `unowned` with a note, not a crash.

**Risk.** Pattern semantics differ subtly from GitHub; document the subset implemented.

**Saturation note.** With these, every axis has a concrete first move. Further ideas now
score ≤4 because they either refine an entry above or add surface without changing a
decision; the constraint is execution, not ideation.

## Pass 7 — closing the loops the earlier passes opened

Pass 6 claimed saturation. These four are exceptions because each one makes an existing
claim *checkable* rather than adding surface: rule stability for consumers, determinism for
signed reports, external attestations for the verifier role, and the already-installed
packages.

| ID | Feature | Axis | Impact | Effort | Depends on |
|---|---|---|---|---|---|
| R19 | Ruleset versioning, changelog and compatibility policy | Robustness, trust | 6 | S–M | R4 |
| T18 | External attestation ingestion (Scorecard, SLSA, deps.dev) | Trust | 6 | M | T1 |
| R20 | Determinism test (same fixture twice, amd64 + arm64) | Robustness | 5 | S | R3 |
| U23 | `repobeagle audit --installed` | Reach, ease | 5 | M | R12, R13 |

## R19 — Ruleset versioning and compatibility policy · 6 · S–M

**What.** A semver `meta.ruleset_version`, a generated `RULES.md` (id, severity, since,
changed) and `CHANGELOG-rules.md`; `verify` rejects reports whose major ruleset version is
incompatible with the consumer.

**Why.** `meta.ruleset` is a 12-character digest: it proves reports came from different rule
sets, but not *how* they differ. Every downstream feature (R1 baselines, T10 trend, U1
overrides, T15 tiers) matches on rule ids whose semantics can change silently.

**Design.** Derive the version from the registry (R4) with an explicit major bump for
rename/removal/severity change, generated from the rule files in CI rather than
hand-maintained; `rules lint` fails a breaking change without the bump.

**Acceptance.** Renaming a rule id without a major bump fails lint; an incompatible old
report is rejected with a message naming the change.

**Risk.** Discipline decays; generation plus CI enforcement is the mitigation.

## T18 — External attestation ingestion · 6 · M

**What.** `--attest` pulls OpenSSF Scorecard, SLSA provenance and deps.dev signals as `info`
findings and a `signals` block, and flags `attestation-disagreement` when an independent
source materially disagrees with the local verdict.

**Why.** No single static scanner is authoritative. `verify` already establishes trust in a
*signed report*; the same primitive lets RepoBeagle act as an aggregator instead of a 58th
opinion. Disagreement is the most useful triage signal a verifier can emit.

**Design.** Timeouts, cache, degrade to a note; external scores never raise the local verdict
on their own. Every external datum carries `source` + retrieval date so it cannot be mistaken
for a local finding.

**Acceptance.** A mocked GREEN Scorecard for a local-YELLOW fixture yields one disagreement
finding; an offline run records the skip and keeps the verdict; a stale external result is
dated.

**Risk.** Score semantics differ across sources; keep them unopinionated and never silently
weighted.

## R20 — Determinism test · 5 · S

**What.** CI scans one fixture twice in the same image and once per architecture, asserting
identical findings and verdict after normalizing timings, temp paths and ordering.

**Why.** Determinism is what makes a signed report meaningful and `verify --rescan` (R5)
possible. One dict iteration order or locale-dependent regex silently breaks it, and nothing
currently tests it.

**Design.** Hash the normalized `findings` list; run in the existing image test job; fail
loudly with a diff of the two reports.

**Acceptance.** Two runs hash-equal; a deliberately injected unordered iteration is caught;
amd64 and arm64 agree.

**Risk.** Flaky timings — normalize, never loosen the comparison.

## U23 — `audit --installed` · 5 · M

**What.** Enumerate packages already installed on the machine (npm project and global, pip,
cargo) whose source repository is known, batch-scan them (R12/R13) and report RED/YELLOW
ones; `--stale` flags installed versions that lag behind the release being scanned (T11).

**Why.** The tool currently answers "should I install this?"; the user's actual exposure is
what is already on disk. It is also a naturally shareable result: the first scan that
touches a user's own environment with no input.

**Design.** Read `package.json`/lockfiles, `node_modules/*/package.json`, `pip list
--format=json`, `cargo metadata`; never execute package code; cap the list and report the
cap.

**Acceptance.** An installed vulnerable/known-bad package appears by name and version; a
clean environment exits 0 with the scanned count.

**Risk.** Environment parsing variance; degrade per ecosystem with a note rather than failing.

## Built since the backlog was written

- **U16 — done.** `verify --max-age 30d` exits 2 when the signed report is older than the
  policy (even with an unchanged HEAD), and a report without `meta.scanned_at` is stale
  under a policy; the default stays unlimited. `verify` prints the scan age, and the badge
  endpoint/SVG append it (`YELLOW · 40d`) when the report records one.

- **T12 — done.** Every report carries `meta.checks`, a rule-level evidence ledger for the
  top ten high-signal rules (evaluated/files/hits/suppressed plus the negative assertion a
  zero-hit result proves), printed as `Checks run:`. Counters only, so the JSON growth is
  bounded (tested with 100k files); incomplete scans mark the assertions unproven. The
  documented rules link to the R4 registry.

- **T11 — done.** `repobeagle release <owner/repo>` resolves the release tag, loads the
  registry artifact (npm/PyPI/crates, or offline overrides), and compares semantics:
  install hooks, dependency sets/ranges, name/version and a file inventory. `release-drift`
  is high for an added hook/dependency or a version mismatch and the finding names the
  exact delta; provenance presence is reported as `release-provenance`/`no-provenance`.
  The fixture pair (identical artifact vs one with an injected `postinstall` and extra
  dependency) proves both directions offline; a live npm run on `expressjs/express`
  resolves v5.3.0 and its attestations.

- **R7 — done.** `tools/scoreboard.py` measures per-rule precision on a SHA-pinned honest
  cohort (`tests/corpus.yml`, 12 popular repositories) against a committed
  `tests/corpus-baseline.json` budget (median findings + per-rule honest hits + verdicts),
  and detection on the labeled trap-fixture cohort (every expected rule/verdict). The
  nightly `corpus.yml` publishes the scoreboard as a job summary/artifact and fails on
  regression; OSV/trust are disabled so runs are comparable. Offline tests cover the gate
  and both detection failure modes.

- **R4 — done.** The scanner is split into `repobeagle/{core,fetch,report,scanners,cli,
  service,app,index}.py` plus `repobeagle/rules/{agent,privacy,registry}.py`; `repobeagle.py`
  is a shim. Findings carry their `rule` id (no title surgery; `_rule_of` reads the field),
  the explicit `Rule(id, severity, meaning, remediation, docs)` registry is generated from
  the README rule table and checked by `tests/test_registry.py`, and
  `tests/test_snapshots.py` compares byte-stable normalized reports for ten fixtures. The
  package split was verified byte-identical against goldens captured from the previous
  single module, then the additive `rule` field was added to the snapshots.

- **T8 — done.** `repobeagle index` resolves a curated list, skips SHAs that already have
  a signed result, scans with `--jobs` parallel workers in the pinned image, and writes
  `results/<owner>/<repo>@<sha>.json` plus a searchable self-contained `index.html` and
  per-repository pages. `index.yml` signs each report keyless (`index.yml` identity added
  to `verify`'s allowlist), verifies every published report before deploying to GitHub
  Pages, and persists the result history on the `index` branch. Acceptance: 1000-entry cap
  and 20 workers fit the 4 h workflow timeout; every page links its signed report.

- **T2 — done.** `repobeagle app` is the GitHub App webhook server: signature-verified
  `pull_request`/default-branch `push` deliveries are queued (GitHub's 10 s timeout) and
  scanned with the ordinary `scan` CLI, PRs with `--since <base>` (changed files only).
  It maintains exactly one PR comment (marker lookup + PATCH, so a replayed delivery edits
  instead of duplicating) and one check run per commit (created or PATCHed by
  `(sha, name)`), with RED→failure / YELLOW→neutral / GREEN→success and an explicit
  failing check when the scan itself fails. `tests/test_app.py` drives real HMAC-signed
  webhooks against a stub GitHub API: comment/check dedupe, new-tree updates, push and
  non-default-push handling, unknown repos, bad signatures and App JWT generation.
  Installing the App is the only manual step; permissions are documented in the README.

- **T1 — done.** `repobeagle serve` hosts the attestation API: `GET
  /v1/scan/<owner>/<repo>[/<ref>]` scans once per resolved commit (pinned image when
  Docker is available, in-process otherwise) and serves the immutable bytes from a disk
  cache, `/bundle` serves the Sigstore bundle, `/o/<owner>/<repo>` renders the HTML
  report. Per-IP request and per-repo scan budgets answer 429 with `Retry-After`;
  `--sign` signs keyless under GitHub OIDC (or `--key`), unsigned reports are labeled in
  `meta.service.signed` and the headers. The report carries the provenance `verify`
  needs (`meta.scanned_repo`, `meta.scanned_sha`), and `verify`'s default identity now
  accepts the `service.yml` workflow. Acceptance: `.github/workflows/service.yml` starts
  the service with id-token, fetches a scan + bundle, verifies them with `repobeagle
  verify`, repeats the request for byte-identical cache output and proves the 429 path;
  `tests/test_serve.py` covers cache immutability/corruption, budgets, routes and hostile
  paths offline.

- **T10 — done.** `repobeagle trend <owner/repo|report-dir|report.json…>` reads the
  `report-<sha>.json` files the scan workflow already publishes and prints the ordered
  verdict series, the first RED, per-rule regressions (first seen after a report without
  them), the current streak and a reason for every skipped report. Ordering and timestamps
  come from the badge-branch commits (or `meta.scanned_at`/mtime for local files); reports
  from another `meta.ruleset`/`version` than the newest are skipped. Malformed JSON is a
  skip, never a crash. `tests/test_trend.py` asserts the ordering, the regressions, the
  streak and both skip paths against `tests/fixtures/trend`.

- **R6 — done.** `repobeagle db [--update] [dir]` shows or downloads the OSV offline databases
  (osv-scanner's own cache), and `scan --offline-vulnerabilities` runs without any network
  call while recording `meta.osv_db{path,updated,bytes}`. Verified offline against a
  requirements file: `flask==2.0.0` → `Vulnerable dependency: flask@2.0.0` from the local DB;
  the suite asserts status output and the meta wiring without requiring a download.
- **U9 — done.** Findings with a mechanical fix carry `remediation` (JSON, SARIF
  properties), a `fix:` line in the report and a Fix column in the Markdown export. The
  table is deliberately narrow (pin to SHA, cookie flags, `pull_request`,
  `--ignore-scripts`, TLS, consent gating, coverage); rules without an obvious single action
  carry none instead of generic advice. Tests assert both JSON and printed output.
- **U5 — done.** `scan --since <rev>` diffs against that revision, materializes only the
  changed paths plus root manifests/`.repobeagleignore` for context, and records
  `meta.scope{changed_files, listed_files, checked_out}`; the report prints a `scope:` line so
  a diff verdict is never mistaken for a full one. Verified on `requests` v2.32.2→v2.32.3:
  3 changed files, 5 materialized of 131 listed, full findings pipeline unchanged.
- **R5 (ref pinning half) — done.** `scan --ref <branch|tag|sha>` fetches that exact
  object with the same blobless/sparse pipeline, records `meta.ref` and the resolved
  `meta.commit`, and rejects `--ref` on a local directory with a clear message. Verified on
  `psf/requests@v2.32.3` → commit `0e322af…`, suite covers both paths. Remaining:
  `verify --rescan` (re-run the report's image on its commit and diff) and a `--ref` pass-through
  for `map`.
- **R8 — done.** `meta.coverage` in every report (source bytes inspected, skipped reasons,
  unscanned extensions), a printed `Coverage:` line, and a `coverage-low` finding below 60%
  on repos with ≥20 files. Tests assert the accounting arithmetic and that the finding fires
  for a tree dominated by an oversize file.
- **T7 — done.** `repobeagle web <url>` fetches a page once (http/https/file, 2 MB cap,
  optional same-origin assets), treats its own host as first-party via a synthetic CNAME in
  the temp tree, and runs the existing privacy rules through the normal scan path, so
  redaction, privacy summary, capabilities and SARIF/JSON consumers all work unchanged.
  Reports are labeled `meta.mode = web`. Offline test uses `file://` on the privacy fixture.
- **T5 — done.** `repobeagle map <target>` and `meta.capabilities` in every report: hosts,
  secret paths, subprocesses, env vars and client storage gathered by a dedicated offline
  regex pass, rendered together with install hooks, permission scopes and telemetry vendors
  from the findings, each with `file:line`. Tested on `trap-npm`. T6 (`--trace`) can now
  attach `verified: true` to these same entries.
- **T4 — done.** `repobeagle mcp` is a stdio MCP server (JSON-RPC 2.0, one message per
  line) exposing `scan_repo`, `verify_badge` and `explain_report` with input schemas. It
  runs scans through the same CLI/image path, keeps the last 20 reports under
  `$XDG_CACHE_HOME/repobeagle/mcp`, and logs to stderr only. Tests drive initialize,
  tools/list, a real scan (verdict RED), an unknown tool and ping. It echoes the client's
  `protocolVersion`; so far exercised with a synthetic client, not a vendor SDK.
- **T3 (SARIF + Markdown core) — done.** `repobeagle export <report.json> --format
  sarif|markdown|json` maps findings to SARIF 2.1.0 (levels, locations, stable
  `partialFingerprints`, explicit suppressions) and to a PR-comment table. The output validates
  against the official SARIF 2.1.0 schema with zero errors; `scan.yml` gained an opt-in
  `upload-sarif` input that publishes to GitHub code scanning. The format switch lives on
  `export` rather than on `scan` (a report stays the single source of truth).
- **R1 (diff gate core) — done.** `repobeagle diff old.json new.json` matches on rule id + file
  (line moves and re-indentation are not changes), prints added/removed, writes `--json`, and
  exits 1 only on added findings at/above `--min-severity` (default `medium`). Tests cover
  unchanged, gated, JSON and line-drift cases. Remaining: a `scan --baseline <report>` convenience
  and wiring the badge branch's last report as the default baseline in `scan.yml`.
- **U10 (transparency half) — done.** `repobeagle explain <report.json>` prints the profile
  thresholds, which one was met, the margin to the next tier and the largest rule
  contributors; pure JSON read, no scan, no network. Tests: suite asserts `decision: RED`,
  `to leave RED`, and exit 1 for a missing report. The triage planner (`--accept`) remains.
- **R3 (offline half) — done.** `.github/workflows/ci.yml` runs `py_compile`, a
  syntax/undefined-name lint (`E9,F63,F7,F82`) and `tests/run_tests.sh --offline` on every
  push and PR. Fuzzing, `mypy` and per-rule positive/negative fixture enforcement remain.
- **R20 (same-host half) — done.** The suite now scans one fixture twice and asserts
  identical findings. The amd64/arm64 comparison still needs an ARM runner.
- **R2 — done.** `install.sh` pins gitleaks 8.30.1, osv-scanner 2.7.0 and cosign 3.1.3 and
  verifies every download against `checksums.txt`; an artifact with no checksum entry is
  refused. `image.yml` keyless-signs the pushed image by digest and the installer verifies
  that signature (`BEAGLE_REQUIRE_SIGNATURE=1` to make it fatal; tags published before this
  change only warn). Verified locally: tampered checksum aborts before installing, a clean
  install verifies both artifacts, and the suite still passes.
- **R17 — done.** The image pins the base by multi-arch digest and the scanners in
  `constraints.txt` (semgrep 1.187.0, guarddog 3.2.0, bandit 1.9.4); `meta.tools` now
  records each scanner's resolved version. Verified by building the image and running the
  `trap-npm` fixture: still RED, and `meta.tools` reports exactly those versions. Transitive
  pip dependencies still float — a full lock is the remaining increment.

## Build order

**Phase 0 — make the claims true (1–2 weeks).** R4 → R3 → R2. Exit: CI enforces the
suite, fuzz and types; every downloaded artifact is checksum-verified; the image is
consumed by digest.

**Phase 1 — CI-native (2 weeks).** R1, T3, U5, U4. Exit: a stranger can gate a PR on new
findings and read them inline; install works without Docker.

**Phase 2 — understandable and actionable (3 weeks).** R8, T5, U9, U6, T6. Exit: the
report states what it did not inspect, what the repo can do, and what to change — and can
change it.

**Phase 2.5 — interception (1–2 weeks).** U7, R13, U14, R14, T11. Exit: `repobeagle
run -- npx …` scans before it executes, archives are actually inspected, and a published
package's contents are compared to its tag.

**Phase 3 — reach (4+ weeks).** T4, T1, T10, T8, T2. Exit: a third-party attested
verdict is one MCP call, one chat message or one URL away.

**Phase 4 — depth as capacity allows.** R5, R6, R7, R9–R13, U1–U3, U10–U13.

**Pass 5 follows its dependencies, not a phase:** R5 → U18 (version review); R4 → T15
(evidence tiers, then T6 emits `trace`); U3/R10 → T13 (workflow data flow); T8 → U19
(org fleet); U1 → T14 (compliance mapping); U8/U16 → T16 (signed waivers); T1/T10 → U20
(watch subscriptions).

**Pass 6:** R17 joins Phase 0 (reproducibility is a claim, not a feature); U21/U22 join Phase
2.5; T17 joins Phase 2; R18 joins Phase 4.

**Pass 7:** R19 and R20 join Phase 0 with R4/R3; T18 joins Phase 3 with T1; U23 joins Phase
4 with R12/R13.

## Not doing

Browser extension (the hosted page covers discovery), more vendor names (diminishing
returns vs R7), git-history scanning (the shallow clone is a feature), rule-level
localization.

## Open questions

- Hosting: who pays, and is the service identity separate from the workflow identity in
  `verify`'s default allowlist?
- `U1` vs `U2` precedence needs a written rule before either ships.
- Is `--trace` acceptable to users who chose RepoBeagle precisely for "never runs code"?
  It must stay opt-in and visibly labeled.
