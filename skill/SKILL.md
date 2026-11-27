---
name: repobeagle
description: Static safety gate for untrusted repositories, packages, MCP servers and agent skills — when to scan, how to read the verdict, and how to present it.
---
# RepoBeagle

Answer one question before touching someone else's code: **is this safe enough to run?**
RepoBeagle is static: by default it never executes repository code. It reports findings with
`severity`, `rule`, `file:line`, `meaning` and a `remediation`, a `verdict` (GREEN/YELLOW/RED),
and the `meta` facts you need to judge how much the verdict covers.

## When to use it

- Before `git clone`, `npm install`, `pip install`, `cargo add`, or running a script from a repository you did not write.
- Before enabling an MCP server, agent skill, plugin or agent config copied from a catalog or README.
- When a pull request adds or bumps a dependency (baseline the report; fail only on new findings).
- When the user asks "is this repo/skill/package safe?" — answer with evidence, not vibes.
- When a downloaded zip/tarball or GitHub release asset will be unpacked or executed (`repobeagle scan <archive>`, `--release-assets`).

## When not to, and limits

- Trusted first-party code, or a huge monorepo under a deadline: use the fast metadata triage (`head`) and say that it is triage.
- A GREEN verdict is **evidence, not proof**: static analysis cannot see runtime-only payloads; `head` and partial reports are explicitly narrower.
- No Docker and no host tools? `scan` degrades with notes; still report the skipped tools rather than implying a full scan.

## Install

- Hardened image (recommended): `./install.sh`; light mode: `pipx install .` (see the project README). Pin the same release tag as this skill.
- MCP host: `skill/mcp.json` registers `repobeagle mcp` (stdio JSON-RPC: `scan_repo`, `verify_badge`, `explain_report`).

## Decision recipes

| Situation | Command | If it is not GREEN |
|---|---|---|
| Unknown repo, triage | `repobeagle head <owner/repo> --json report.json` | RED: do not clone/run; YELLOW: read the findings first |
| Before running/installing | `repobeagle scan <url\|dir> --json report.json` | RED: stop; quote the critical/high findings and the fix |
| A package runner is about to fetch code | `repobeagle run -- npx -y <pkg>` | RED refuses automatically; YELLOW prompts (CI needs `--yes`/`--force`) |
| Registry/catalog listing | `repobeagle gate entries.txt` / `repobeagle batch entries.txt` | new RED fails; `unknown` entries were not verified |
| A published badge/report | `repobeagle verify <owner/repo>` | signature invalid or stale: do not trust the colour |
| What does this rule id mean? | `repobeagle explain <rule>` | severity, meaning, remediation and corpus examples with exact lines |
| Existing report, what if I accept X | `repobeagle explain report.json --accept RULE` | shows the verdict after accepting; `--write` records it with a reason |
| A tool updates silently under the same name | `repobeagle diff <url>@v1 <url>@v2` | scans both refs; new hosts/hooks/findings, renames as moves |
| Dependency change vs yesterday | `repobeagle diff old.json new.json` | fails on added findings; use `scan --baseline old.json` for one step |
| Is it getting safer or riskier? | `repobeagle trend <owner/repo>` | ordered verdicts, first RED, per-rule regressions and the current streak; never re-scans |
| Is a popular repo already scanned? | `repobeagle index --out public` | static index with signed reports; refresh by SHA, parallel scans |
| Every PR should get a verdict automatically | `repobeagle app --port 8080` | one updated comment + check run per commit; no PR code executed |
| Did the published package come from this repo? | `repobeagle release <owner/repo>` | compares the registry artifact's hooks/deps with the tag; flags `no-provenance` |
| Serving verdicts to other people/agents | `repobeagle serve --port 8080` | immutable per-commit reports, 429 budgets, optional signing; `--root` serves local dirs |
| Unpacking an archive/asset | `repobeagle scan bundle.zip` | same verdict rules; `meta.archive` says what was expanded |

## Reading a result

| Result | Meaning |
|---|---|
| exit 0 / GREEN | findings at or below the profile threshold — proceed, but state the scope and that it is evidence, not proof |
| exit 1 / YELLOW | findings worth a look — read them; proceed only if the user accepts the remaining ones |
| exit 2 / RED | at least one critical (or high under `--strict`) — do not run until the remediation is applied or the risk is accepted |
| `meta.complete: false` | the scan hit `--max-seconds`; **never present it as GREEN**; it is a partial report |
| `meta.scope.mode: metadata` | `head` triage: no clone, no scanners; a GREEN here is not a full-repo verdict |
| `meta.scope.mode: changed` | diff verdict covering only changed files since a revision |
| `tools.<name>.ok: false` / notes "skipped" | that scanner did not run; say which evidence is missing |
| `meta.cache: hit` | the analysis came from an identical tree/commit/image; still cite the report |
| `suppressed` findings | accepted with a reason and maybe an expiry date; they stay in the JSON |

## Field reference (JSON)

Findings: `tool`, `severity` (`critical|high|medium|low|info`), `rule` (stable id), `file`, `line`, `title`, `snippet` (redacted by default), `meaning`, `remediation`, optional `fixed_in`/`fixed_note` (OSV fix availability), `dependency_path`/`dependency_depth` (why a dependency is in the tree), `package`/`package_path` (monorepo attribution), suppression state.
Report: `verdict`, `why`, `counts`, `findings`, `notes`, `recommended_actions`, `meta.profile`, `meta.ruleset`, `meta.target`, `meta.commit`, `meta.scanned_at`, `meta.complete`, `meta.cache`, `meta.tools`, `meta.scope`, `meta.suppressed`, `meta.privacy_mode`, `meta.capabilities`, `meta.trace`, `meta.archive`, `meta.release_assets`, `meta.workspace`, `meta.scanned_repo`, `meta.scanned_sha`, `meta.service` (served reports: signed state and mode), `meta.checks` (rule-level evidence ledger: evaluated/files/hits/negative assertion for the top rules).
Use the JSON, not scraped prose, when you need to reason.

## Presenting it to the user

- Lead with the verdict and the exact evidence: severity, rule, `file:line`, one-sentence meaning, and the remediation.
- Say what was scanned (`meta.scope`, `meta.complete`) and which tools ran (`meta.tools`), and that GREEN is not a guarantee.
- Never paste a raw report; summarise and link/cite the report path or actions run URL.
- For a published badge, quote `verify`'s signature and freshness lines, not the colour alone.

## Closing the loop

- A wrong finding: `repobeagle feedback report.json --false-positive --rule RULE --file FILE[:LINE]` builds a prefilled, re-redacted GitHub issue URL.
- A missed rule: same command with `--miss`.
- Accepting a finding: `repobeagle ignore RULE --reason "why" [--until YYYY-MM-DD]` (never silence without a reason); `explain --write` records a decision interactively.
- Repo owners: `repobeagle init` adds the reusable scan workflow; `.repobeagle.yml` sets the repo's policy.

## Security and privacy

- Default scans never execute repository code; `--trace` is the only opt-in exception and runs just the install phase, under strace, in the hardened container.
- Snippets/titles are PII-redacted by default; `--no-redact` shows raw values; the cache keeps the same raw snippets locally (0600) and publishes nothing.
- The network is used only for the clone, OSV/trust lookups, `--release-assets`, `--trace` installs and the optional LLM review; everything else is offline.

## Recipes (CI-tested)

Every line below is executed in CI: the `{json}` placeholder is a temporary report path.

```bash
$ repobeagle --version
$ repobeagle head tests/fixtures/trap-gha --no-color --json {json}
$ repobeagle scan tests/fixtures/trap-gha --strict --no-docker --no-osv --no-trust --no-cache --no-color --json {json}
$ repobeagle explain {json} --target yellow
$ repobeagle gate tests/fixtures/gate/list.txt --no-cache --no-color
$ repobeagle run --repo tests/fixtures/control-clean --no-docker --no-osv --no-trust --no-cache --no-color -- python3 -c "print('ran')"
```
