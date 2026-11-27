# Contributing to RepoBeagle

Thanks for looking. This project has one job: tell someone whether an untrusted
repository can be trusted enough to run, without running it. Contributions that make a
verdict more accurate, more explainable, or harder to fool are welcome. Contributions that
only add surface are questioned — see `FEATURES.md` for the scored backlog and the issues
for what is actually planned.

## Be a decent human/agent

- Assume good faith. Critique the code, the fixture, the severity choice — never the person.
- No harassment, no gatekeeping, no "just read the docs" unless you link the paragraph.
- Disagreement is fine and expected; being rude is not. A maintainer will edit, lock or
  close a thread that stops being useful.
- Respect that a scanner has to choose severities for imperfect information. If you think a
  rule is wrong, bring a file that demonstrates it.

Short version: this project follows the spirit of the
[Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
Behave like a colleague.

## Before you start

- Browse the [issues](https://github.com/javierbits/repobeagle/issues): #1–#62 cover the
  scored backlog. Small bugs and typos can go straight to a PR; anything that changes a
  verdict, adds a rule, or changes the report schema should start as an issue.
- `FEATURES.md` is the design backlog with impact scores, effort and acceptance criteria.
  If you add a design entry, it needs a score and a Definition of Done, not a wish.
- Keep pull requests to one logical change. A rule, its fixtures and its docs are one
  change. A refactor mixed with a behaviour change is two.
- Contribution is **fork-based**: you push to your fork and open a PR from it. Your only
  direct write channel on this repository is commenting on issues, so claims are made by
  comment — do not expect to self-assign or apply labels.

## Claiming an issue (so two people don't work on the same thing)

Contributors work from forks and cannot assign themselves. The `issue-claim` workflow turns
a command comment into the claim: it assigns when GitHub permits, adds `status: claimed`,
and posts the window.

1. Comment on the issue. First line exactly `/claim`, then the scope and ETA:

   ```
   /claim
   scope: rules/android-permission in repobeagle.py + tests/fixtures/trap-privacy
   eta: 2026-11-30
   plan: add the maxSdkVersion downgrade; the fixture already has the manifest
   ```

2. The workflow replies with the claim confirmation. If assignment fails for your account,
   the label plus that comment are the authoritative claim — the bot does not depend on
   assignees.
3. Open a **draft PR from your fork** within **7 days** and link the issue (`Closes #12`).
   After **21 days** without activity the workflow releases the claim automatically;
   `/release` gives it back earlier. A maintainer can take over at any time, with a comment.
4. One claim per person for a first contribution, at most two concurrently afterwards. Need
   part of a claimed issue? Comment and take a named slice (files, functions, rule ids) that
   does not overlap another active claim. If overlap is unavoidable, the older claim goes
   first and the second PR waits, or the issue gets split.
5. Bots and agents claim the same way and must include the run or report link in the claim
   comment. Their claims expire on the same 7/21-day rule — nobody inherits a dead agent's
   claim.

Maintainers keep `status: blocked` for issues waiting on another issue, a PR or a decision;
`status: claimed` means hands off unless you coordinate.

## Fork workflow

```bash
gh repo fork javierbits/repobeagle --clone && cd repobeagle
git checkout -b feat/12-android-permission
# edit, test, then commit with a Conventional Commit message
git push -u origin feat/12-android-permission
gh pr create --fill --draft
```

Rules that keep the fork model boring:

- PRs come from your fork. Never push to a branch you do not own.
- Rebase on `main` instead of merging it into your branch; keep the PR history clean.
- `ci.yml` is read-only on fork PRs and needs no secret. Anything that writes (badge
  branch, commit status) only runs on the upstream reusable workflow.
- Do not merge your own PR; a maintainer does, after the checklist is complete.

## Ground rules for the code

These are non-negotiable because they *are* the product:

- **Never execute repository code.** Static analysis only. Fetching, `git`, and the
  scanners run in a read-only non-root container with `--network none`; the only opt-in
  exception is `--trace`, which runs the install phase inside that same container.
- **The scanner stays stdlib-only.** `repobeagle.py` (the shim) and the `repobeagle/` package must run on a bare `python3`. External
  tools (gitleaks, semgrep, guarddog, bandit, OSV) enter through the image and are invoked
  as subprocesses; a missing tool must degrade to a note, never a traceback.
- **Every finding is evidence**: a relative `file:line`, a stable `rule` id (the title
  prefix), a severity, and a one-sentence reason. No vague findings.
- **No verdict changes without a flag or a profile.** New detection is welcome; silently
  making honest repositories red is not.
- **Determinism.** Same input, same findings, same order. No locale-, time- or
  `dict`-order-dependent output. Timings live in `meta`, never in the verdict. The
  normalized core (`normalize_findings()` / `report_fingerprint()`) is what
  `arch.yml` and `verify --rescan` compare; adding a finding field means deciding
  whether it belongs there, and `tests/test_determinism.py` covers both directions.
- **Privacy by default.** Snippets and titles of privacy/telemetry findings are redacted
  (`redact_pii`). If you add a field that can contain PII, redact it or document why not.
- **Never extract archives, never follow symlinks** unless you are in `safe_extract`-style
  code that rejects absolute paths, `..`, symlinks and decompression bombs.
- **Offline in CI.** Network calls are limited to documented places: OSV (or its offline
  DB), the GitHub trust API, `web`, `verify`, and the optional LLM review. Don't add one
  without a flag or a skip note.
- **Additive report changes.** New `meta.*` or finding keys are fine; renaming or removing
  one is a breaking change and needs a `ruleset`/version note (see issue #60).

## Development setup

```bash
git clone https://github.com/javierbits/repobeagle && cd repobeagle
python3 repobeagle.py scan tests/fixtures/trap-npm   # works with no deps, no Docker
```

Optional, for the full pipeline:

```bash
./install.sh --build-local    # build the scanner image locally
./install.sh --local-tools    # gitleaks/semgrep/guarddog/bandit on the host (--no-docker)
```

Python 3.12 is what CI uses. There is no runtime package to install: the scanner is a
stdlib-only package (`repobeagle/`) with a thin `repobeagle.py` shim, deliberately.

## Tests and checks

Run these before opening a PR:

```bash
tests/run_tests.sh --offline     # fixtures only; must be green
tests/run_tests.sh               # also clones a few real repos; run when behaviour changed
python3 -m pip install -r requirements-dev.txt
mypy                             # mypy.ini covers repobeagle.py and tools; check_untyped_defs is on
python3 -m py_compile repobeagle.py tools/make_badge.py tests/test_*.py
ruff check --select E9,F63,F7,F82 repobeagle.py tools tests/*.py
```

`.github/workflows/ci.yml` runs the same compile/lint/mypy/offline steps on push and PRs.
`tests/run_tests.sh --offline` also runs `tests/test_rule_fixtures.py` (every declared rule
must fire on its trap fixture and stay silent on `control-clean`) and the bounded
`tests/test_fuzz.py` targets (skipped with a note when hypothesis is not installed).
`.github/workflows/nightly.yml` runs the online corpus on a schedule; it can be red
without blocking a PR.

Adding a rule or detection requires **two fixtures**: one that fires it and one that must
not. Put them under `tests/fixtures/` and assert the rule id in `tests/run_tests.sh` — the
suite already asserts rule ids, not just verdicts. If a legitimate repository would trip
your rule, add a `.repobeagleignore` example or narrow the pattern instead of lowering the
severity.

Known gaps, tracked as issues: no enforced formatter (#5, the syntax lint catches errors,
not style).

## Commit messages: Conventional Commits are required

This repository uses [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).
Every commit on `main` must follow it, and PR titles must too:

```
<type>(<scope>): <imperative subject, max 72 chars>
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`.
Scopes used here: `privacy`, `cli`, `verify`, `update`, `image`, `deps`, `docs`, `tests`.
Use a breaking-change marker (`feat(cli)!:`) when a flag, report key or rule id changes
incompatibly.

Real examples from this repository's history:

```
feat(privacy): transitive lockfile matches for analytics vendors
fix(privacy): history capability needs a real history use
feat(verify): reject reports whose verdict/counts mismatch findings
feat(cli): --version and self-update checks
```

- Subject in the imperative mood, no trailing period, one logical change per commit.
- The body explains *why* and what was measured, not a restatement of the diff.
- Squash WIP commits. Don't mix refactors with behaviour changes.
- Leave the `VERSION` file to maintainers unless your PR is the release itself: the image
  tag and checksums are pinned to it.

## Pull requests

- Use the PR template; every checkbox is meant to be true or explicitly justified.
- Link the issue (`Closes #12`). If there is no issue, say why in one sentence.
- Include the commands you ran and their output for the behaviour you changed. "Tests
  pass" alone is not verification.
- Expect review. Changes to severities, verdicts or report keys get the most scrutiny,
  because somebody's pipeline depends on them.
- Don't paste unredacted PII into a PR body: this tool exists to avoid that.
- If you used an AI assistant, say so and confirm you reviewed every line. That is a
  disclosure, not a demerit.

## Adding a dependency or scanner

- Pin it (`constraints.txt`) and pin the base image by digest; `image.yml` builds and
  signs. Transitive pip dependencies are pinned by SHA-256 in `requirements.lock`
  (`pip --require-hashes`); regenerating the lock is part of the bump, see
  `README.md#toolchain-pins-and-reproducibility`.
- Downloaded binaries need a SHA-256 entry in `checksums.txt`; `install.sh` refuses
  unknown artifacts.
- Update `THIRD-PARTY-NOTICES` when you add a redistributed component.
- Offline scanners run with `--network none`: if yours needs the network, it belongs on
  the host side with an explicit skip flag, like OSV.
- Give every subprocess a timeout, parse failures into a note, and never let a scanner
  crash the scan.

## Security reports

If the issue is sensitive (a false negative on a real payload, a bypass, a crash on
hostile input), prefer a private advisory via the repository's **Security** tab. Everything
else is an issue.

## License

RepoBeagle is Apache-2.0. By contributing you agree your contribution is licensed under the
same terms. No CLA, no copyright assignment.
