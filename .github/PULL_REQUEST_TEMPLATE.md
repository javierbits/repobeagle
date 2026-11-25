## Summary

<!-- What changes, and why. Link the issue below. One logical change per PR. -->

## Linked issue

<!-- Closes #12 — or explain in one sentence why there is no issue. -->

Closes #

## Claim

- [ ] I claimed the linked issue by commenting `/claim` and the claim is mine (or the issue
      was unclaimed and I am about to claim it)
- [ ] This PR comes from **my fork**, not a branch on the upstream repository
- [ ] The diff stays inside the scope I named in the claim (files, functions, rule ids)

## Type of change

- [ ] Bug fix (wrong finding, crash, false positive/negative)
- [ ] New rule or detection
- [ ] CLI / report format / schema change
- [ ] Scanner, image or dependency change
- [ ] Documentation only
- [ ] Refactor with no behaviour change

## Checklist

- [ ] **Tests written or updated for the code in this PR** (fixture under `tests/fixtures/`
      plus an assertion in `tests/run_tests.sh`), or stated below why a test is not possible
- [ ] New rule has a **positive and a negative** fixture
- [ ] `tests/run_tests.sh --offline` passes locally
- [ ] `tests/run_tests.sh` (online) run when behaviour changed
- [ ] `python3 -m py_compile` and `ruff check --select E9,F63,F7,F82 repobeagle.py tools tests/*.py` pass
- [ ] Code formatted consistently with the file it touches (no formatter is enforced yet, issue #5)
- [ ] PR title follows Conventional Commits (`type(scope): subject`)
- [ ] Docs updated (`README.md` rule table / command docs, `FEATURES.md` status), or N/A
- [ ] Report changes are additive, or the breaking change is documented with a ruleset/version note
- [ ] No new dependency, or it is pinned (`constraints.txt` / `checksums.txt`) and
      `THIRD-PARTY-NOTICES` is updated
- [ ] Still never executes repository code; no new network call in the offline path
- [ ] Findings keep `file:line` and a stable rule id; PII stays redacted
- [ ] No unredacted PII pasted in this PR body

## Verification

<!-- Commands you actually ran, and their relevant output. -->

```sh
tests/run_tests.sh --offline
```

## Risk and rollback

<!-- What can this break? Which profiles/consumers are affected? How is it reverted? -->
