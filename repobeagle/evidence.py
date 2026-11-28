"""Rule-level evidence ledger (T12).

Shows the checks that passed, not only the findings: for a bounded set of high-signal
rules, whether the check family ran, how many files it examined, the hits, and the
negative assertion ("no download piped into a shell"). Only counters are stored, never
per-file lists, so the report grows by a constant amount on a 100k-file repo.

Coverage (R8) is file-level; this is rule-level. It is deliberately incremental (the
top rules), not every rule, as the design asks.
"""
from typing import Any

from .rules.registry import RULES

# (rule id, family, negative assertion). Rule ids match the stable title prefixes emitted
# by the checks; the assertion is what a zero-hit result lets the reader conclude.
EVIDENCE_RULES: tuple[tuple[str, str, str], ...] = (
    ("gha-curl-pipe-shell", "agent",
     "no workflow pipes a downloaded script into a shell"),
    ("gha-unpinned-action", "agent",
     "no action is referenced by a moving tag/branch instead of a commit SHA"),
    ("gha-pwn-request", "agent",
     "no pull_request_target/workflow_run workflow checks out the PR head with secrets"),
    ("npm lifecycle script 'postinstall' runs automatically on install", "agent",
     "no npm lifecycle hook runs automatically on install"),
    ("Download-and-execute", "agent",
     "no installer/script is downloaded and executed"),
    ("gguf-chat-template-command", "agent",
     "no GGUF chat template makes the model print a shell command"),
    ("Code reads secrets/credentials near a network call", "agent",
     "no credential file is read next to a network sink"),
    ("import-time-network", "privacy",
     "no network call runs at module scope"),
    ("third-party-script", "privacy",
     "no script is loaded from a third-party host"),
    ("cookie-flags", "privacy",
     "no cookie is written without Secure/SameSite where it matters"),
    ("pii-in-url", "privacy",
     "no PII is placed in URL query parameters"),
)

LEDGER_JSON_BUDGET = 4096   # bytes; counters only, independent of the file count


def build_ledger(findings, suppressed, files, complete):
    """{rule: {evaluated, files, hits, suppressed, negative, family, documented}}.

    `evaluated` is true only for a complete scan: a partial run examined only some files,
    so a negative assertion would be unproven. `files` is the number of text files the
    built-in check families examined.
    """
    counts: dict[str, int] = {}
    suppressed_counts: dict[str, int] = {}
    for finding in findings or []:
        if isinstance(finding, dict):
            rule = str(finding.get("rule") or str(finding.get("title") or "").split(":")[0].split(" (")[0])
            counts[rule] = counts.get(rule, 0) + 1
    for finding in suppressed or []:
        if isinstance(finding, dict):
            rule = str(finding.get("rule") or str(finding.get("title") or "").split(":")[0].split(" (")[0])
            suppressed_counts[rule] = suppressed_counts.get(rule, 0) + 1
    files = max(0, int(files or 0))
    ledger: dict[str, dict[str, Any]] = {}
    for rule, family, negative in EVIDENCE_RULES:
        ledger[rule] = {
            "evaluated": bool(complete) and files > 0,
            "files": files,
            "hits": counts.get(rule, 0),
            "suppressed": suppressed_counts.get(rule, 0),
            "negative": negative,
            "family": family,
            "documented": rule in RULES,
        }
    return ledger
