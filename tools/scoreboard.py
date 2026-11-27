#!/usr/bin/env python3
"""R7 precision/detection scoreboard.

Honest cohort (real repositories pinned by SHA): measures false-positive drift per rule and
the median finding count. Detection cohort (labeled trap fixtures): every expected rule must
fire. The committed baseline is the budget: a rule change that adds hits on the honest
cohort, worsens a verdict, raises the median, or loses a detection fails the scoreboard.

Scans use the pinned image by default (set BEAGLE_IMAGE to the tag you built) with OSV and
trust disabled so the numbers are comparable between the nightly job and local runs.
`--update-baseline` is a reviewed decision: the diff shows exactly which rule moved.
"""
import argparse
import concurrent.futures
import json
import os
import re
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import repobeagle as rb

VERDICT_RANK = {"GREEN": 0, "YELLOW": 1, "RED": 2}
TOOL_NAME = "repobeagle-scoreboard"


def parse_args():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--corpus", default=str(ROOT / "tests" / "corpus.yml"))
    ap.add_argument("--baseline", default=str(ROOT / "tests" / "corpus-baseline.json"))
    ap.add_argument("--out", metavar="FILE", help="write the Markdown scoreboard")
    ap.add_argument("--json", metavar="FILE", help="write the machine-readable scoreboard")
    ap.add_argument("--update-baseline", action="store_true",
                    help="replace the baseline with this run (review the diff)")
    ap.add_argument("--jobs", type=int, default=4, metavar="N", help="parallel scans (default: 4)")
    ap.add_argument("--no-docker", action="store_true", help="scan on the host instead of the pinned image")
    ap.add_argument("--with-osv", action="store_true", help="also run OSV (network; off by default)")
    ap.add_argument("--with-trust", action="store_true", help="also run GitHub trust signals (network)")
    return ap.parse_args()


def load_corpus(path):
    try:
        data = rb.parse_yaml_subset(Path(path).read_text(encoding="utf-8"))
    except OSError as ex:
        raise SystemExit(f"corpus: cannot read {path}: {ex}")
    honest = []
    for item in data.get("honest") or []:
        if not isinstance(item, dict) or not (item.get("sha") and (item.get("slug") or item.get("path"))):
            raise SystemExit(f"corpus: honest entry needs slug+sha or path: {item!r}")
        honest.append(item)
    malicious = []
    for item in data.get("malicious") or []:
        if not isinstance(item, dict) or not (item.get("path") and item.get("expect")):
            raise SystemExit(f"corpus: malicious entry needs path and expect: {item!r}")
        expect = item["expect"] if isinstance(item["expect"], list) else [item["expect"]]
        malicious.append({"path": item["path"], "expect": [str(x) for x in expect],
                          "verdict": str(item.get("verdict") or "YELLOW|RED")})
    if not honest or not malicious:
        raise SystemExit("corpus: both cohorts must be non-empty")
    return honest, malicious


def scan_target(args, target, ref=None):
    try:
        raw = rb.scan_json_report(target, ref,
                                  no_docker=args.no_docker,
                                  no_osv=not args.with_osv,
                                  no_trust=not args.with_trust,
                                  profile="balanced", jobs=1, timeout=1800)
        return json.loads(raw)
    except rb.ScanFailure as ex:
        return {"error": str(ex)}


def measure(report):
    findings = [f for f in report.get("findings") or []
                if isinstance(f, dict) and not f.get("suppressed") and f.get("severity") in rb.SEV_ORDER]
    rules: dict[str, int] = {}
    for finding in findings:
        rule = rb._rule_of(finding)
        rules[rule] = rules.get(rule, 0) + 1
    return {
        "verdict": report.get("verdict"),
        "counts": {k: int((report.get("counts") or {}).get(k) or 0) for k in rb.SEV_ORDER},
        "findings": len(findings),
        "rules": rules,
        "sha": str((report.get("meta") or {}).get("commit") or ""),
        "error": report.get("error"),
    }


def examples_from(report, repo, sha, limit=3):
    """Up to `limit` positive example locations per rule, for `repobeagle explain <rule>`."""
    out: dict[str, list[dict[str, object]]] = {}
    for finding in report.get("findings") or []:
        if not isinstance(finding, dict) or finding.get("suppressed"):
            continue
        rule = rb._rule_of(finding)
        entry = {"repo": repo, "sha": sha, "file": str(finding.get("file") or ""),
                 "line": int(finding.get("line") or 0)}
        bucket = out.setdefault(rule, [])
        if entry["file"] and entry not in bucket and len(bucket) < limit:
            bucket.append(entry)
    return out


def scan_honest(args, entry):
    slug = str(entry.get("slug") or "")
    if slug:
        target = f"https://github.com/{slug}.git"
        ref = str(entry["sha"])
        key = slug
    else:
        target = str(entry["path"])
        ref = None
        key = "local/" + Path(target).name
    report = scan_target(args, target, ref)
    metric = measure(report)
    metric["examples"] = examples_from(report, key, str(entry.get("sha") or "worktree"))
    if metric["error"]:
        return key, {**metric, "sha": str(entry.get("sha") or ""), "error": metric["error"]}
    if slug and metric["sha"] and metric["sha"] != str(entry["sha"]):
        metric["error"] = f"scanned {metric['sha'][:12]} but corpus pins {str(entry['sha'])[:12]}"
    return key, metric


def scan_malicious(args, entry):
    report = scan_target(args, str(entry["path"]), None)
    if report.get("error"):
        return {"path": entry["path"], "error": report["error"], "fired": [], "missing": entry["expect"]}
    fired = sorted({rb._rule_of(f) for f in report.get("findings") or []
                    if isinstance(f, dict) and not f.get("suppressed")})
    examples = examples_from(report, "fixture:" + str(entry["path"]), "worktree")
    verdict = str(report.get("verdict") or "?")
    missing = [rule for rule in entry["expect"] if rule not in fired]
    try:
        verdict_ok = re.search(entry["verdict"], verdict) is not None
    except re.error:
        verdict_ok = False
    return {"path": entry["path"], "verdict": verdict, "fired": fired, "missing": missing,
            "verdict_ok": verdict_ok, "expected": entry["expect"], "examples": examples}


def collect(args):
    honest_entries, malicious_entries = load_corpus(args.corpus)
    honest, detection = {}, []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        futures = {pool.submit(scan_honest, args, e): ("honest", e) for e in honest_entries}
        futures.update({pool.submit(scan_malicious, args, e): ("malicious", e) for e in malicious_entries})
        for future in concurrent.futures.as_completed(futures):
            kind, entry = futures[future]
            try:
                result = future.result()
            except Exception as ex:
                result = (f"local/{entry.get('path', '?')}", {"error": f"{type(ex).__name__}: {ex}"}) \
                    if kind == "honest" else {"path": entry.get("path"), "error": str(ex),
                                              "missing": entry.get("expect", []), "fired": []}
            if kind == "honest":
                honest[result[0]] = result[1]
            else:
                detection.append(result)
    detection.sort(key=lambda d: d.get("path") or "")
    return honest, detection


def summarize(honest, detection):
    counts = [m["findings"] for m in honest.values() if not m.get("error")]
    examples: dict[str, list[dict[str, object]]] = {}
    for metric in list(honest.values()) + list(detection):
        for rule, items in (metric.get("examples") or {}).items():
            bucket = examples.setdefault(rule, [])
            for item in items:
                if item not in bucket and len(bucket) < 3:
                    bucket.append(item)
    baseline_rules: dict[str, int] = {}
    for metric in honest.values():
        for rule, hits in (metric.get("rules") or {}).items():
            baseline_rules[rule] = baseline_rules.get(rule, 0) + hits
    return {
        "tool": TOOL_NAME,
        "tool_version": rb.VERSION,
        "ruleset": rb.RULESET,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cohorts": {"honest": len(honest), "detection": len(detection)},
        "median_findings": statistics.median(counts) if counts else 0,
        "totals_by_rule": dict(sorted(baseline_rules.items())),
        "examples": dict(sorted(examples.items())),
        "honest": dict(sorted(honest.items())),
        "detection": detection,
    }


def regressions(current, baseline):
    problems = []
    old, new = baseline.get("honest") or {}, current.get("honest") or {}
    for slug in sorted(set(old) | set(new)):
        before, after = old.get(slug), new.get(slug)
        if before and not after:
            problems.append(f"honest repository disappeared: {slug}")
            continue
        if after and after.get("error"):
            problems.append(f"{slug}: scan failed: {after['error']}")
            continue
        if not before or not after:
            continue
        if str(before.get("sha")) != str(after.get("sha")):
            problems.append(f"{slug}: corpus SHA {after.get('sha', '')[:12]} differs from baseline "
                            f"{str(before.get('sha'))[:12]} (update the baseline with the corpus change)")
        if VERDICT_RANK.get(str(after.get("verdict")), 9) > VERDICT_RANK.get(str(before.get("verdict")), 9):
            problems.append(f"{slug}: verdict worsened {before.get('verdict')} -> {after.get('verdict')}")
    old_rules, new_rules = baseline.get("totals_by_rule") or {}, current.get("totals_by_rule") or {}
    for rule in sorted(set(old_rules) | set(new_rules)):
        if int(new_rules.get(rule, 0)) > int(old_rules.get(rule, 0)):
            problems.append(f"rule {rule}: honest hits {old_rules.get(rule, 0)} -> {new_rules.get(rule, 0)}")
    if float(current.get("median_findings") or 0) > float(baseline.get("median_findings") or 0):
        problems.append(f"honest median findings {baseline.get('median_findings')} -> {current.get('median_findings')}")
    old_det = {d.get("path"): d for d in baseline.get("detection") or []}
    for det in current.get("detection") or []:
        before = old_det.get(det.get("path"))
        if before and len(det.get("missing") or []) > len(before.get("missing") or []):
            problems.append(f"detection regressed for {det.get('path')}: missing {det.get('missing')}")
        if det.get("missing"):
            problems.append(f"{det.get('path')}: expected rules did not fire: {det.get('missing')}")
        if not det.get("verdict_ok"):
            problems.append(f"{det.get('path')}: verdict {det.get('verdict')} does not match the corpus label")
    return problems


def markdown(score, problems):
    lines = ["# RepoBeagle precision scoreboard", "",
             f"tool {score['tool_version']} · ruleset `{score['ruleset']}` · {score['generated_at']}",
             "",
             f"**Honest cohort:** {score['cohorts']['honest']} pinned repositories · "
             f"median findings **{score['median_findings']}** · "
             f"**{len(score['totals_by_rule'])}** rules with hits",
             "",
             "| honest repository | verdict | critical | high | medium | low | findings |",
             "|---|---|---|---|---|---|---|"]
    for slug, metric in score["honest"].items():
        c = metric.get("counts") or {}
        state = metric.get("error") or metric.get("verdict") or "error"
        lines.append(f"| {slug} | {state} | {c.get('critical', 0)} | {c.get('high', 0)} | "
                     f"{c.get('medium', 0)} | {c.get('low', 0)} | {metric.get('findings', 0)} |")
    lines += ["", "| rule | honest hits |", "|---|---|"]
    for rule, hits in list(score["totals_by_rule"].items())[:40]:
        lines.append(f"| `{rule}` | {hits} |")
    if len(score["totals_by_rule"]) > 40:
        lines.append(f"| … {len(score['totals_by_rule']) - 40} more | |")
    lines += ["", f"**Detection cohort:** {score['cohorts']['detection']} labeled fixtures", "",
              "| fixture | verdict | expected rules | missing |", "|---|---|---|---|"]
    for det in score["detection"]:
        missing = ", ".join(det.get("missing") or []) or "—"
        lines.append(f"| {det.get('path')} | {det.get('verdict', 'error')} | "
                     f"{len(det.get('expected') or [])} | {missing} |")
    lines += ["", f"**Result:** {'FAIL' if problems else 'PASS'}", ""]
    for problem in problems:
        lines.append(f"- {problem}")
    return "\n".join(lines) + "\n"


def main():
    args = parse_args()
    honest, detection = collect(args)
    score = summarize(honest, detection)
    baseline = {}
    if Path(args.baseline).is_file():
        try:
            baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        except (OSError, ValueError) as ex:
            print(f"scoreboard: cannot read baseline: {ex}", file=sys.stderr)
            return 1
    problems = [] if args.update_baseline else regressions(score, baseline)
    text = markdown(score, problems)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"scoreboard: wrote {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    if args.json:
        Path(args.json).write_text(json.dumps(score, indent=2), encoding="utf-8")
        print(f"scoreboard: wrote {args.json}", file=sys.stderr)
    if args.update_baseline:
        Path(args.baseline).write_text(json.dumps(score, indent=2), encoding="utf-8")
        print(f"scoreboard: baseline updated at {args.baseline}", file=sys.stderr)
        return 0
    for problem in problems:
        print(f"scoreboard: {problem}", file=sys.stderr)
    print(f"scoreboard: {'FAIL' if problems else 'PASS'} "
          f"(median {score['median_findings']}, rules {len(score['totals_by_rule'])})", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
