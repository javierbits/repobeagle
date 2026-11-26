"""Feedback loop: prefilled issue URL is re-redacted, complete and fits GitHub's URL limit."""
import json
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import repobeagle as rb

META = {"target": "acme/widget", "commit": "b" * 40, "ref": "main", "profile": "balanced",
        "ruleset": "0123456789ab", "pii_redacted": False}


def finding(rule, file="README.md", line=1, snippet="", title=None, severity="info"):
    return {"tool": "privacy", "severity": severity, "file": file, "line": line, "rule": rule,
            "title": title or f"{rule}: something in {file}", "snippet": snippet, "meaning": "m"}


def report(*findings):
    return {"verdict": "YELLOW", "meta": META, "findings": list(findings), "counts": {"low": 1}}


def decode(url):
    assert url.startswith("https://github.com/acme/widget/issues/new?") or url.startswith("https://github.com/")
    assert len(url) <= rb.FEEDBACK_URL_MAX, len(url)
    return {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlparse(url).query).items()}


def test_body_redacted_and_complete():
    f = finding("pii-email", snippet="contact privacy@widget.dev about CARD 4111 1111 1111 1111",
                title="pii-email: privacy@widget.dev in README.md")
    url, notes = rb.feedback_url(report(f), f, "false-positive", repo="acme/widget")
    q = decode(url)
    body = q["body"]
    assert "privacy@widget.dev" not in body, body            # acceptance: no raw email
    assert "4111 1111 1111 1111" not in body, body           # acceptance: no raw card
    assert "p***@widget.dev" in body and "4111 **** **** 1111" in body, body
    for need in ["false positive", "pii-email", "README.md:1", "info", rb.VERSION,
                 f"ruleset `{META['ruleset']}`", f"commit `{META['commit']}`", "acme/widget",
                 "repobeagle feedback", "Why this is wrong"]:
        assert need in body, (need, body)
    assert "<details>" not in body                            # full report only with --attach
    assert q["labels"] == "bug"
    assert q["title"].startswith("[false positive] pii-email:"), q["title"]
    assert notes == []
    print("PASS feedback body is complete and always re-redacted")


def test_attach_and_truncation():
    small = finding("gha-curl-pipe-shell", file=".github/workflows/ci.yml", line=12,
                    snippet="curl -fsSL https://x | sh", severity="high")
    url, notes = rb.feedback_url(report(small), small, "miss", repo="acme/widget", attach=True)
    q = decode(url)
    assert "<details>" in q["body"] and '"findings"' in q["body"], q["body"][:400]
    assert q["title"].startswith("[miss] gha-curl-pipe-shell:"), q["title"]

    big = finding("pii-email", snippet="x" * 9000)
    url, notes = rb.feedback_url(report(big), big, "false-positive", repo="acme/widget", attach=True)
    q = decode(url)
    assert len(url) <= rb.FEEDBACK_URL_MAX, len(url)
    assert "truncated" in q["body"] or any("truncated" in n or "dropped" in n for n in notes), (notes, q["body"][-400:])
    assert notes, "truncation must be reported on stderr"

    url, notes = rb.feedback_url(report(big), big, "false-positive", repo="acme/widget")
    q = decode(url)
    assert len(url) <= rb.FEEDBACK_URL_MAX, len(url)
    assert "Snippet truncated" in q["body"], q["body"][-300:]
    assert any("snippet truncated" in n for n in notes), notes
    print("PASS feedback attach + URL budget truncation", notes)


def test_selection():
    f1 = finding("pii-email", file="README.md", line=1, snippet="a@b.c")
    f2 = finding("pii-email", file="docs/guide.md", line=7, snippet="d@e.f")
    got, err = rb.select_finding(report(f1, f2), "pii-email")
    assert got is None and "--file" in err and "README.md:1" in err, err
    got, err = rb.select_finding(report(f1, f2), "pii-email", "docs/guide.md:7")
    assert err == "" and got is f2
    got, err = rb.select_finding(report(f1), "pii-card")
    assert got is None and "no finding for rule 'pii-card'" in err and "pii-email" in err, err
    got, err = rb.select_finding(report(f1))
    assert err == "" and got is f1
    print("PASS feedback finding selection")


def test_cli_no_redact_report():
    with tempfile.TemporaryDirectory() as td:
        rj = Path(td, "r.json")
        scan = subprocess.run([sys.executable, "repobeagle.py", "scan", "tests/fixtures/trap-privacy", "--no-color",
                               "--no-docker", "--no-osv", "--no-trust", "--no-redact", "--json", str(rj)],
                              cwd=ROOT, capture_output=True, text=True, timeout=300)
        assert scan.returncode in (0, 1, 2) and rj.exists(), (scan.returncode, scan.stderr[-500:])
        raw = json.loads(rj.read_text())
        emails = [f for f in raw["findings"] if f["rule"] == "pii-email" and f["file"] == "README.md"]
        assert emails and "privacy@widget.dev" in emails[0]["snippet"], emails[:1]
        proc = subprocess.run([sys.executable, "repobeagle.py", "feedback", str(rj), "--false-positive",
                               "--rule", "pii-email", "--file", "README.md:1", "--no-open",
                               "--repo", "acme/widget"], cwd=ROOT, capture_output=True, text=True, timeout=60)
        assert proc.returncode == 0, (proc.returncode, proc.stderr)
        q = decode(proc.stdout.strip())
        body = q["body"]
        assert "privacy@widget.dev" not in body and "p***@widget.dev" in body, body
        assert "PII**: report scan redacted snippets: no" in body, body

        proc = subprocess.run([sys.executable, "repobeagle.py", "feedback", str(rj), "--miss",
                               "--rule", "pii-card", "--no-open", "--repo", "acme/widget"],
                              cwd=ROOT, capture_output=True, text=True, timeout=60)
        assert proc.returncode == 0, proc.stderr
        body = decode(proc.stdout.strip())["body"]
        assert "4111 1111 1111 1111" not in body and "4111 **** **** 1111" in body, body

        proc = subprocess.run([sys.executable, "repobeagle.py", "feedback", str(rj), "--false-positive",
                               "--no-open"], cwd=ROOT, capture_output=True, text=True, timeout=60)
        assert proc.returncode == 1 and "--file" in proc.stderr and not proc.stdout.strip(), (proc.returncode, proc.stderr)
    print("PASS feedback CLI re-redacts a --no-redact scan")


if __name__ == "__main__":
    test_body_redacted_and_complete()
    test_attach_and_truncation()
    test_selection()
    test_cli_no_redact_report()
    print("feedback tests passed")
