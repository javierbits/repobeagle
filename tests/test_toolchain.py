#!/usr/bin/env python3
"""Toolchain pinning tests: pins, drift detection, and lock/constraints consistency (no network)."""
import re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import repobeagle as rb

ROOT = Path(__file__).resolve().parent.parent
fail = 0
def check(name, ok):
    global fail
    print(("PASS " if ok else "FAIL ") + name)
    if not ok:
        fail = 1

pins = rb.toolchain_pins()
check("constraints pins parsed",
      pins.get("semgrep") == "1.187.0" and pins.get("guarddog") == "3.2.0" and pins.get("bandit") == "1.9.4")
check("gitleaks pinned from the Dockerfile", pins.get("gitleaks") == "8.30.1")
check("no drift when versions agree",
      rb.toolchain_drift({"semgrep": {"version": "1.187.0"}}, {"semgrep": "1.187.0"}) == [])
check("drift names the tool, the report version and the pin",
      rb.toolchain_drift({"semgrep": {"version": "1.180.0"}, "bandit": {"version": "1.9.4"}},
                         {"semgrep": "1.187.0", "bandit": "1.9.4"}) == ["semgrep 1.180.0 (pins 1.187.0)"])
check("unversioned scanner ignored", rb.toolchain_drift({"semgrep": {"seconds": 1.0}}, {"semgrep": "1.187.0"}) == [])
check("unpinned scanner ignored", rb.toolchain_drift({"osv-scanner": {"version": "9.9.9"}}, {"semgrep": "1.187.0"}) == [])
check("missing tools ignored", rb.toolchain_drift(None, {"semgrep": "1.187.0"}) == [])

lock = (ROOT / "requirements.lock").read_text(encoding="utf-8")
def lock_entries(text):
    """[(name, hash count)] for a pip --require-hashes file; continuation lines belong to the previous pin."""
    out, cur = [], None
    for ln in text.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        if not ln[:1].isspace() and "==" in s:
            cur = s.split("==", 1)[0].strip()
            out.append([cur, 0])
        elif cur and "--hash=sha256:" in s:
            out[-1][1] += 1
    return [(n, h) for n, h in out]

entries = lock_entries(lock)
names = [n for n, _ in entries]
check("lock carries the transitive closure", len(entries) >= 50)
check("every locked requirement has a sha256", all(h > 0 for _, h in entries))
check("no duplicate locked requirements", len(names) == len(set(names)))
check("universal lock covers several wheels per platform-specific package",
      max((h for _, h in entries), default=0) >= 3)
missing = [f"{n}=={v}" for n, v in sorted(pins.items())
           if n != "gitleaks" and not re.search(rf"(?m)^{re.escape(n)}=={re.escape(v)}\s", lock)]
check("lock matches constraints.txt" + (f" (missing: {', '.join(missing)})" if missing else ""), not missing)
dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
check("image installs the lock with --require-hashes",
      "--require-hashes" in dockerfile and "requirements.lock" in dockerfile
      and "-r /opt/repobeagle/requirements.lock" in dockerfile)

sys.exit(fail)
