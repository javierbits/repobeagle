#!/usr/bin/env python3
"""Packaging tests: pyproject contract, wheel data files, console entry point, installer OS support."""
import sys, tempfile, tomllib
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import repobeagle as rb

fail = 0
def check(name, ok):
    global fail
    print(("PASS " if ok else "FAIL ") + name)
    if not ok:
        fail = 1

pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
check("console entry point is repobeagle:main",
      pyproject["project"]["scripts"].get("repobeagle") == "repobeagle:main")
check("the single module is packaged", pyproject["tool"]["setuptools"]["py-modules"] == ["repobeagle"])
check("the wheel ships the custom semgrep rules and the version",
      pyproject["tool"]["setuptools"]["data-files"]["share/repobeagle"] == ["rules/custom.yml", "VERSION"])
check("wheel version follows VERSION",
      pyproject["tool"]["setuptools"]["dynamic"]["version"] == {"attr": "repobeagle.VERSION"})
check("python requirement matches the syntax used", pyproject["project"]["requires-python"] == ">=3.10")
check("declared version equals the VERSION file",
      rb.RELEASE == (ROOT / "VERSION").read_text().strip() and rb.VERSION == rb.RELEASE.lstrip("v"))
check("main() is callable as the console script", callable(rb.main))

# the checkout's rules are preferred, and a wheel install falls back to share/repobeagle
check("checkout rules are used when present",
      rb.semgrep_configs() == [ROOT / "rules" / "custom.yml"])
old_rules, old_prefix = rb.RULES_DIR, sys.prefix
with tempfile.TemporaryDirectory() as td:
    share = Path(td) / "share" / "repobeagle"
    share.mkdir(parents=True)
    (share / "custom.yml").write_text("rules: []\n")
    (share / "VERSION").write_text("v9.9.9\n")
    rb.RULES_DIR = Path(td) / "no-rules-here"
    sys.prefix = td
    try:
        check("packaged rules are used when the checkout is absent", rb.semgrep_configs() == [share / "custom.yml"])
        check("packaged version is read when the checkout is absent",
              rb._read_version(here=Path(td) / "no-repo") == "v9.9.9")
    finally:
        rb.RULES_DIR, sys.prefix = old_rules, old_prefix

installer = (ROOT / "install.sh").read_text(encoding="utf-8")
check("installer knows macOS", "Darwin" in installer and "brew install" in installer)
check("installer verifies checksums without GNU coreutils", "shasum -a 256" in installer)

readme = (ROOT / "README.md").read_text(encoding="utf-8")
check("README documents the light mode and macOS",
      "pipx install ." in readme and "Light mode" in readme and "macOS" in readme)

sys.exit(fail)
