#!/usr/bin/env python3
"""Packaging tests: pyproject contract, wheel data files, console entry point, installer OS support."""
import os, sys, tempfile, tomllib
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

binary = ROOT / "tools" / "build_binary.sh"
build_text = binary.read_text(encoding="utf-8") if binary.is_file() else ""
check("the airgapped binary script is executable, pinned and bundles version/rules",
      binary.is_file() and os.access(binary, os.X_OK) and "--onefile" in build_text
      and "pyinstaller==" in build_text and "--add-data" in build_text and "VERSION" in build_text)
binary_workflow = (ROOT / ".github/workflows/binary.yml").read_text(encoding="utf-8")
check("binary workflow builds linux amd64/arm64 and macOS arm64",
      all(x in binary_workflow for x in ("ubuntu-latest", "ubuntu-24.04-arm", "macos-14", "tools/build_binary.sh")))
ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
check("CI runs the pipx acceptance on a macOS arm64 runner",
      ("macos-latest" in ci or "macos-14" in ci) and "pipx install ." in ci and "--no-docker" in ci
      and "arm64" in ci)

readme = (ROOT / "README.md").read_text(encoding="utf-8")
check("README documents the light mode, macOS, the macOS CI acceptance and binaries",
      "pipx install ." in readme and "Light mode" in readme and "macOS" in readme
      and "packaging-macos" in readme and "tools/build_binary.sh" in readme)

sys.exit(fail)
