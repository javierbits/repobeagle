#!/usr/bin/env python3
"""repobeagle: static safety gate for untrusted repositories (package shim).

Implementation: repobeagle/{core,fetch,report,scanners,rules/,cli}.py.
NEVER executes repository code. Stdlib only (scanners are external binaries).

The shim defines VERSION without importing the package, because setuptools reads it for
the wheel metadata while `repobeagle` also resolves to this file for that loader.
"""
import sys
from pathlib import Path

def _shim_version():
    for cand in (Path(__file__).resolve().parent / "VERSION",
                 Path(sys.prefix) / "share" / "repobeagle" / "VERSION"):
        try:
            value = cand.read_text().strip()
        except OSError:
            continue
        if value:
            return value
    return "v1.0.0"

RELEASE = _shim_version()
VERSION = RELEASE.lstrip("v")

if __name__ == "__main__":
    from repobeagle.cli import main

    sys.exit(main())
