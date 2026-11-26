#!/usr/bin/env bash
# Build the light-mode one-file binary with PyInstaller (no Python needed on the target).
# The binary still shells out to the host scanner tools (gitleaks/semgrep/guarddog/bandit/
# osv-scanner) when run, or uses the Docker image unless --no-docker is passed.
#   tools/build_binary.sh [dist-dir]
# PyInstaller is pinned so the artifact is reproducible; the venv stays out of git.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$HERE/dist}"
PYINSTALLER_VERSION="${PYINSTALLER_VERSION:-6.11.1}"
VENV="$HERE/.build-venv"
python3 -m venv "$VENV"
"$VENV/bin/pip" install -q --upgrade pip "pyinstaller==$PYINSTALLER_VERSION"
rm -rf "$OUT"
mkdir -p "$HERE/build"
"$VENV/bin/pyinstaller" --clean --noconfirm --onefile --name repobeagle \
  --add-data "$HERE/VERSION:." --add-data "$HERE/rules:rules" \
  --distpath "$OUT" --workpath "$HERE/build/pyinstaller" --specpath "$HERE/build" \
  "$HERE/repobeagle.py"
"$OUT/repobeagle" --version
printf '\033[1;36m[repobeagle]\033[0m binary: %s (%s)\n' "$OUT/repobeagle" "$(uname -s)/$(uname -m)"
