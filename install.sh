#!/usr/bin/env bash
# repobeagle installer (idempotent). The Docker image is the hardened path; this script
# also supports macOS (host tools via Homebrew) and the light mode (`pipx install .`).
#   ./install.sh                 pull prebuilt image ghcr.io/javierbits/repobeagle:<VERSION> + install wrapper
#   ./install.sh --build-local   build the image locally from this folder instead of pulling
#   ./install.sh --local-tools   also install gitleaks/semgrep/guarddog/bandit on the host (for --no-docker fallback)
# Every Linux artifact is pinned and SHA-256 verified against checksums.txt, and the pulled
# image's keyless signature is checked when cosign is available. On macOS the host tools
# come from Homebrew (which verifies its own bottles); Docker Desktop is used when present.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="$(tr -d '[:space:]' < "$HERE/VERSION" 2>/dev/null || true)"; VERSION="${VERSION:-v1.0.0}"
IMAGE="${BEAGLE_IMAGE:-ghcr.io/javierbits/repobeagle:$VERSION}"
PREFIX="${BEAGLE_HOME:-$HOME/.local/share/repobeagle}"
BIN="${BEAGLE_BIN:-$HOME/.local/bin}"
BUILD_LOCAL=0; LOCAL_TOOLS=0
for a in "$@"; do case "$a" in --build-local) BUILD_LOCAL=1;; --local-tools) LOCAL_TOOLS=1;; *) echo "unknown option $a"; exit 1;; esac; done
say(){ printf '\033[1;36m[repobeagle]\033[0m %s\n' "$*"; }
mkdir -p "$BIN" "$PREFIX"
OS="$(uname -s)"
case "$OS" in
  Linux|Darwin) ;;
  *) echo "Unsupported OS $OS (Linux and macOS)"; exit 1 ;;
esac
case "$(uname -m)" in
  aarch64|arm64) GL_ARCH=arm64; OSV_ARCH=arm64 ;;
  x86_64|amd64)  GL_ARCH=x64;   OSV_ARCH=amd64 ;;
  *) echo "Unsupported arch $(uname -m)"; exit 1 ;;
esac
# Pinned releases. Bump these here and in checksums.txt together: the installer
# refuses to install an artifact it cannot verify against a pinned SHA-256.
GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.30.1}"
OSV_VERSION="${OSV_VERSION:-2.7.0}"
COSIGN_VERSION="${COSIGN_VERSION:-3.1.3}"
CHECKSUMS="$HERE/checksums.txt"

verify_sha(){ # downloaded-file expected-artifact-name
  local f=$1 name=$2 want got
  want="$(awk -v n="$name" '$2==n {print $1; exit}' "$CHECKSUMS" 2>/dev/null || true)"
  if [[ -z $want ]]; then
    echo "no checksum for $name in $CHECKSUMS: refusing an unverified artifact (bump checksums.txt)" >&2
    return 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    got="$(sha256sum "$f" | awk '{print $1}')"
  else
    got="$(shasum -a 256 "$f" | awk '{print $1}')"   # macOS
  fi
  if [[ $got != "$want" ]]; then
    echo "checksum mismatch for $name: expected $want, got $got" >&2
    return 1
  fi
  say "verified $name (sha256 ${want:0:12}...)"
}

fetch(){ # url destination-path
  local url=$1 dest=$2 name tmp
  name="${url##*/}"
  tmp="$(mktemp)"
  if ! curl -fsSL -o "$tmp" "$url"; then echo "download failed: $url" >&2; rm -f "$tmp"; return 1; fi
  if ! verify_sha "$tmp" "$name"; then rm -f "$tmp"; return 1; fi
  mv "$tmp" "$dest"
}

command -v git >/dev/null && command -v python3 >/dev/null || { echo "need git and python3"; exit 1; }

# 1) scanner image
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  if [[ $BUILD_LOCAL == 1 ]]; then
    say "building $IMAGE locally ($(uname -m))"; docker build -t "$IMAGE" "$HERE"
  else
    say "pulling $IMAGE"
    docker pull "$IMAGE" || { echo "pull failed (check your network or Docker), or use --build-local"; exit 1; }
  fi
else
  say "Docker not available -> scans will run with host tools (--no-docker). Installing them."; LOCAL_TOOLS=1
fi

# 2-3) host tools. Linux: pinned release binaries verified against checksums.txt.
#       macOS: Homebrew (Linux binaries cannot run there).
if [[ $OS == Darwin ]]; then
  if command -v brew >/dev/null 2>&1; then
    for t in gitleaks osv-scanner cosign; do
      if ! command -v "$t" >/dev/null 2>&1; then
        say "installing $t with Homebrew"
        brew install "$t"
      fi
    done
  else
    say "macOS without Homebrew: install gitleaks, osv-scanner and cosign (brew install gitleaks osv-scanner cosign) or use the Docker image"
  fi
else
  # 2) osv-scanner on the host (needs network for the vuln DB; reads lockfiles only)
  if ! command -v osv-scanner >/dev/null 2>&1; then
    say "installing osv-scanner $OSV_VERSION ($OSV_ARCH)"
    fetch "https://github.com/google/osv-scanner/releases/download/v$OSV_VERSION/osv-scanner_linux_${OSV_ARCH}" "$BIN/osv-scanner"
    chmod 0755 "$BIN/osv-scanner"
  fi

  # 3) cosign on the host (verifies signatures on published badge reports)
  if ! command -v cosign >/dev/null 2>&1 && [[ ! -x "$BIN/cosign" ]]; then
    say "installing cosign $COSIGN_VERSION ($OSV_ARCH)"
    fetch "https://github.com/sigstore/cosign/releases/download/v$COSIGN_VERSION/cosign-linux-${OSV_ARCH}" "$BIN/cosign"
    chmod 0755 "$BIN/cosign"
  fi
fi

# 4) verify the pulled image's keyless signature (the image workflow signs by digest)
if [[ $BUILD_LOCAL == 0 ]]; then
  C="$(command -v cosign || true)"; [[ -n $C ]] || C="$BIN/cosign"
  if [[ -x $C ]]; then
    if "$C" verify "$IMAGE" \
        --certificate-identity-regexp '^https://github\.com/javierbits/repobeagle/\.github/workflows/image\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+)$' \
        --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' >/dev/null 2>&1; then
      say "image signature verified"
    elif [[ "${BEAGLE_REQUIRE_SIGNATURE:-0}" == 1 ]]; then
      echo "image $IMAGE is not verifiably signed; refusing (BEAGLE_REQUIRE_SIGNATURE=1)" >&2; exit 1
    else
      echo "warning: no verifiable signature on $IMAGE (tag published before signing, or a local build)" >&2
    fi
  else
    say "cosign unavailable: image signature not checked"
  fi
fi

# 5) optional host tools for the no-docker fallback
if [[ $LOCAL_TOOLS == 1 ]]; then
  if ! command -v gitleaks >/dev/null 2>&1; then
    if [[ $OS == Darwin ]]; then
      command -v brew >/dev/null 2>&1 && brew install gitleaks
    else
      say "installing gitleaks $GITLEAKS_VERSION ($GL_ARCH)"
      T="$(mktemp -d)"; A="gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz"
      fetch "https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS_VERSION/$A" "$T/$A"
      tar -xzf "$T/$A" -C "$T" gitleaks
      install -m 0755 "$T/gitleaks" "$BIN/gitleaks"; rm -rf "$T"
    fi
  fi
  if [[ ! -x "$PREFIX/venv/bin/semgrep" || ! -x "$PREFIX/venv/bin/guarddog" || ! -x "$PREFIX/venv/bin/bandit" ]]; then
    say "installing semgrep + guarddog + bandit into $PREFIX/venv"
    python3 -m venv "$PREFIX/venv"; "$PREFIX/venv/bin/pip" install -q --upgrade pip semgrep guarddog bandit
  fi
  for t in semgrep guarddog bandit; do command -v $t >/dev/null 2>&1 || ln -sf "$PREFIX/venv/bin/$t" "$BIN/$t"; done
fi

# 5) thin wrapper
cat > "$BIN/repobeagle" <<WRAP
#!/usr/bin/env bash
export BEAGLE_IMAGE="\${BEAGLE_IMAGE:-$IMAGE}"
export PATH="$BIN:\$PATH"
exec python3 "$HERE/repobeagle.py" "\$@"
WRAP
chmod +x "$BIN/repobeagle"
grep -qs repobeagle.py "$BIN/beagle" && rm -f "$BIN/beagle"  # remove only our old wrapper
say "installed $BIN/repobeagle (image: $IMAGE)"
case ":$PATH:" in *":$BIN:"*) ;; *) say "add $BIN to your PATH";; esac
say "try: repobeagle scan https://github.com/psf/requests"
