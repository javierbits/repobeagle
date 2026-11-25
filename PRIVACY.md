# Privacy

RepoBeagle is a static scanner. It does not run repository code and does not send
telemetry about you.

## What leaves your machine

- `scan` **offline mode**: nothing. The clone and all scans happen locally; only
  `--verify-deps` and OSV vulnerability lookups need network and are explicit
  (OSV sends package names/versions to osv.dev).
- `scan` of a git URL: the repository is fetched from GitHub/your git host.
- `trust signals`: the scanned repo's public GitHub metadata is requested from
  `api.github.com` (no account, no token) unless `--no-trust` is passed.
- `verify`: fetches `report.json` and `report.sigstore.json` from the badge
  branch and verifies the Sigstore bundle locally (cosign is installed on first
  use).
- `install.sh`: pulls the container image from `ghcr.io` and downloads
  `osv-scanner`/`cosign`/`gitleaks` from GitHub releases.

There is no analytics, crash reporting, APM or OTEL exporter in RepoBeagle.
The `telemetry-*` findings describe the *scanned* repository, not the scanner.

## Privacy checks for scanned repos

`telemetry-*` (analytics incl. GTM/GA and marketing/engagement platforms,
session replay, ad pixels, crash reporting, APM/OTEL, dev-tool and transitive
dependency telemetry, vendor PII configs), `fingerprint`, `android-permission`,
`android-feature`, `extension-permission`, `extension-resource`,
`extension-connectable`, `macos-entitlement`, `ios-tracking`,
`ios-tracking-domain`, `ios-api-category`, `ios-data-type`, `ios-purpose-string`,
`cookie-write`, `cookie-flags`, `cookie-lifetime`, `browser-storage`,
`browser-capability`, `client-id`, `third-party-cdn`, `third-party-script`,
`third-party-stylesheet`, `third-party-media`, `third-party-preconnect`,
`third-party-preload`, `third-party-embed`, `third-party-form`, `iframe-allow`,
`consent-manager`, `consent-mode`, `consent-state`, `consent-gating`,
`consent-order`, `dnt-respect`, `insecure-endpoint`, `external-endpoint`,
`first-party-endpoint`, `ip-logging`, `pii-log`, `pii-email`, `pii-phone`,
`pii-address`, `pii-postcode`, `pii-ssn`, `pii-card`, `pii-in-url`,
`tracking-params`, `tracking-cookie`, `import-time-network`,
`import-time-storage`, `data-retention`, `upload-surface`, `upload-limit`,
`store-disclosure`, `undisclosed-vendor`, `privacy-doc`. See the README for what
each rule means and its severity, and `.repobeagleignore` for per-repo
suppression of reviewed findings.

## Report data

A published badge branch contains the scan report for a public repository:
findings, file paths, `file:line` locations, short snippets of the offending
lines, the scanned commit and image provenance. No source file content beyond
those snippets is published, and secrets reported by gitleaks are redacted
(`--redact=60`).
