"""Registry release-drift and provenance checks (T11).

A clean repository does not prove the published package was built from it. This module
resolves an npm/PyPI/crates artifact, compares it *semantically* with the repository at the
release tag (install hooks, dependency sets, file inventory), and reports whether the
registry carries provenance evidence. It never executes the package.
"""
import json
import os
import re
import shutil
import sys
import tempfile
import urllib.request
from pathlib import Path

# --- cross-module imports ---
from .core import finding, iter_files
from .fetch import WEB_UA, safe_extract
from .scanners import _github_download, _registry_fetch

RELEASE_ARTIFACT_MAX_BYTES = 50 * 1024 * 1024
NPM_INSTALL_HOOKS = ("preinstall", "install", "postinstall")
RELEASE_FINDING_CAP = 20
SLUG_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as ex:
        raise ValueError(f"cannot read {path}: {ex}") from ex


def _toml(path):
    try:
        import tomllib   # Python 3.11+; the rest of the scanner supports 3.10
    except ImportError as ex:
        raise ValueError(f"{path}: TOML manifests need Python 3.11+ (tomllib)") from ex
    try:
        return tomllib.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as ex:
        raise ValueError(f"cannot read {path}: {ex}") from ex


def _github_headers():
    token = (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "")
    headers = {"User-Agent": WEB_UA, "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def latest_release_tag(slug):
    """Latest release tag for a repository (or '' when it cannot be resolved)."""
    api = os.environ.get("GITHUB_API_URL") or "https://api.github.com"
    for path in (f"/repos/{slug}/releases/latest", f"/repos/{slug}/tags?per_page=1"):
        try:
            req = urllib.request.Request(api + path, headers=_github_headers())
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
        except Exception:
            continue
        if path.endswith("/latest"):
            tag = str(data.get("tag_name") or "")
        else:
            tag = str((data[0] if isinstance(data, list) and data else {}).get("name") or "")
        if tag:
            return tag
    return ""


def find_manifest(root):
    """(ecosystem, manifest path, parsed manifest) for the most relevant manifest under root."""
    root = Path(root)
    candidates = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in (".git", "node_modules") for part in path.relative_to(root).parts):
            continue
        if path.name == "package.json":
            candidates.append(("npm", path))
        elif path.name == "pyproject.toml":
            candidates.append(("pypi", path))
        elif path.name == "Cargo.toml" and "target" not in path.relative_to(root).parts:
            candidates.append(("crates", path))
    for ecosystem, path in candidates:
        try:
            data = _read_json(path) if ecosystem == "npm" else _toml(path)
        except ValueError:
            continue
        if ecosystem == "npm" and isinstance(data, dict) and data.get("name"):
            return ecosystem, path, data
        if ecosystem == "pypi" and isinstance(data, dict) and (data.get("project") or {}).get("name"):
            return ecosystem, path, data
        if ecosystem == "crates" and isinstance(data, dict) and (data.get("package") or {}).get("name"):
            return ecosystem, path, data
    return None, None, None


def _normalize_dep(spec):
    text = re.sub(r"\s+", " ", str(spec or "")).strip()
    return text


def manifest_summary(ecosystem, data):
    """Semantic view: name/version, install hooks and dependency sets."""
    summary = {"ecosystem": ecosystem, "name": None, "version": None, "hooks": {}, "deps": {}}
    if ecosystem == "npm":
        summary["name"] = str(data.get("name") or "")
        summary["version"] = str(data.get("version") or "")
        scripts = data.get("scripts") or {}
        if isinstance(scripts, dict):
            summary["hooks"] = {k: str(scripts.get(k)) for k in NPM_INSTALL_HOOKS if scripts.get(k)}
        for field in ("dependencies", "optionalDependencies", "peerDependencies"):
            block = data.get(field)
            if isinstance(block, dict):
                for name, spec in block.items():
                    summary["deps"][str(name)] = _normalize_dep(spec)
    elif ecosystem == "pypi":
        project = data.get("project") or {}
        summary["name"] = str(project.get("name") or "")
        summary["version"] = str(project.get("version") or "")
        deps = project.get("dependencies") or []
        if isinstance(deps, list):
            for spec in deps:
                name = re.split(r"[<>=!~ ;\[]", str(spec), 1)[0].strip()
                if name:
                    summary["deps"][name] = _normalize_dep(spec)
        for field in ("optional-dependencies",):
            for group in (project.get(field) or {}).values() if isinstance(project.get(field), dict) else []:
                for spec in group or []:
                    name = re.split(r"[<>=!~ ;\[]", str(spec), 1)[0].strip()
                    if name and name not in summary["deps"]:
                        summary["deps"][name] = _normalize_dep(spec)
    elif ecosystem == "crates":
        package = data.get("package") or {}
        summary["name"] = str(package.get("name") or "")
        summary["version"] = str(package.get("version") or "")
        for field in ("dependencies", "build-dependencies"):
            block = data.get(field)
            if isinstance(block, dict):
                for name, spec in block.items():
                    if name == "package":
                        continue
                    version = spec.get("version") if isinstance(spec, dict) else spec
                    summary["deps"][str(name)] = _normalize_dep(version)
    return summary


def inventory(root):
    """Coarse file inventory (counts and extensions): generated/minified files legitimately differ."""
    files = [p for p in iter_files(Path(root))]
    exts: dict[str, int] = {}
    for p in files:
        suffix = p.suffix.lower() or "(none)"
        exts[suffix] = exts.get(suffix, 0) + 1
    return {"files": len(files), "extensions": dict(sorted(exts.items()))}


def _release_version(registry, ecosystem, name):
    if ecosystem == "npm":
        latest = str((registry.get("dist-tags") or {}).get("latest") or "")
        return latest, ((registry.get("versions") or {}).get(latest) or {})
    if ecosystem == "pypi":
        return str((registry.get("info") or {}).get("version") or ""), registry
    if ecosystem == "crates":
        crate = registry.get("crate") or {}
        version = str(crate.get("max_version") or "")
        for entry in registry.get("versions") or []:
            if str(entry.get("num")) == version:
                return version, entry
        return version, {}
    return "", registry


def _artifact_url(ecosystem, name, version, info):
    if ecosystem == "npm":
        return str(((info.get("dist") or {}).get("tarball")) or "")
    if ecosystem == "pypi":
        for url in info.get("urls") or []:
            if str(url.get("packagetype")) == "sdist" and str(url.get("url") or "").endswith((".tar.gz", ".zip")):
                return str(url["url"])
        for url in info.get("urls") or []:
            if str(url.get("url") or "").endswith((".tar.gz", ".zip")):
                return str(url["url"])
        return ""
    if ecosystem == "crates":
        path = str(info.get("dl_path") or "")
        return ("https://crates.io" + path) if path.startswith("/") else path
    return ""


def provenance_evidence(ecosystem, info):
    if ecosystem == "npm":
        attestations = (info.get("dist") or {}).get("attestations")
        if attestations:
            return "npm dist.attestations present"
        if (info.get("dist") or {}).get("signatures"):
            return "npm registry signature present"
        return ""
    if ecosystem == "pypi":
        signed = [u for u in info.get("urls") or [] if u.get("has_sig")]
        if signed:
            return f"{len(signed)} artifact(s) carry a detached signature"
        return ""
    return ""


def compare_manifests(repo, artifact):
    """Findings that name exactly what differs; generated/minified bytes are not compared."""
    findings = []
    tool = "release"
    if repo["name"] != artifact["name"] and artifact["name"]:
        findings.append(finding(tool, "high", "(release)", 0,
                                 f"release-drift: artifact name {artifact['name']} != repo {repo['name']}",
                                 f"{artifact['name']} vs {repo['name']}",
                                 "The published package is not the repository you scanned."))
    if repo["version"] and artifact["version"] and repo["version"] != artifact["version"]:
        findings.append(finding(tool, "high", "(release)", 0,
                                 f"release-drift: artifact version {artifact['version']} != repo {repo['version']}",
                                 f"{artifact['version']} vs {repo['version']}",
                                 "The registry version does not match the repository at the resolved tag."))
    for hook in NPM_INSTALL_HOOKS if repo["ecosystem"] == "npm" else ():
        before, after = repo["hooks"].get(hook), artifact["hooks"].get(hook)
        if after and not before:
            findings.append(finding(tool, "high", "(release)", 0,
                                     f"release-drift: artifact adds install hook {hook}",
                                     str(after), "The registry artifact runs a command the repository manifest does not."))
        elif before and not after:
            findings.append(finding(tool, "medium", "(release)", 0,
                                     f"release-drift: artifact drops install hook {hook}",
                                     str(before), "The published package no longer runs the hook the repository declares."))
        elif before != after and after:
            findings.append(finding(tool, "high", "(release)", 0,
                                     f"release-drift: install hook {hook} differs",
                                     f"{before} -> {after}", "The registry artifact runs a different command."))
    for name in sorted(set(artifact["deps"]) - set(repo["deps"])):
        findings.append(finding(tool, "high", "(release)", 0,
                                 f"release-drift: artifact adds dependency {name}",
                                 artifact["deps"][name], "A dependency the repository does not declare ships in the package."))
    for name in sorted(set(repo["deps"]) & set(artifact["deps"])):
        if repo["deps"][name] != artifact["deps"][name]:
            findings.append(finding(tool, "medium", "(release)", 0,
                                     f"release-drift: dependency {name} range differs",
                                     f"{repo['deps'][name]} -> {artifact['deps'][name]}",
                                     "Semantic manifest difference; generated files are not compared."))
    for name in sorted(set(repo["deps"]) - set(artifact["deps"]))[:10]:
        findings.append(finding(tool, "info", "(release)", 0,
                                 f"release-drift: repo dependency {name} absent from artifact",
                                 repo["deps"][name], "The published package no longer depends on a repo dependency."))
    return findings


def cmd_release(a):
    """Compares a published registry artifact with the repository at the release tag (network, except overrides)."""
    if not SLUG_RE.fullmatch(a.slug):
        print(f"release: {a.slug!r} is not an owner/repo slug", file=sys.stderr)
        return 2
    work = tempfile.mkdtemp(prefix="repobeagle-release-")
    try:
        tag = a.tag or latest_release_tag(a.slug)
        if not tag:
            print(f"release: cannot resolve a release tag for {a.slug}", file=sys.stderr)
            return 2
        if a.repo:
            repo_root = Path(a.repo)
            if not repo_root.is_dir():
                print(f"release: --repo {a.repo} is not a directory", file=sys.stderr)
                return 2
        else:
            from .fetch import fetch_repo
            try:
                repo_root, _how, _commit = fetch_repo(f"https://github.com/{a.slug}.git", work, ref=tag)
            except SystemExit as ex:
                print(f"release: cannot fetch {a.slug}@{tag}: {ex}", file=sys.stderr)
                return 2
        ecosystem, repo_manifest_path, repo_data = find_manifest(repo_root)
        if ecosystem is None:
            print(f"release: no package.json/pyproject.toml/Cargo.toml in {a.slug}@{tag}", file=sys.stderr)
            return 2
        repo = manifest_summary(ecosystem, repo_data)
        if a.ecosystem != "auto":
            ecosystem = a.ecosystem
        package = a.package or repo["name"]
        if not package:
            print("release: cannot determine the published package name", file=sys.stderr)
            return 2
        if a.registry_json:
            registry = _read_json(a.registry_json)
        elif ecosystem == "npm":
            registry = _registry_fetch(f"https://registry.npmjs.org/{package}")
        elif ecosystem == "pypi":
            registry = _registry_fetch(f"https://pypi.org/pypi/{package}/json")
        elif ecosystem == "crates":
            registry = _registry_fetch(f"https://crates.io/api/v1/crates/{package}")
        else:
            print(f"release: unsupported ecosystem {ecosystem}", file=sys.stderr)
            return 2
        version, info = _release_version(registry, ecosystem, package)
        if a.version:
            version = a.version
            if ecosystem == "npm" and isinstance(registry.get("versions"), dict) and version in registry["versions"]:
                info = registry["versions"][version]
        artifact_dir = Path(work) / "artifact"
        if a.tarball:
            tarball = Path(a.tarball)
        else:
            url = _artifact_url(ecosystem, package, version, info)
            if not url:
                print(f"release: no downloadable artifact for {package}@{version}", file=sys.stderr)
                return 2
            tarball = Path(work) / ("artifact" + (".zip" if url.endswith(".zip") else ".tgz"))
            _github_download(url, tarball, RELEASE_ARTIFACT_MAX_BYTES)
        summary = safe_extract(tarball, artifact_dir)
        if summary.get("format") is None or summary.get("encrypted"):
            print(f"release: cannot inspect {tarball} ({summary.get('note') or summary.get('format')})", file=sys.stderr)
            return 2
        art_ecosystem, _art_path, art_data = find_manifest(artifact_dir)
        if art_ecosystem is None:
            print("release: artifact has no package manifest", file=sys.stderr)
            return 2
        artifact = manifest_summary(art_ecosystem, art_data)
        findings = compare_manifests(repo, artifact)
        if version and artifact["version"] and version != artifact["version"]:
            findings.append(finding("release", "high", "(release)", 0,
                                     f"release-drift: registry lists {version} but the artifact manifest says {artifact['version']}",
                                     f"{version} vs {artifact['version']}",
                                     "The registry resolved a different version than the artifact contains."))
        evidence = provenance_evidence(ecosystem, info)
        if evidence:
            findings.append(finding("release", "info", "(release)", 0,
                                     f"release-provenance: {evidence}", str(version),
                                     "The registry metadata carries build provenance / signature evidence for this version."))
        else:
            findings.append(finding("release", "low", "(release)", 0,
                                     "no-provenance: registry metadata has no attestation or signature",
                                     f"{ecosystem} {package}@{version}",
                                     "A publish can differ from this repo; provenance would tie the artifact to a build."))
        files = {"repo": inventory(repo_root), "artifact": inventory(artifact_dir)}
        drift = [f for f in findings if f["title"].startswith("release-drift") and f["severity"] in ("high", "medium")]
        for f in sorted(findings, key=lambda x: (-{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[x["severity"]],
                                                  x["title"]))[:RELEASE_FINDING_CAP]:
            print(f"  {f['severity'].upper():<8} {f['title']}  [{f['snippet']}]")
        print(f"release: {a.slug}@{tag} -> {ecosystem} {package}@{version}  "
              f"{'DRIFT' if drift else 'consistent'}  ({len(findings)} finding(s), "
              f"files repo {files['repo']['files']} / artifact {files['artifact']['files']})")
        if a.json:
            Path(a.json).write_text(json.dumps({
                "slug": a.slug, "tag": tag, "ecosystem": ecosystem, "package": package,
                "version": version, "repo": repo, "artifact": artifact, "files": files,
                "provenance": evidence or None, "findings": findings,
                "verdict": "DRIFT" if drift else "CONSISTENT"}, indent=2), encoding="utf-8")
            print(f"[repobeagle] JSON written to {a.json}", file=sys.stderr)
        return 1 if any(f["severity"] == "high" for f in drift) else 0
    finally:
        shutil.rmtree(work, ignore_errors=True)
