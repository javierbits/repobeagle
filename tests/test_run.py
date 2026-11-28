"""`repobeagle run`: parse the runner, resolve the package repo, and apply the run/refuse policy."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import repobeagle as rb

FLAGS = ["--no-docker", "--no-osv", "--no-trust", "--no-cache", "--no-color"]
RAN = "print('RAN')"


def run(*args, stdin=""):
    return subprocess.run([sys.executable, "repobeagle.py", "run", *args], cwd=ROOT, capture_output=True,
                          text=True, timeout=900, input=stdin, env=dict(os.environ, XDG_CACHE_HOME=tempfile.mkdtemp()))


def wrapped(*args):
    return [*FLAGS, "--", sys.executable, "-c", *args]


def test_parse_run_package():
    cases = [
        (["npx", "-y", "cowsay"], ("npm", "cowsay")),
        (["npx", "--yes", "@scope/tool@1.2.3"], ("npm", "@scope/tool")),
        (["pnpm", "dlx", "left-pad@1.3.0"], ("npm", "left-pad")),
        (["yarn", "dlx", "some-cli"], ("npm", "some-cli")),
        (["bunx", "prettier@3"], ("npm", "prettier")),
        (["pipx", "run", "black==24.1.0"], ("pypi", "black")),
        (["uvx", "ruff"], ("pypi", "ruff")),
        (["cargo", "install", "ripgrep", "--locked"], ("crates", "ripgrep")),
        (["hf", "download", "owner/model"], ("huggingface", "https://huggingface.co/owner/model")),
        (["hf", "download", "--local-dir", "/tmp/x", "owner/model"], ("huggingface", "https://huggingface.co/owner/model")),
        (["hf", "download", "--repo-type", "dataset", "owner/data"], ("huggingface", "https://huggingface.co/datasets/owner/data")),
        (["huggingface-cli", "download", "https://huggingface.co/spaces/a/b/"], ("huggingface", "https://huggingface.co/spaces/a/b")),
        (["python3", "-c", "pass"], (None, None)),
        (["npx"], (None, None)),
        (["hf", "upload", "owner/model"], (None, None)),
        (["hf", "download"], (None, None)),
    ]
    for argv, want in cases:
        assert rb.parse_run_package(argv) == want, (argv, rb.parse_run_package(argv), want)
    assert rb._hf_download_spec(["hf", "download", "--revision", "v1.2", "owner/model"]) == \
        ("https://huggingface.co/owner/model", "v1.2")
    assert rb._hf_download_spec(["hf", "download", "--repo-type=dataset", "--revision=refs/pr/1", "o/d"]) == \
        ("https://huggingface.co/datasets/o/d", "refs/pr/1")
    assert rb._repo_url("git+https://github.com/a/b.git") == "https://github.com/a/b"
    assert rb._repo_url("https://github.com/a/b/") == "https://github.com/a/b"
    assert rb._repo_url("https://gitlab.com/a/b.git") == "https://gitlab.com/a/b"
    assert rb._repo_url("https://example.com/docs") is None
    print("PASS run package parsing and repository URL normalization")


def test_registry_lookup_and_cache():
    calls = []
    payloads = {
        "https://registry.npmjs.org/pkg": {"repository": {"url": "git+https://github.com/acme/pkg.git"}},
        "https://pypi.org/pypi/tool/json": {"info": {"project_urls": {"Source": "https://github.com/acme/tool"},
                                                    "home_page": "https://acme.dev/tool"}},
        "https://crates.io/api/v1/crates/rip": {"crate": {"repository": "https://github.com/acme/rip"}},
    }
    orig = rb._registry_fetch
    def fake(url):
        calls.append(url)
        return payloads[url]
    try:
        rb._registry_fetch = fake
        with tempfile.TemporaryDirectory() as td:
            os.environ["XDG_CACHE_HOME"] = td
            try:
                rb._RULE_IDS  # no-op; keep caches independent
                assert rb.registry_repo("npm", "pkg") == "https://github.com/acme/pkg"
                assert rb.registry_repo("pypi", "tool") == "https://github.com/acme/tool"
                assert rb.registry_repo("crates", "rip") == "https://github.com/acme/rip"
                assert len(calls) == 3, calls
                assert rb.registry_repo("npm", "pkg") == "https://github.com/acme/pkg"
                assert len(calls) == 3, "a cache hit must not refetch"
                os.environ["BEAGLE_REGISTRY_TTL"] = "0"
                rb.registry_repo("npm", "pkg")
                assert len(calls) == 4, "ttl=0 must refetch"
                os.environ.pop("BEAGLE_REGISTRY_TTL")
                cache = Path(td) / "repobeagle" / "registry" / "npm_pkg.json"
                assert json.loads(cache.read_text())["repo"] == "https://github.com/acme/pkg"
            finally:
                os.environ.pop("XDG_CACHE_HOME", None)
    finally:
        rb._registry_fetch = orig
    print("PASS registry lookup (npm/pypi/crates), cache hit and TTL refetch")


def test_policy_and_passthrough():
    r = run("--repo", "tests/fixtures/control-clean", *wrapped(RAN))
    assert r.returncode == 0 and "RAN" in r.stdout, (r.returncode, r.stdout, r.stderr)

    r = run("--repo", "tests/fixtures/trap-npm", *wrapped(RAN))
    assert r.returncode == 1 and "RAN" not in r.stdout, (r.returncode, r.stdout)
    assert "refusing to run" in r.stderr and "CRITICAL" in r.stderr

    r = run("--repo", "tests/fixtures/trap-npm", "--force", *wrapped(RAN))
    assert r.returncode == 0 and "RAN" in r.stdout, (r.returncode, r.stdout, r.stderr)

    r = run("--repo", "tests/fixtures/trap-markdown", *wrapped(RAN))     # YELLOW, not a TTY
    assert r.returncode == 1 and "RAN" not in r.stdout and "without --yes/--force" in r.stderr, r.stderr

    r = run("--repo", "tests/fixtures/trap-markdown", "--yes", *wrapped(RAN))
    assert r.returncode == 0 and "RAN" in r.stdout, (r.returncode, r.stderr)

    r = run("--repo", "tests/fixtures/trap-npm", "--dry-run", *wrapped(RAN))
    assert r.returncode == 0 and "RAN" not in r.stdout and ": RED (" in r.stderr, (r.returncode, r.stderr)

    r = run("--repo", "tests/fixtures/control-clean", *wrapped("import sys; sys.exit(7)"))
    assert r.returncode == 7, (r.returncode, r.stderr)
    print("PASS GREEN runs, RED refuses/--force, YELLOW needs --yes, --dry-run, exit code passthrough")


def test_unknown_runner_and_explicit_repo():
    r = run(*wrapped(RAN))
    assert r.returncode == 1 and "cannot tell which package" in r.stderr, r.stderr
    r = run("--repo", "tests/fixtures/control-clean", *wrapped("print('RAN')"))
    assert r.returncode == 0 and "RAN" in r.stdout
    with tempfile.TemporaryDirectory() as td:
        r = run("--repo", str(Path(td) / "missing"), *wrapped(RAN))   # unscannable -> no report -> refuse
        assert r.returncode == 1 and "refusing to run" in r.stderr and "RAN" not in r.stdout,             (r.returncode, r.stdout, r.stderr)
    print("PASS unknown runner needs --repo; --repo accepts arbitrary commands")


if __name__ == "__main__":
    test_parse_run_package()
    test_registry_lookup_and_cache()
    test_policy_and_passthrough()
    test_unknown_runner_and_explicit_repo()
    print("run tests passed")
