"""Agent skill drift guard: documented commands/flags exist, recipes run, fields are real."""
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SKILL = ROOT / "skill" / "SKILL.md"
TEXT = SKILL.read_text(encoding="utf-8")


def run(args, timeout=600):
    return subprocess.run([sys.executable, "repobeagle.py", *args], cwd=ROOT, capture_output=True,
                          text=True, timeout=timeout,
                          env=dict(os.environ, XDG_CACHE_HOME=tempfile.mkdtemp()))


def test_frontmatter_and_manifest():
    m = re.match(r"^---\n(.*?)\n---\n", TEXT, re.S)
    assert m, "SKILL.md must start with YAML frontmatter"
    meta = dict(line.split(":", 1) for line in m.group(1).splitlines() if ":" in line)
    assert meta.get("name", "").strip() == "repobeagle"
    assert len(meta.get("description", "").strip()) > 20
    mcp = json.loads((ROOT / "skill" / "mcp.json").read_text(encoding="utf-8"))
    server = mcp["mcpServers"]["repobeagle"]
    assert server["command"] == "repobeagle" and server["args"] == ["mcp"], server
    r = run(["mcp", "--help"])
    assert r.returncode == 0, r.stderr
    print("PASS skill frontmatter, mcp.json and `repobeagle mcp`")


def invocations():
    """Every `repobeagle …` invocation in the skill (fenced `$` recipes and inline code)."""
    return [m.group(1).strip() for m in re.finditer(r"(?m)(?:^\$ |`)(repobeagle [^`\n]+)", TEXT)]


def test_commands_and_flags_exist():
    checked = 0
    for line in invocations():
        try:
            argv = shlex.split(line)
        except ValueError as ex:
            raise AssertionError(f"unparsable documented command {line!r}: {ex}")
        if "--" in argv:
            argv = argv[:argv.index("--")]
        if argv[1] in ("--version", "-V"):
            out = run(["--version"])
            assert "RepoBeagle" in out.stdout, (line, out.stdout, out.stderr)
            checked += 1
            continue
        sub = next(t for t in argv[1:] if not t.startswith(("-", "[")))
        out = run([sub, "--help"])
        help_text = out.stdout + out.stderr
        assert "usage:" in help_text, f"no help for documented subcommand {sub!r}: {line}"
        for token in argv[1:]:
            if token.startswith("--") and token not in help_text:
                raise AssertionError(f"documented flag {token!r} does not exist for `{sub}`: {line}")
        checked += 1
    assert checked >= 10, f"only {checked} documented invocations parsed"
    print(f"PASS every documented subcommand/flag exists ({checked} invocations)")


def test_recipes_run():
    recipes = [ln.strip()[2:] for ln in TEXT.splitlines() if ln.strip().startswith("$ repobeagle ")]
    assert recipes, "no CI-tested recipes found"
    with tempfile.TemporaryDirectory() as td:
        report = str(Path(td) / "report.json")
        for recipe in recipes:
            argv = [x.replace("{json}", report) for x in shlex.split(recipe)]
            proc = subprocess.run([sys.executable, "repobeagle.py", *argv[1:]], cwd=ROOT, capture_output=True,
                                  text=True, timeout=900, env=dict(os.environ, XDG_CACHE_HOME=tempfile.mkdtemp()))
            assert proc.returncode in (0, 1, 2), (recipe, proc.returncode, proc.stderr[-400:])
            if argv[1] == "--version":
                assert "RepoBeagle" in proc.stdout, proc.stdout
            if "run" == argv[1]:
                assert "ran" in proc.stdout, proc.stdout
            if "--json" in argv:
                doc = json.loads(Path(report).read_text(encoding="utf-8"))
                assert doc["verdict"] in ("GREEN", "YELLOW", "RED") and doc["findings"] is not None, doc.keys()
    print(f"PASS every recipe runs against the fixtures ({len(recipes)})")


def test_documented_fields_are_real():
    section = re.search(r"(?ms)^## Field reference \(JSON\).*?(?=^## )", TEXT)
    assert section, "Field reference section missing"
    report = None
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "report.json"
        r = run(["scan", "tests/fixtures/trap-gha", "--strict", "--no-docker", "--no-osv", "--no-trust",
                 "--no-cache", "--no-color", "--json", str(out)])
        assert out.exists(), r.stderr[-400:]
        report = json.loads(out.read_text(encoding="utf-8"))
    source = (ROOT / "repobeagle.py").read_text(encoding="utf-8")

    def present(path):
        node = report
        for part in path.split("."):
            if not isinstance(node, dict) or part not in node:
                return False
            node = node[part]
        return True

    tokens = set(re.findall(r"`([A-Za-z_][A-Za-z0-9_.|]*)`", section.group(0)))
    fields = {t.split("|")[0] for t in tokens if not t.startswith(("JSON", "GREEN"))}
    assert len(fields) >= 15, sorted(fields)
    missing = []
    for field in fields:
        if present(field):
            continue
        if field in ("verdict", "why", "counts", "findings", "notes"):
            continue
        if f'"{field.split(".")[-1]}"' in source or field.split(".")[-1] in source:
            continue
        missing.append(field)
    assert not missing, f"documented fields absent from reports and source: {sorted(missing)}"
    print(f"PASS every documented JSON field is real ({len(fields)})")


if __name__ == "__main__":
    test_frontmatter_and_manifest()
    test_commands_and_flags_exist()
    test_recipes_run()
    test_documented_fields_are_real()
    print("skill tests passed")
