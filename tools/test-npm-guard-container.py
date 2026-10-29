#!/usr/bin/env python3
"""Run the real npm fixtures in Docker with no external network or host mounts.

Linux-only development gate. Packages the locally built test, Zoli, Node/npm,
shell and their shared libraries; this is not a portable release-image test.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import uuid


def run(*args, **kwargs):
    try:
        return subprocess.run(args, check=True, **kwargs)
    except subprocess.CalledProcessError as error:
        if error.stdout:
            print(error.stdout)
        if error.stderr:
            print(error.stderr)
        raise


repo = Path(__file__).resolve().parents[1]
os.chdir(repo)
build = run(
    "cargo", "test", "-p", "zoli-cli", "--locked", "--test", "npm_guard",
    "--no-run", "--message-format=json", capture_output=True, text=True,
)
test = next(
    Path(item["executable"])
    for line in build.stdout.splitlines()
    if (item := json.loads(line)).get("executable")
    and item.get("target", {}).get("name") == "npm_guard"
)
image = "zoli-npm-guard-test:" + uuid.uuid4().hex
with tempfile.TemporaryDirectory(prefix="zoli-container-") as directory:
    context = Path(directory)
    root = context / "root"
    root.mkdir()

    def copy(source, destination=None):
        source = Path(source)
        target = root / str(destination or source).lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target, follow_symlinks=True)

    def binary(source, destination=None):
        copy(source, destination)
        libs = run("ldd", str(source), capture_output=True, text=True).stdout
        for library in re.findall(r"(/[^\s()]+)", libs):
            copy(library)

    for name in ["node", "sh", "env", "cp"]:
        binary(shutil.which(name), "/bin/" + name)
    (root / "usr/bin").mkdir(parents=True, exist_ok=True)
    (root / "usr/bin/env").symlink_to("/bin/env")
    # Distribution npm packages may use an absolute versioned Node shebang.
    node = Path(shutil.which("node")).resolve()
    copy(node)
    if not (root / "usr/bin/node").exists():
        (root / "usr/bin/node").symlink_to("/bin/node")
    npm = Path(shutil.which("npm")).resolve()
    shutil.copytree(npm.parent.parent, root / "opt/npm", symlinks=False)
    (root / "bin/npm").symlink_to("/opt/npm/bin/npm-cli.js")
    binary(test)
    binary(repo / "target/debug/zoli")
    copy(repo / "testdata/mock-registry/tls/ca.pem")
    # Keep compile-time paths resolvable, including lexical ../.. in CA paths.
    (root / str(repo / "crates/zoli-cli").lstrip("/")).mkdir(parents=True)
    (root / "tmp").mkdir()
    (context / "Dockerfile").write_text(
        "FROM scratch\nCOPY root /\nENV PATH=/bin\n"
        + "ENTRYPOINT " + json.dumps([str(test), "--test-threads=1", "--nocapture"]) + "\n"
    )
    try:
        run("docker", "build", "--network=none", "--tag", image, str(context))
        run(
            "docker", "run", "--rm", "--network=none", "--read-only",
            "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--user", "65534:65534", "--pids-limit=256", "--memory=2g",
            "--tmpfs", "/tmp:rw,exec,nosuid,size=1g,mode=1777", image,
        )
    finally:
        subprocess.run(["docker", "image", "rm", image], check=False)
