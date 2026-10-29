#!/usr/bin/env python3
"""Negative control for Phase 2: a warm npm cache bypasses a dead proxy.

Only generated, inert packages are installed in a temporary project. A lifecycle
script writes one local marker. No real registry or user npm configuration is used.
"""
import base64
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import threading
from datetime import datetime, timezone


def archive(name, dependencies):
    manifest = {"name": name, "version": "1.0.0", "dependencies": dependencies}
    if name == "zoli-cache-child":
        manifest["scripts"] = {"postinstall": 'node -e "require(\'fs\').writeFileSync(\'zoli-hook-ran\',\'inert fixture\')"'}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as writer:
        data = json.dumps(manifest).encode()
        entry = tarfile.TarInfo("package/package.json")
        entry.size, entry.mode = len(data), 0o644
        writer.addfile(entry, io.BytesIO(data))
    return buf.getvalue()


def main():
    npm = shutil.which("npm")
    if not npm:
        raise SystemExit("npm is required")
    artifacts = {
        "zoli-cache-parent": archive("zoli-cache-parent", {"zoli-cache-child": "1.0.0"}),
        "zoli-cache-child": archive("zoli-cache-child", {}),
    }
    requests = []

    class Registry(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            name = self.path.removeprefix("/").removesuffix(".tgz")
            if name not in artifacts:
                self.send_error(404)
                return
            body = artifacts[name]
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    with tempfile.TemporaryDirectory(prefix="zoli-npm-cache-") as work:
        root = Path(work)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Registry)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = f"http://127.0.0.1:{server.server_port}"
        env = {"PATH": os.environ["PATH"], "HOME": work, "CI": "1"}
        config = root / "empty-npmrc"
        config.write_text("")
        global_config = root / "global-npmrc"
        global_config.write_text("")
        project = {"name": "zoli-cache-probe", "version": "1.0.0", "dependencies": {"zoli-cache-parent": "1.0.0"}}
        (root / "package.json").write_text(json.dumps(project))
        packages = {"": project}
        for name, data in artifacts.items():
            packages[f"node_modules/{name}"] = {
                "version": "1.0.0", "resolved": f"{origin}/{name}.tgz",
                "integrity": "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode(),
                "hasInstallScript": name == "zoli-cache-child",
                "dependencies": {"zoli-cache-child": "1.0.0"} if name == "zoli-cache-parent" else {},
            }
        (root / "package-lock.json").write_text(json.dumps({"name":project["name"], "version":"1.0.0", "lockfileVersion":3, "packages":packages}))
        args = [npm, "ci", "--audit=false", "--fund=false", "--cache", str(root / "cache"),
                "--registry", origin, "--userconfig", str(config), "--globalconfig", str(global_config)]

        def run(extra, environment):
            completed = subprocess.run(args + extra, cwd=root, env=environment, capture_output=True, text=True, timeout=60)
            if completed.returncode:
                raise RuntimeError(completed.stdout + completed.stderr)

        try:
            run(["--ignore-scripts"], env)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        marker = root / "node_modules/zoli-cache-child/zoli-hook-ran"
        assert not marker.exists(), "seed must not run lifecycle scripts"
        shutil.rmtree(root / "node_modules")
        dead_proxy = "http://127.0.0.1:1"
        env.update({"HTTP_PROXY":dead_proxy, "HTTPS_PROXY":dead_proxy, "http_proxy":dead_proxy,
                    "https_proxy":dead_proxy, "npm_config_proxy":dead_proxy, "npm_config_https_proxy":dead_proxy,
                    "NO_PROXY":"", "no_proxy":""})
        run(["--offline"], env)
        assert marker.read_text() == "inert fixture", "warm-cache transitive lifecycle was not observed"
        print(json.dumps({
            "schema":1, "measured_at":datetime.now(timezone.utc).isoformat(),
            "node":subprocess.check_output(["node", "--version"], text=True).strip(),
            "npm":subprocess.check_output([npm, "--version"], text=True, env=env).strip(),
            "seed_artifact_requests":len(requests), "registry_stopped":True,
            "proxy_unreachable":True, "offline_install_succeeded":True,
            "transitive_lifecycle_executed_from_cache":True,
            "conclusion":"Proxy-only interception cannot enforce approval for warm-cache npm ci",
            "limitations":["Negative control using inert fixtures; no Zoli install guard is implemented", "Linux host npm only; Docker and other package managers remain ungated"],
        }, indent=2))


if __name__ == "__main__":
    main()
