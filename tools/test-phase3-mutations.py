#!/usr/bin/env python3
"""Bounded negative controls in a temporary source copy; never mutate the checkout.

Run sequentially inside the documented local CPU scope. Copy cached dependency
artifacts into an isolated target: NEVER share workspace binaries/fingerprints.
A compile failure or timeout is NOT a killed mutation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MUTATIONS = [
    ("reverse-comparison", "crates/zoli-intel/src/pypi.rs",
     "Ok(Version::parse(a)?.cmp(&Version::parse(b)?))", "Ok(Version::parse(a)?.cmp(&Version::parse(b)?).reverse())",
     "zoli-intel", "pypi_properties", "ordinary_suffix_chain_is_antisymmetric_and_transitive"),
    ("extra-constraint-term", "crates/zoli-intel/src/pypi/constraints.rs",
     "const MAX_TERMS: usize = 128;", "const MAX_TERMS: usize = 129;",
     "zoli-intel", "pypi_limits", "constraint_limits_validate_the_entire_expression"),
    ("ignore-input-gaps", "crates/zoli-pms/src/requirements.rs",
     "self.gaps.is_empty() && !self.packages.is_empty()", "!self.packages.is_empty()",
     "zoli-pms", "requirements", "unsupported_inputs_are_never_hidden_among_valid_pins"),
    ("release-before-audit", "crates/zoli-cli/src/output.rs",
     "    audit(home, &bytes)?;", "    let _ = home; // deliberate mutation: unaudited output",
     "zoli-cli", "pypi_failures", "audit_parent_failure_cannot_emit_an_unaudited_clean_report"),
]


def copy_dependency_cache(target):
    """Copy immutable external dependency artifacts, never hard-link outputs.

    Workspace artifacts and incremental caches must be rebuilt in isolation.
    Otherwise a mutated binary can outlive its source copy and poison a later
    normal Cargo run, even when all original source files are unchanged.
    """
    debug = target / "debug"
    debug.mkdir(parents=True)
    for name in [".fingerprint", "build"]:
        original = ROOT / "target/debug" / name
        if original.exists():
            shutil.copytree(original, debug / name, ignore=shutil.ignore_patterns("zoli-*"))
    (debug / "deps").mkdir()
    for path in (ROOT / "target/debug/deps").iterdir():
        if path.is_file() and not path.name.startswith(("libzoli_", "zoli_")) and path.suffix in {".rlib", ".rmeta", ".so", ".d"}:
            shutil.copy2(path, debug / "deps" / path.name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    results = []
    binary = ROOT / "target/debug/zoli"
    before_binary = hashlib.sha256(binary.read_bytes()).hexdigest() if binary.exists() else None
    environment = os.environ.copy()
    environment.update(CARGO_BUILD_JOBS="1", RUST_TEST_THREADS="1", GOMAXPROCS="1")
    with tempfile.TemporaryDirectory(prefix="zoli-mutation-") as temporary:
        source = Path(temporary) / "zoli"
        shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns(".git", "target", "node_modules", "__pycache__"))
        target = Path(temporary) / "target"
        copy_dependency_cache(target)
        environment["CARGO_TARGET_DIR"] = str(target)
        for name, relative, before, after, crate, suite, test in MUTATIONS:
            path = source / relative
            original = path.read_text()
            assert before in original, f"stale mutation target: {name}"
            path.write_text(original.replace(before, after, 1))
            command = ["cargo", "test", "--offline", "--locked", "-p", crate, "--test", suite, test, "--", "--exact"]
            try:
                with (args.output / f"{name}.log").open("w") as log:
                    run = subprocess.run(command, cwd=source, env=environment, stdout=log, stderr=subprocess.STDOUT, timeout=300)
            finally:
                path.write_text(original)
            output = (args.output / f"{name}.log").read_text()
            killed = run.returncode == 101 and "test result: FAILED. 0 passed; 1 failed;" in output and "panicked at" in output
            results.append(dict(mutation=name, killed=killed, exit_code=run.returncode, test=f"{suite}::{test}"))
            print(f"{name}: {'killed by assertion' if killed else 'FAILED validation'}", flush=True)
            if not killed:
                raise RuntimeError(f"mutation survived or failed to run: {name}; inspect log")
    after_binary = hashlib.sha256(binary.read_bytes()).hexdigest() if binary.exists() else None
    assert before_binary == after_binary, "mutation runner modified the workspace binary"
    (args.output / "results.json").write_text(json.dumps({"mutations": results, "workspace_binary_sha256": after_binary, "workspace_binary_unchanged": True}, indent=2) + "\n")


if __name__ == "__main__":
    main()
