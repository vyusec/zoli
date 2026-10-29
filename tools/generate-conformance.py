#!/usr/bin/env python3
"""Run the Go oracle in a temporary intel-feed copy; never edit the source repo."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / "testdata" / "conformance"
GENERATED = ("wire-strings.tsv", "record-encoding.json", "identities.json", "queries.json", "feed-cases.json", "npm-matrix.json", "pypi-matrix.json")


def generator_files():
    return [*sorted((ROOT / "tools/conformance-gen").glob("*.go")), ROOT / "tools/conformance-client/transport.go"]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def source_files(source):
    # Inventory all build inputs, including local replace modules, instead of
    # depending on a clean Git checkout. The local handoff may have no .git.
    files = []
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if any(part in {".git", "target", "node_modules", "bin"} for part in relative.parts):
            continue
        if path.is_symlink():
            raise ValueError(f"source symlink must be resolved explicitly: {relative}")
        if path.is_file() and (path.suffix in {".go", ".sql"} or path.name in {"go.mod", "go.sum", "LICENSE", "NOTICE"}):
            files.append((relative, path.read_bytes()))
    return files


def git_commit(source):
    # A parent repository is not evidence of this module's revision.
    if not (source / ".git").exists():
        return None
    result = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=True)
    return result.stdout.strip()


def verify_committed():
    """Check committed provenance without Go or an upstream checkout (for CI)."""
    provenance = json.loads((DESTINATION / "PROVENANCE.json").read_text())
    if provenance["schema"] != 1 or provenance["families"] != list(GENERATED):
        raise ValueError("unsupported or incomplete fixture provenance")
    if set(provenance["fixtures"]) != set(GENERATED):
        raise ValueError("fixture hash inventory is incomplete")
    expected_sources = {
        "generator_sha256": ROOT / "tools" / "conformance-gen" / "main.go",
        "wrapper_sha256": Path(__file__),
    }
    for key, path in expected_sources.items():
        if digest(path.read_bytes()) != provenance[key]:
            raise ValueError(f"{path.name} changed; regenerate the conformance corpus")
    sources = {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in generator_files()}
    if provenance["generator_files"] != sources:
        raise ValueError("generator source inventory changed; regenerate the corpus")
    inventory = json.dumps(provenance["source_files"], sort_keys=True, separators=(",", ":")).encode()
    if digest(inventory) != provenance["source_tree_sha256"]:
        raise ValueError("source-tree inventory does not match provenance")
    for name in GENERATED:
        if digest((DESTINATION / name).read_bytes()) != provenance["fixtures"][name]:
            raise ValueError(f"{name} changed; regenerate fixtures instead of editing them")
    print(f"Committed fixture hashes and generator provenance are consistent ({len(GENERATED)} families).")


def run(args):
    source = args.intel_feed.resolve()
    if source == ROOT or ROOT in source.parents or source in ROOT.parents:
        raise ValueError("--intel-feed must name a separate source module")
    if "module zoli.dev/intel-feed" not in (source / "go.mod").read_text():
        raise ValueError("--intel-feed must be the zoli.dev/intel-feed module")
    generator = ROOT / "tools" / "conformance-gen" / "main.go"
    inputs = source_files(source)
    inventory = [{"path": str(path), "sha256": digest(data)} for path, data in inputs]
    tree_bytes = json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    provenance = {
        "schema": 1,
        "generator_sha256": digest(generator.read_bytes()),
        "generator_files": {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in generator_files()},
        "wrapper_sha256": digest(Path(__file__).read_bytes()),
        "intel_feed_commit": git_commit(source),
        "source_tree_sha256": digest(tree_bytes),
        "source_tree_scope": "All .go, .sql (go:embed), go.mod, go.sum, LICENSE and NOTICE files, excluding .git, bin, target and node_modules; before generator overlay",
        "go_version": subprocess.run(["go", "version"], check=True, capture_output=True, text=True).stdout.strip(),
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "families": list(GENERATED),
        "limitations": [
            "A null intel_feed_commit means the source has no Git metadata; the inventoried build inputs identify this local baseline.",
            "Query fixtures share an explicit clock and cover selected freshness boundaries; the corpus is finite.",
            "PyPI comparison and exact/event queries are covered; constraint-string matching and pip installation remain separate gates.",
            "Live-delivery and resource-ceiling tests are separate gates; fixtures do not demonstrate deployed service readiness.",
        ],
        "source_files": inventory,
    }
    if args.check:
        old = json.loads((DESTINATION / "PROVENANCE.json").read_text())
        provenance["generated_at"] = old["generated_at"]

    # This copy is the actual hashed build input. Neither source files nor
    # upstream internal-package visibility are changed to run the oracle.
    with tempfile.TemporaryDirectory(prefix="zoli-conformance-") as temporary:
        temporary = Path(temporary)
        module = temporary / "intel-feed"
        for relative, data in inputs:
            target = module / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        overlay = module / "cmd" / "conformance-gen"
        if overlay.exists():
            raise ValueError("upstream already has cmd/conformance-gen; reconcile the generators first")
        overlay.mkdir(parents=True)
        for path in sorted(generator.parent.glob("*.go")):
            shutil.copyfile(path, overlay / path.name)
        shutil.copyfile(ROOT / "tools/conformance-client/transport.go", module / "pkg/client/zoli_conformance.go")
        output = temporary / "output"
        environment = os.environ.copy()
        # Task-local Go cache keeps this offline tool inside writable roots.
        environment.setdefault("GOCACHE", str(ROOT / "target" / "go-conformance-cache"))
        environment["GOPROXY"] = "off"
        environment["GOSUMDB"] = "off"
        environment["GOTOOLCHAIN"] = "local"
        environment["GOWORK"] = "off"
        environment["GOFLAGS"] = "-mod=readonly -p=1"
        environment.setdefault("GOMAXPROCS", "1")
        subprocess.run(["go", "run", "./cmd/conformance-gen", "--out", str(output)],
                       cwd=module, env=environment, check=True)
        if args.rust_caches:
            subprocess.run(["go", "run", "./cmd/conformance-gen", "--verify-rust-caches", str(args.rust_caches.resolve())],
                           cwd=module, env=environment, check=True)
        provenance["fixtures"] = {name: digest((output / name).read_bytes()) for name in GENERATED}
        (output / "PROVENANCE.json").write_text(json.dumps(provenance, indent=2, ensure_ascii=False) + "\n")
        names = (*GENERATED, "PROVENANCE.json")
        if args.check:
            changed = [name for name in names if not (DESTINATION / name).exists()
                       or (DESTINATION / name).read_bytes() != (output / name).read_bytes()]
            if changed:
                raise ValueError("generated fixtures differ: " + ", ".join(changed))
            print("Conformance fixtures and provenance reproduce exactly.")
        else:
            DESTINATION.mkdir(parents=True, exist_ok=True)
            for name in names:
                shutil.copyfile(output / name, DESTINATION / name)
            print(f"Generated {len(GENERATED)} fixture families in {DESTINATION}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--intel-feed", type=Path, help="local intel-feed source directory (read only)")
    parser.add_argument("--rust-caches", type=Path, help="also authenticate exported Rust caches with Go client.Load")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check", action="store_true", help="regenerate in temporary storage and compare, without writing fixtures")
    modes.add_argument("--verify", action="store_true", help="check committed hashes without Go or an upstream checkout")
    args = parser.parse_args()
    if not args.verify and args.intel_feed is None:
        parser.error("--intel-feed is required for generation and --check")
    if args.verify and args.intel_feed is not None:
        parser.error("--verify does not use --intel-feed; use --check to regenerate")
    if args.verify and args.rust_caches:
        parser.error("--rust-caches requires the Go oracle, not --verify")
    try:
        if args.verify:
            verify_committed()
        else:
            run(args)
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"conformance generation failed: {error}\n")


if __name__ == "__main__":
    main()
