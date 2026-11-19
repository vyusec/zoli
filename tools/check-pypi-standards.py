#!/usr/bin/env python3
"""Compare the Go oracle with an independent, installed PyPA packaging library.

This is a development diagnostic, not a runtime dependency or a pip resolver.
Known differences are asserted explicitly; aggregate differences are reported,
not mislabeled as compliance. Run Rust conformance tests on the same fixtures.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path

import packaging
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "testdata/conformance"


def compare(a, b):
    try:
        left, right = Version(a), Version(b)
        return (left > right) - (left < right)
    except InvalidVersion:
        return None


def matches(constraint, version):
    try:
        # Default PyPA prerelease handling; no dependency resolution is claimed.
        return SpecifierSet(constraint).contains(Version(version))
    except (InvalidSpecifier, InvalidVersion):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    concrete = json.loads((FIXTURES / "pypi-matrix.json").read_text())
    constraints = json.loads((FIXTURES / "pypi-constraints.json").read_text())
    seeded = json.loads(gzip.decompress((FIXTURES / "pypi-seeded.json.gz").read_bytes()))
    comparisons = [(c["a"], c["b"], None if c["error"] else c["order"]) for c in concrete]
    match_cases = [(c["constraint"], c["version"], None if c["error"] else c["match"]) for c in constraints]
    by_pair = {(a,b): value for a,b,value in comparisons}
    by_match = {(a,b): value for a,b,value in match_cases}
    # Each entry gives independently expected Go and PyPA answers. A change in
    # either is an explicit review event, not a silently accepted new baseline.
    known = [
        ("comparison", "1.0+ABC", "1.0+abc", -1, 0),
        ("comparison", "1.0.post1+abc", "1.0.post1+xyz", 0, -1),
        ("comparison", "1.0a1", "1.0a1.post0", 0, -1),
        ("comparison", "255!1", "256!1", None, -1),
        ("constraint", ">1,<=1", "1", True, False),
        ("constraint", ">=1.0,<2", "1.0+abc", False, True),
        ("constraint", "!=1,!=2,!=1,!=2", "1", True, False),
        ("constraint", "<2,!=2!0", "1", False, True),
    ]
    differences = []
    for kind, a, b, go, pypa in known:
        actual_go = (by_pair if kind == "comparison" else by_match)[a,b]
        actual_pypa = (compare if kind == "comparison" else matches)(a,b)
        assert actual_go == go and actual_pypa == pypa, (kind,a,b,actual_go,actual_pypa)
        differences.append(dict(kind=kind, left=a, right=b, go=go, pypa=pypa))
    hashes = {name: hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest() for name in ["pypi-matrix.json", "pypi-constraints.json", "pypi-seeded.json.gz"]}
    report = {"packaging_version": packaging.__version__, "fixture_sha256": hashes, "seed": seeded["seed"], "known_differences": differences, "aggregate": {}}
    for name, cases, function in [
        ("comparisons", comparisons + seeded["comparisons"], compare),
        ("constraints", match_cases + seeded["matches"], matches),
    ]:
        count = 0
        examples = []
        for a,b,expected in cases:
            actual = function(a,b)
            if actual != expected:
                count += 1
                if len(examples) < 10:
                    examples.append(dict(left=a,right=b,go=expected,pypa=actual))
        report["aggregate"][name] = dict(cases=len(cases), differences=count, examples=examples)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"packaging_version": packaging.__version__, "known_differences": len(known), "aggregate": {k: {n:v for n,v in values.items() if n != "examples"} for k,values in report["aggregate"].items()}}, indent=2))


if __name__ == "__main__":
    main()
