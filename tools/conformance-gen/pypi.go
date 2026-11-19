// SPDX-License-Identifier: Apache-2.0
package main

import (
	"deps.dev/util/semver"
	"zoli.dev/intel-feed/internal/model"
)

func pypiVersions() []string {
	return []string{
		"0", "1", "1.0", "1.0.0", "01.00.0", "1.0.0.0", "1.0.0.1", "1.1", "2.0",
		"1.0.dev0", "1.0dev1", "1.0a0", "1.0alpha1", "1.0a1.dev1", "1.0a1", "1.0a1.post0", "1.0a1.post1",
		"1.0b1", "1.0beta2", "1.0rc1", "1.0c1", "1.0pre1", "1.0preview1", "1.0RC1",
		"1.0.post0", "1.0.post1", "1.0.post1.dev1", "1.0-1", "1.0rev1", "1.0r1", "1.0_post_1", "1.0dev",
		"1.0+abc", "1.0+ABC", "1.0+abc.1", "1.0+abc.2", "1.0+abc.10", "1.0+1", "1.0+01", "1.0+1.0", "1.0+abc-1", "1.0+abc_1",
		"1.0rc1+abc", "1.0.post1+abc", "1.0.post1+xyz", "1.0+abc..x", "1.0+abc..", "1.0+", "1.0+é",
		"v1.0", "V1.0", "vv1.0", "v1!1.0", "1!v1.0", "0!1.0", "1!1.0", "2!0", "255!1", "256!1",
		"1a", "1A", "1..a1", "1.", "1..0", "1.*", "*", "1x", "", "bad", " 1.0", "1.0 ", "1.0\n", "1.0\n2",
		"9223372036854775806", "9223372036854775807", "18446744073709551616", "1.0rc18446744073709551616", "1.0rc9223372036854775808",
	}
}

func pypiMatrix(dir string) error {
	type comparison struct {
		A     string `json:"a"`
		B     string `json:"b"`
		Error bool   `json:"error"`
		Order int    `json:"order"`
	}
	versions := pypiVersions()
	comparisons := []comparison{}
	for _, a := range versions {
		for _, b := range versions {
			order, err := model.Compare("PyPI", a, b)
			comparisons = append(comparisons, comparison{a, b, err != nil, order})
		}
	}
	if err := writeJSON(dir, "pypi-matrix.json", comparisons); err != nil {
		return err
	}
	return pypiConstraints(dir)
}

// Exercise the actual feed library, including its non-PEP-440 edge cases.
// Cross-products include malformed inputs; no result is hand-authored.
func pypiConstraints(dir string) error {
	type matchCase struct {
		Constraint string `json:"constraint"`
		Version    string `json:"version"`
		Error      bool   `json:"error"`
		Match      bool   `json:"match"`
	}
	constraints := []string{"", " ", "*", "1.0", "=1.0", "===1.0", "~=1", "==*", "==1.x", "==1.*.2", "==1.*.*", "!=1.*.*", "!=1.*.2", "==1.*rc1", "==1.*.0rc1", "==1.0.*.post1", "~=1.2.3.4", ">=1!1.0,<2!0", "==1!1.0", "!=1!1.0", "==256!1", "==1.0_post_1", "==1.0rc18446744073709551616", ">=1.0rc18446744073709551616", "==1.0+abc_1", ">=1.0 <2", ">=1.0<2", ">=1.0,", ",>=1.0", ">=1.0,,<2", ">=1.0 || <2", "==1.0\n<2", "\n==1.0\n", "==1.0; python_version>='3'", "==1.0\x00", "==1.0é", "==1.0\t", "==1.0,1.0", "==1.0,1.*", "==1.0,=1.0", "==1.0,==1.0", "==1.0,!=1.0", ">=2,<1", ">=1,<=1", ">1,<=1", ">=1,<1", "<1,>=1", "<=1,>1", "!=0", "<0", "<=0", "<0.dev1", "<=0.dev1", "~=0.0", "~=0.0.0"}
	for _, op := range []string{"==", "!=", ">", ">=", "<", "<=", "~="} {
		for _, v := range []string{"0", "1", "1.0", "1.0.0", "1.0.0.0", "1.*", "1.0.*", "1.0a1", "1.0rc1", "1.0.dev1", "1.0.post1", "1.0+abc", "1!1.0", "255!1", "9223372036854775806"} {
			constraints = append(constraints, op+v)
		}
	}
	for _, left := range []string{">=0", ">=1.0", ">1.0", ">=1.0a1", "<=2", "==1.*", "!=1.0", "!=1.0.*", "!=1.0a1", "!=1!1.0"} {
		for _, right := range []string{"<2", "<=1.0", "!=1.0", "!=1.0.*", "!=1.0a1", ">=1.0.dev1", "==1.0+abc", "!=1!1.0"} {
			constraints = append(constraints, left+","+right)
		}
	}
	// Three-way intersections exercise exclusion fragments after an earlier
	// intersection, including cases that become a point or an empty interval.
	for _, left := range []string{">=0", ">=1.0rc1", ">=1!1", "==1.*"} {
		for _, middle := range []string{"<=2", "!=1", "!=1.*", "!=1.0a1"} {
			for _, right := range []string{"<2!1", "!=1.0.post1", "!=1.1", "==1.0"} {
				constraints = append(constraints, left+","+middle+","+right)
			}
		}
	}
	versions := append(pypiVersions(), "0.dev0", "0.dev1", "0a1", "0.post1", "0+abc", "0!0", "1.0.1", "1.0.1a1", "1.0.1.post1", "1.2.3.4", "1.2.3.5", "1.2.4", "1.2", "2.0a1", "2.0.post1", "1!0", "1!1.0a1", "1!1.0.post1", "2!1.0")
	// Minimized failures from seed 0x5a4f4c493033 and independent properties.
	constraints = append(constraints, "<2,!=2!0", "!=2!0.0.dev0,<=1", "!=255!0-2,!=1!1", "!=1,!=2", "!=1,!=2,!=1,!=2")
	cases := []matchCase{}
	for _, c := range constraints {
		parsed, ce := semver.PyPI.ParseConstraint(c)
		for _, raw := range versions {
			v, ve := semver.PyPI.Parse(raw)
			entry := matchCase{Constraint: c, Version: raw, Error: ce != nil || ve != nil || (ve == nil && v.IsWildcard())}
			if !entry.Error {
				entry.Match = parsed.MatchVersion(v)
			}
			cases = append(cases, entry)
		}
	}
	return writeJSON(dir, "pypi-constraints.json", cases)
}
