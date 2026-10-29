// SPDX-License-Identifier: Apache-2.0
package main

import "deps.dev/util/semver"

func npmMatrix(dir string) error {
	type matchCase struct {
		Constraint string `json:"constraint"`
		Version    string `json:"version"`
		Error      bool   `json:"error"`
		Match      bool   `json:"match"`
	}
	type compareCase struct {
		A     string `json:"a"`
		B     string `json:"b"`
		Error bool   `json:"error"`
		Order int    `json:"order"`
	}
	versions := []string{"0", "0.0", "0.0.0", "0.0.0-0", "0.0.0-alpha", "0.0.1", "0.1.0", "0.2.3", "1", "1.2", "1.2.0", "1.2.3", "1.2.4", "1.3.0", "2.0.0", "3.1.0", "1.2.3-alpha", "1.2.3-alpha.1", "1.2.3-beta.1", "1.2.3-01", "1.2.3-1", "1.2.3+build", "v1.2.3", "vv1.2.3", "01.02.003", "1-beta", "1.2-beta", "1.2.3.4", "1.x", "*", "bad", "", "1.2.3+", "1.2.3-", "1.2.3-a..b", "9223372036854775807.0.0", "1.2.3-9223372036854775808"}
	constraints := []string{"", "*", "x", "X", "1", "1.2", "1.2.3", "=1.2.3", "= 1.2.3", "==1.2.3", ">1", ">1.2", ">1.2.3", ">=1.2.3", "<1.2.3", "<=1.2.3", "<=1.2", "<0.0.0", "<0.0.0-beta", ">*", ">=x", "<x", "<=x", "1.x", "1.x.2", "1.*.*", "^1.2.3", "^0.2.3", "^0.0.1", "^0.0", "^0", "^*", "~1.2.3", "~1.2", "~1", "~>1.2", "~>1.2.3", "1.0.0 - 2.0.0", "1.2 - 2", "1.2.3 || >=3.0.0", ">=1.0.0 <2.0.0", ">=1.2.3-beta.0 <2", ">1.2.3-alpha", "1.2.3-alpha || 1.2.3-beta.1", "1-beta", "1.2-beta", "!=1.2.3", ">=1.0.0, <2.0.0", ">=1.0.0<2.0.0", "1.2.3 ||", "||", "1.2.3 | 2.0.0", "v1.2.x", "01.02.003", "1.2.3\n<2", "\n1.2.3\n"}
	matches := []matchCase{}
	comparisons := []compareCase{}
	for _, c := range constraints {
		parsed, ce := semver.NPM.ParseConstraint(c)
		for _, raw := range versions {
			v, ve := semver.NPM.Parse(raw)
			entry := matchCase{Constraint: c, Version: raw, Error: ce != nil || ve != nil || (ve == nil && v.IsWildcard())}
			if !entry.Error {
				entry.Match = parsed.MatchVersion(v)
			}
			matches = append(matches, entry)
		}
	}
	for _, a := range versions {
		for _, b := range versions {
			av, ae := semver.NPM.Parse(a)
			bv, be := semver.NPM.Parse(b)
			entry := compareCase{A: a, B: b, Error: ae != nil || be != nil || (ae == nil && av.IsWildcard()) || (be == nil && bv.IsWildcard())}
			if !entry.Error {
				entry.Order = av.Compare(bv)
			}
			comparisons = append(comparisons, entry)
		}
	}
	return writeJSON(dir, "npm-matrix.json", struct {
		Matches     []matchCase   `json:"matches"`
		Comparisons []compareCase `json:"comparisons"`
	}{matches, comparisons})
}
