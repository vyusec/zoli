// SPDX-License-Identifier: Apache-2.0
package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"deps.dev/util/semver"
	"zoli.dev/intel-feed/internal/model"
)

// A fixed algorithm/seed, independent of math/rand's implementation. Keep the
// compressed corpus in CI so normal Rust tests need neither Go nor a network.
type seededRandom uint64

func (r *seededRandom) next(n int) int {
	x := uint64(*r)
	x ^= x << 13
	x ^= x >> 7
	x ^= x << 17
	*r = seededRandom(x)
	return int(x % uint64(n))
}

func (r *seededRandom) version() string {
	if r.next(4) == 0 {
		v := pypiVersions()
		return v[r.next(len(v))]
	}
	epoch := []string{"", "", "0!", "1!", "2!", "255!"}[r.next(6)]
	parts := make([]string, 1+r.next(5))
	for i := range parts {
		parts[i] = fmt.Sprint(r.next(5))
	}
	pre := []string{"", "", "a0", "b1", "rc2", "preview1"}[r.next(6)]
	post := []string{"", "", ".post0", "-2"}[r.next(4)]
	dev := []string{"", "", ".dev0", ".dev3"}[r.next(4)]
	local := []string{"", "", "", "+abc", "+ABC.01", "+2"}[r.next(6)]
	return epoch + strings.Join(parts, ".") + pre + post + dev + local
}

func pypiSeeded(dir string) error {
	const seed = 0x5a4f4c493033
	rng := seededRandom(seed)
	comparisons := make([][3]any, 0, 25000)
	for i := 0; i < cap(comparisons); i++ {
		a, b := rng.version(), rng.version()
		// Same-release suffix ordering is rarer in unrelated random pairs.
		if i%3 == 0 {
			a = "1.0" + []string{"a1", "a1.post0", "a1.dev0", "+ABC", "+abc", ".post1+abc", ".post1+xyz", "rc1.dev1"}[rng.next(8)]
			b = "1.0" + []string{"a1", "a1.post1", "a1.dev1", "+abc", "+abc.1", ".post1+abc", ".post1+xyz", "rc1"}[rng.next(8)]
		}
		var expected any
		if order, err := model.Compare("PyPI", a, b); err == nil {
			expected = order
		}
		comparisons = append(comparisons, [3]any{a, b, expected})
	}
	matches := make([][3]any, 0, 75000)
	atoms := []string{">=0", ">=1", ">1", "<=1", "<2", ">=1.0a1", ">=1.0.dev1", "!=1", "!=1.0.*", "!=1!1", "!=1.0a1", "!=1.0.post1", "==1.*", "==1!1.*", "~=1.0", "~=1.0.1", "<=2!1", "<2!0", "==1.0+abc"}
	for i := 0; i < cap(matches); i++ {
		terms := make([]string, 1+rng.next(8))
		for j := range terms {
			if rng.next(5) == 0 {
				terms[j] = []string{"==", "!=", ">", ">=", "<", "<=", "~="}[rng.next(7)] + rng.version()
			} else {
				terms[j] = atoms[rng.next(len(atoms))]
			}
		}
		if i%11 == 0 {
			terms = append(terms, terms[0]) // idempotence, including invalid atoms
		}
		constraint := strings.Join(terms, ",")
		version := rng.version()
		if i%2 == 0 {
			version = []string{"0", "1", "1.0a1", "1.0.dev1", "1.0.post1", "1.1", "2", "1!1", "1!1.5", "1.0+abc"}[rng.next(10)]
		}
		var expected any
		parsed, ce := semver.PyPI.ParseConstraint(constraint)
		v, ve := semver.PyPI.Parse(version)
		if ce == nil && ve == nil && !v.IsWildcard() {
			expected = parsed.MatchVersion(v)
		}
		matches = append(matches, [3]any{constraint, version, expected})
	}
	f, err := os.Create(filepath.Join(dir, "pypi-seeded.json.gz"))
	if err != nil {
		return err
	}
	defer f.Close()
	w := gzip.NewWriter(f) // zero timestamp and no filename: reproducible bytes
	if err := json.NewEncoder(w).Encode(struct {
		Seed        uint64   `json:"seed"`
		Comparisons [][3]any `json:"comparisons"`
		Matches     [][3]any `json:"matches"`
	}{seed, comparisons, matches}); err != nil {
		return err
	}
	return w.Close()
}
