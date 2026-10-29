// SPDX-License-Identifier: Apache-2.0
package main

import "zoli.dev/intel-feed/internal/model"

func pypiMatrix(dir string) error {
	type comparison struct {
		A     string `json:"a"`
		B     string `json:"b"`
		Error bool   `json:"error"`
		Order int    `json:"order"`
	}
	versions := []string{
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
	comparisons := []comparison{}
	for _, a := range versions {
		for _, b := range versions {
			order, err := model.Compare("PyPI", a, b)
			comparisons = append(comparisons, comparison{a, b, err != nil, order})
		}
	}
	return writeJSON(dir, "pypi-matrix.json", comparisons)
}
