// SPDX-License-Identifier: Apache-2.0
// This development-only generator runs inside an unmodified copy of intel-feed.
// It is not part of the Zoli binary. See tools/generate-conformance.py.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"zoli.dev/intel-feed/internal/api"
	"zoli.dev/intel-feed/internal/feed"
	"zoli.dev/intel-feed/internal/model"
)

func main() {
	out := flag.String("out", "", "destination directory")
	caches := flag.String("verify-rust-caches", "", "load and authenticate Rust-written caches")
	flag.Parse()
	if *caches != "" {
		if err := verifyRustCaches(*caches); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr, "--out is required")
		os.Exit(2)
	}
	if err := generate(*out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// QueryAt makes freshness fixtures reproducible at exact clock boundaries.
var queryTime = time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
var past = time.Date(2000, 1, 2, 3, 4, 5, 0, time.UTC)
var future = time.Date(9998, 1, 2, 3, 4, 5, 0, time.UTC)

func generate(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err := stringsFixture(dir); err != nil {
		return err
	}
	if err := recordsFixture(dir); err != nil {
		return err
	}
	if err := identitiesFixture(dir); err != nil {
		return err
	}
	if err := queriesFixture(dir); err != nil {
		return err
	}
	if err := feedFixtures(dir); err != nil {
		return err
	}
	if err := npmMatrix(dir); err != nil {
		return err
	}
	return pypiMatrix(dir)
}

func writeJSON(dir, name string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), append(b, '\n'), 0644)
}

func stringsFixture(dir string) error {
	var cases = []struct{ name, input string }{
		{"empty", ""},
		{"ascii", "package@1.2.3"},
		{"quote-backslash-slash", "\"\\/"},
		{"html", "<script>&</script>"},
		{"line-separators", "before\u2028middle\u2029after"},
		{"non-ascii", "café नमस्ते 日本語 🦀"},
		{"del-c1", "\u007f\u0085\u009f"},
		{"replacement-character", "\ufffd"},
		{"unicode-boundaries", "\u07ff\u0800\ud7ff\ue000\uffff\U00010000\U0010ffff"},
		{"mixed", "<\t>&\n\"\\\u2028🦀"},
	}
	allControls := make([]byte, 32)
	for i := range allControls {
		allControls[i] = byte(i)
		cases = append(cases, struct{ name, input string }{
			fmt.Sprintf("control-%02x", i), string([]byte{byte(i)}),
		})
	}
	cases = append(cases, struct{ name, input string }{"all-controls", string(allControls)})
	// Hex columns keep the test reader independent of Rust's JSON parser and
	// preserve Go's exact output, including escaping and the hash row newline.
	var out bytes.Buffer
	out.WriteString("# name\tutf8_hex\thash_json_hex\tmarshal_json_hex\n")
	for _, c := range cases {
		var hash bytes.Buffer
		enc := json.NewEncoder(&hash)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(c.input); err != nil {
			return err
		}
		marshal, err := json.Marshal(c.input)
		if err != nil {
			return err
		}
		fmt.Fprintf(&out, "%s\t%s\t%s\t%s\n", c.name,
			hex.EncodeToString([]byte(c.input)), hex.EncodeToString(hash.Bytes()), hex.EncodeToString(marshal))
	}
	return os.WriteFile(filepath.Join(dir, "wire-strings.tsv"), out.Bytes(), 0644)
}

func record() model.Record {
	return model.Record{
		SchemaVersion: model.Schema, ID: "ZOLI-000000000000000000000001",
		Classification: "malicious", Status: "published", Summary: "Synthetic conformance record",
		Affected:   []model.Affected{{Package: model.Identity{Ecosystem: "npm", Name: "zoli-fixture", Registry: "https://registry.npmjs.org"}, Versions: []string{"1.2.3"}, Scope: "versions"}},
		Evidence:   []model.Evidence{{Explanation: "Synthetic evidence only"}},
		Sources:    []model.Provenance{{Source: "fixture", ID: "fixture-1", URL: "https://example.invalid/report", License: "Apache-2.0", Revision: "1", RetrievedAt: past}},
		ModifiedAt: past, Revision: 1,
	}
}

func recordsFixture(dir string) error {
	type encodingCase struct {
		Name       string          `json:"name"`
		Record     json.RawMessage `json:"record"`
		HashJSON   string          `json:"hash_json_hex"`
		Marshal    string          `json:"marshal_json_hex"`
		RecordsSHA string          `json:"records_sha256"`
	}
	cases := []encodingCase{}
	add := func(name string, r model.Record) error {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		var hash bytes.Buffer
		enc := json.NewEncoder(&hash)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(r); err != nil {
			return err
		}
		marshal, err := json.Marshal(r)
		if err != nil {
			return err
		}
		cases = append(cases, encodingCase{name, marshal, hex.EncodeToString(hash.Bytes()), hex.EncodeToString(marshal), feed.RecordsHash([]model.Record{r})})
		return nil
	}
	if err := add("zero-published-at", record()); err != nil {
		return err
	}
	r := record()
	r.Summary = "<tag>&\u2028\u2029\x00 café 🦀"
	if err := add("escaping", r); err != nil {
		return err
	}
	r = record()
	r.Aliases, r.References, r.Reviews = []string{}, []string{}, []model.Review{}
	r.Evidence[0].Observations, r.Evidence[0].Limitations = []string{}, []string{}
	if err := add("empty-omitted-slices", r); err != nil {
		return err
	}
	r = record()
	r.PublishedAt = time.Date(2026, 10, 16, 1, 2, 3, 120000000, time.FixedZone("fixture", 19800))
	r.ModifiedAt = time.Date(2026, 10, 16, 1, 2, 3, 123456789, time.UTC)
	r.WithdrawnAt = &past
	r.Aliases = []string{"MAL-fixture"}
	r.Reviews = []model.Review{{Action: "approve", Reviewer: "fixture", Rationale: "Synthetic", At: past, Revision: 1}}
	if err := add("timestamps-and-optionals", r); err != nil {
		return err
	}
	// Validate normalizes the record before RecordsHash, exactly as update does.
	r = record()
	r.SchemaVersion = ""
	r.Affected[0].Package.Ecosystem = "pip"
	r.Affected[0].Package.Name = "Some_Package.Name"
	r.Affected[0].Package.Registry = ""
	r.Affected[0].Scope = ""
	if err := add("normalized-before-hash", r); err != nil {
		return err
	}
	return writeJSON(dir, "record-encoding.json", cases)
}

func identitiesFixture(dir string) error {
	type identityCase struct {
		Name   string          `json:"name"`
		Input  model.Identity  `json:"input"`
		Output *model.Identity `json:"normalized,omitempty"`
		Error  string          `json:"error,omitempty"`
	}
	cases := []identityCase{}
	add := func(name string, p model.Identity) {
		c := identityCase{Name: name, Input: p}
		if err := p.Normalize(); err != nil {
			c.Error = err.Error()
		} else {
			c.Output = &p
		}
		cases = append(cases, c)
	}
	add("npm-default-registry", model.Identity{Ecosystem: "npm", Name: "zoli-fixture", Version: "1.2.3"})
	add("pnpm-alias", model.Identity{Ecosystem: "pnpm", Name: "@scope/fixture", Version: "1.0.0"})
	add("pypi-normalization", model.Identity{Ecosystem: "pip", Name: "Some_Package.Name", Registry: "https://pypi.org/simple/"})
	add("cargo-registry-alias", model.Identity{Ecosystem: "rust", Name: "Some-Crate", Registry: "sparse+https://index.crates.io/"})
	add("registry-host-case", model.Identity{Ecosystem: "npm", Name: "fixture", Registry: "https://REGISTRY.NPMJS.ORG/"})
	add("version-kept-verbatim", model.Identity{Ecosystem: "npm", Name: "fixture", Version: "v1.2.3+build"})
	add("invalid-npm-name", model.Identity{Ecosystem: "npm", Name: "Uppercase"})
	add("unsupported-ecosystem", model.Identity{Ecosystem: "unknown", Name: "fixture"})
	add("registry-credentials", model.Identity{Ecosystem: "npm", Name: "fixture", Registry: "https://user:pass@example.invalid"})
	add("registry-query", model.Identity{Ecosystem: "npm", Name: "fixture", Registry: "https://example.invalid?q=1"})
	add("registry-http", model.Identity{Ecosystem: "npm", Name: "fixture", Registry: "http://example.invalid"})
	add("registry-backslash", model.Identity{Ecosystem: "npm", Name: "fixture", Registry: `https://example.invalid\path`})
	add("registry-bad-escape", model.Identity{Ecosystem: "npm", Name: "fixture", Registry: "https://example.invalid/%GG"})
	add("registry-control", model.Identity{Ecosystem: "npm", Name: "fixture", Registry: "https://example.invalid/\x7f"})
	add("invalid-digest", model.Identity{Ecosystem: "npm", Name: "fixture", SHA256: "abc"})
	return writeJSON(dir, "identities.json", cases)
}

func queriesFixture(dir string) error {
	type queryCase struct {
		Name     string          `json:"name"`
		Query    model.Identity  `json:"query"`
		Manifest feed.Manifest   `json:"manifest"`
		Records  []model.Record  `json:"records"`
		Expected json.RawMessage `json:"expected,omitempty"`
		Marshal  string          `json:"marshal_json_hex,omitempty"`
		Error    string          `json:"error,omitempty"`
	}
	cases := []queryCase{}
	manifest := func() feed.Manifest {
		return feed.Manifest{SchemaVersion: model.Schema, Sequence: 42, GeneratedAt: queryTime,
			Coverage: model.DefaultCoverage(), Sources: []model.SourceState{{Name: "fixture", LastSuccess: &queryTime, Coverage: "complete"}}}
	}
	add := func(name string, q model.Identity, m feed.Manifest, records []model.Record) error {
		for i := range records {
			if err := records[i].Validate(); err != nil {
				return fmt.Errorf("%s record: %w", name, err)
			}
		}
		m.RecordCount = len(records)
		m.RecordsSHA256 = feed.RecordsHash(records)
		c := queryCase{Name: name, Query: q, Manifest: m, Records: records}
		response, err := api.QueryAt(q, m, records, queryTime)
		if err != nil {
			c.Error = err.Error()
		} else if c.Expected, err = json.Marshal(response); err != nil {
			return err
		} else {
			c.Marshal = hex.EncodeToString(c.Expected)
		}
		cases = append(cases, c)
		return nil
	}
	q := model.Identity{Ecosystem: "npm", Name: "zoli-fixture", Version: "1.2.3"}
	for _, v := range []struct{ name, version string }{
		{"exact", "1.2.3"}, {"other-version", "1.2.4"}, {"missing-version", ""},
		{"leading-v", "v1.2.3"}, {"build-metadata", "1.2.3+build"}, {"invalid-version", "not-a-version"},
	} {
		query := q
		query.Version = v.version
		if err := add(v.name, query, manifest(), []model.Record{record()}); err != nil {
			return err
		}
	}
	for _, v := range []struct{ name, constraint, version string }{
		{"x-range", "1.2.x", "1.2.9"}, {"or-range", "1.x || >=3.0.0", "3.1.0"},
		{"hyphen-range", "1.0.0 - 2.0.0", "2.0.0"}, {"caret-range", "^1.2.0", "1.9.0"},
		{"prerelease-excluded", ">=1.0.0 <2.0.0", "1.2.3-beta.1"},
		{"prerelease-included", ">=1.2.3-beta.0 <2.0.0", "1.2.3-beta.1"},
		{"invalid-constraint", "definitely not a constraint", "1.2.3"},
	} {
		r := record()
		r.Affected[0].Versions = nil
		r.Affected[0].Ranges = []model.Range{{Type: "constraint", Constraint: v.constraint}}
		query := q
		query.Version = v.version
		if err := add(v.name, query, manifest(), []model.Record{r}); err != nil {
			return err
		}
	}
	for _, end := range []string{"fixed", "last_affected", "limit"} {
		r := record()
		event := model.Event{}
		switch end {
		case "fixed":
			event.Fixed = "1.2.3"
		case "last_affected":
			event.LastAffected = "1.2.3"
		case "limit":
			event.Limit = "1.2.3"
		}
		r.Affected[0].Versions = nil
		r.Affected[0].Ranges = []model.Range{{Type: "SEMVER", Events: []model.Event{{Introduced: "0"}, event}}}
		if err := add("event-"+end, q, manifest(), []model.Record{r}); err != nil {
			return err
		}
	}
	for _, state := range []string{"withdrawn-status", "withdrawn-at", "unknown-scope", "all-scope", "suspicious"} {
		r := record()
		switch state {
		case "withdrawn-status":
			r.Status = "withdrawn"
		case "withdrawn-at":
			r.WithdrawnAt = &past
		case "unknown-scope":
			r.Affected[0].Versions = nil
			r.Affected[0].Scope = "unknown"
		case "all-scope":
			r.Affected[0].Versions = nil
			r.Affected[0].Scope = "all"
		case "suspicious":
			r.Classification = "suspicious"
		}
		if err := add(state, q, manifest(), []model.Record{r}); err != nil {
			return err
		}
	}
	for _, state := range []string{"current-no-match", "stale-no-match", "degraded-no-match", "degraded-overrides-stale", "missing-source-success", "missing-coverage"} {
		m := manifest()
		switch state {
		case "stale-no-match":
			m.GeneratedAt = past
		case "degraded-no-match":
			m.Sources[0].Error = "synthetic source error"
		case "degraded-overrides-stale":
			m.GeneratedAt = past
			m.Sources[0].LastSuccess = &past
		case "missing-source-success":
			m.Sources[0].LastSuccess = nil
		case "missing-coverage":
			m.Coverage = nil
		}
		if err := add(state, q, m, []model.Record{}); err != nil {
			return err
		}
	}
	for _, state := range []string{"no-sources", "publication-one-hour", "publication-over-one-hour", "source-one-hour", "source-over-one-hour", "publication-future-boundary", "publication-future-exceeded", "source-future-boundary", "source-future-exceeded"} {
		m := manifest()
		stamp := queryTime
		switch state {
		case "no-sources":
			m.Sources = nil
		case "publication-one-hour":
			m.GeneratedAt = queryTime.Add(-time.Hour)
		case "publication-over-one-hour":
			m.GeneratedAt = queryTime.Add(-time.Hour - time.Nanosecond)
		case "source-one-hour":
			stamp = queryTime.Add(-time.Hour)
			m.Sources[0].LastSuccess = &stamp
		case "source-over-one-hour":
			stamp = queryTime.Add(-time.Hour - time.Nanosecond)
			m.Sources[0].LastSuccess = &stamp
		case "publication-future-boundary":
			m.GeneratedAt = queryTime.Add(5 * time.Minute)
		case "publication-future-exceeded":
			m.GeneratedAt = queryTime.Add(5*time.Minute + time.Nanosecond)
		case "source-future-boundary":
			stamp = queryTime.Add(5 * time.Minute)
			m.Sources[0].LastSuccess = &stamp
		case "source-future-exceeded":
			stamp = queryTime.Add(5*time.Minute + time.Nanosecond)
			m.Sources[0].LastSuccess = &stamp
		}
		if err := add(state, q, m, []model.Record{}); err != nil {
			return err
		}
	}
	for _, state := range []string{"normalized-exact", "normalized-version", "other-version", "prerelease", "fixed", "last-affected", "epoch", "local-version", "hash-missing", "hash-match", "hash-mismatch", "private-registry", "withdrawn", "stale", "unknown-scope"} {
		r := record()
		a := &r.Affected[0]
		a.Package = model.Identity{Ecosystem: "PyPI", Name: "some-package", Registry: "https://pypi.org"}
		a.Versions = []string{"1.0"}
		q := model.Identity{Ecosystem: "pip", Name: "Some_Package", Version: "1.0", Registry: "https://pypi.org/simple/"}
		m := manifest()
		switch state {
		case "normalized-version":
			q.Version = "1.0.0"
		case "other-version":
			q.Version = "2.0"
		case "prerelease", "fixed", "last-affected":
			a.Versions = nil
			end := model.Event{Fixed: "1.0"}
			if state == "last-affected" {
				end = model.Event{LastAffected: "1.0"}
			}
			a.Ranges = []model.Range{{Type: "ECOSYSTEM", Events: []model.Event{{Introduced: "1.0rc1"}, end}}}
			if state == "prerelease" {
				q.Version = "1.0rc2"
			}
		case "epoch":
			a.Versions = []string{"1!1.0"}
			q.Version = "1!1.0.0"
		case "local-version":
			a.Versions = []string{"1.0+abc.1"}
			q.Version = "1.0+abc_1"
		case "hash-missing", "hash-match", "hash-mismatch":
			a.Package.SHA256 = fmt.Sprintf("%064d", 1)
			if state == "hash-match" {
				q.SHA256 = a.Package.SHA256
			}
			if state == "hash-mismatch" {
				q.SHA256 = fmt.Sprintf("%064d", 2)
			}
		case "private-registry":
			q.Registry = "https://packages.example.invalid/simple"
		case "withdrawn":
			r.Status = "withdrawn"
		case "stale":
			m.Sources[0].LastSuccess = &past
		case "unknown-scope":
			a.Scope = "unknown"
			a.Versions = nil
		}
		if err := add("pypi-"+state, q, m, []model.Record{r}); err != nil {
			return err
		}
	}
	return writeJSON(dir, "queries.json", cases)
}
