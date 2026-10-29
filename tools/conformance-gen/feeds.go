// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"zoli.dev/intel-feed/internal/feed"
	"zoli.dev/intel-feed/internal/model"
	"zoli.dev/intel-feed/pkg/client"
)

const fixtureBase = "https://feed.example.invalid/feed"

type memoryTransport map[string][]byte

func (m memoryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	b, ok := m[r.URL.String()]
	status := 200
	if !ok {
		status = 404
	}
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(b)), Request: r}, nil
}
func gzipBytes(b []byte) ([]byte, error) {
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	if _, err := w.Write(b); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
func rowBytes(value any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(value); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
func feedFixtures(dir string) error {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	key := ed25519.NewKeyFromSeed(seed)
	public := key.Public().(ed25519.PublicKey)
	type fixture struct {
		Name       string            `json:"name"`
		PublicKey  string            `json:"public_key"`
		Previous   string            `json:"previous_hex,omitempty"`
		Responses  map[string]string `json:"responses"`
		Expected   string            `json:"expected_hex,omitempty"`
		Error      string            `json:"error,omitempty"`
		RustReject bool              `json:"rust_reject,omitempty"`
	}
	cases := []fixture{}
	build := func(records []model.Record, sequence int64) (feed.Manifest, memoryTransport, error) {
		var rows bytes.Buffer
		for i := range records {
			if err := records[i].Validate(); err != nil {
				return feed.Manifest{}, nil, err
			}
			row, err := rowBytes(records[i])
			if err != nil {
				return feed.Manifest{}, nil, err
			}
			rows.Write(row)
		}
		b, err := gzipBytes(rows.Bytes())
		if err != nil {
			return feed.Manifest{}, nil, err
		}
		m := feed.Manifest{SchemaVersion: model.Schema, Sequence: sequence, GeneratedAt: future, RecordCount: len(records), RecordsSHA256: feed.RecordsHash(records), Coverage: model.DefaultCoverage(), Sources: []model.SourceState{{Name: "fixture", LastSuccess: &future, Coverage: "complete"}}, Files: []feed.Artifact{{Path: "snapshot.jsonl.gz", SHA256: model.Hash(b), Bytes: int64(len(b)), Kind: "snapshot", CreatedAt: past}}}
		return m, memoryTransport{fixtureBase + "/snapshot.jsonl.gz": b}, nil
	}
	add := func(name string, m feed.Manifest, responses memoryTransport, previous *client.Snapshot, mutate func(*feed.Envelope), rustReject bool) error {
		envelope, err := feed.Sign(m, key)
		if err != nil {
			return err
		}
		if mutate != nil {
			mutate(&envelope)
		}
		encoded, err := json.Marshal(envelope)
		if err != nil {
			return err
		}
		responses[fixtureBase+"/latest.json"] = encoded
		c := fixture{Name: name, PublicKey: base64.StdEncoding.EncodeToString(public), Responses: map[string]string{}, RustReject: rustReject}
		if previous != nil {
			b, err := json.Marshal(previous)
			if err != nil {
				return err
			}
			c.Previous = hex.EncodeToString(b)
		}
		for url, b := range responses {
			c.Responses[url] = hex.EncodeToString(b)
		}
		oracle, err := client.ConformanceClient(fixtureBase, public, responses)
		if err != nil {
			return err
		}
		out, err := oracle.Update(context.Background(), previous)
		if err != nil {
			c.Error = err.Error()
		} else {
			if _, err = out.Verify(public); err != nil {
				return err
			}
			b, err := json.Marshal(out)
			if err != nil {
				return err
			}
			c.Expected = hex.EncodeToString(b)
		}
		cases = append(cases, c)
		return nil
	}
	baseline, baseResponses, err := build([]model.Record{record()}, 1)
	if err != nil {
		return err
	}
	envelope, err := feed.Sign(baseline, key)
	if err != nil {
		return err
	}
	previous := &client.Snapshot{Envelope: envelope, Records: []model.Record{record()}}
	if _, err = previous.Verify(public); err != nil {
		return err
	}
	for _, name := range []string{"valid-snapshot", "empty-snapshot", "snapshot-file-order", "bad-signature", "wrong-key", "schema", "rollback", "equal-sequence", "equivocation", "artifact-byte", "artifact-size", "record-count", "records-hash", "bad-path-absolute", "bad-path-parent", "bad-path-backslash", "bad-path-empty-component", "short-artifact-hash", "negative-artifact-bytes", "oversize-artifact-descriptor", "missing-full-snapshot", "dot-path", "dotdot-path", "blank-row", "crlf-row", "no-final-newline", "multistream-gzip", "edited-previous-cache", "unknown-row-fields"} {
		records := []model.Record{record()}
		seq := int64(2)
		if name == "empty-snapshot" {
			records = []model.Record{}
		}
		if name == "snapshot-file-order" {
			r := record()
			r.ID = "ZOLI-000000000000000000000000"
			records = append(records, r)
		}
		m, responses, err := build(records, seq)
		if err != nil {
			return err
		}
		var prev *client.Snapshot
		var mutate func(*feed.Envelope)
		reject := false
		switch name {
		case "bad-signature":
			mutate = func(e *feed.Envelope) {
				b, _ := base64.StdEncoding.DecodeString(e.Signature)
				b[0] ^= 1
				e.Signature = base64.StdEncoding.EncodeToString(b)
			}
		case "wrong-key":
			mutate = func(e *feed.Envelope) { e.KeyID = "0000000000000000" }
		case "schema":
			m.SchemaVersion = "99"
		case "rollback":
			m.Sequence = 0
			prev = previous
		case "equal-sequence":
			m = baseline
			responses = memoryTransport{}
			prev = previous
		case "equivocation":
			m.Sequence = 1
			m.RuleSetSHA256 = "changed"
			prev = previous
			reject = true
		case "artifact-byte":
			responses[fixtureBase+"/snapshot.jsonl.gz"][0] ^= 1
		case "artifact-size":
			m.Files[0].Bytes++
		case "record-count":
			m.RecordCount++
		case "records-hash":
			m.RecordsSHA256 = fmt.Sprintf("%064d", 0)
		case "bad-path-absolute":
			m.Files[0].Path = "/absolute"
		case "bad-path-parent":
			m.Files[0].Path = "a/../b"
		case "bad-path-backslash":
			m.Files[0].Path = `a\b`
		case "bad-path-empty-component":
			m.Files[0].Path = "a//b"
		case "short-artifact-hash":
			m.Files[0].SHA256 = "abc"
		case "negative-artifact-bytes":
			m.Files[0].Bytes = -1
		case "oversize-artifact-descriptor":
			m.Files[0].Bytes = 256<<20 + 1
		case "missing-full-snapshot":
			m.Files[0].Ecosystem = "npm"
		case "dot-path", "dotdot-path":
			path := "."
			if name == "dotdot-path" {
				path = ".."
			}
			responses[fixtureBase+"/"+path] = responses[fixtureBase+"/snapshot.jsonl.gz"]
			m.Files[0].Path = path
		case "edited-previous-cache":
			copy := *previous
			copy.Records = []model.Record{record()}
			copy.Records[0].Summary = "tampered"
			prev = &copy
		case "blank-row", "crlf-row", "no-final-newline", "multistream-gzip", "unknown-row-fields":
			row, err := rowBytes(record())
			if err != nil {
				return err
			}
			switch name {
			case "blank-row":
				row = append(row, '\n')
			case "crlf-row":
				row = append(row[:len(row)-1], '\r', '\n')
			case "no-final-newline":
				row = row[:len(row)-1]
			case "unknown-row-fields":
				row = append(append([]byte(`{"future":123,`), row[1:]...), []byte{}...)
			}
			b, err := gzipBytes(row)
			if err != nil {
				return err
			}
			if name == "multistream-gzip" {
				split := len(row) / 2
				a, err := gzipBytes(row[:split])
				if err != nil {
					return err
				}
				z, err := gzipBytes(row[split:])
				if err != nil {
					return err
				}
				b = append(a, z...)
			}
			responses[fixtureBase+"/snapshot.jsonl.gz"] = b
			m.Files[0].SHA256 = model.Hash(b)
			m.Files[0].Bytes = int64(len(b))
		}
		if err := add(name, m, responses, prev, mutate, reject); err != nil {
			return err
		}
	}
	for _, name := range []string{"delta-correction", "delta-withdraw", "delta-remove", "delta-upsert", "missing-delta-fallback", "overshoot-fallback", "bad-delta-hard-error", "invalid-withdraw", "remove-with-record", "unknown-delta-operation", "delta-id-mismatch", "delta-hash-mismatch", "delta-first-descriptor"} {
		r := record()
		r.Summary = "corrected"
		r.Revision = 2
		d := feed.Delta{Operation: "upsert", ID: r.ID, Record: &r}
		switch name {
		case "delta-withdraw":
			r.Status = "withdrawn"
			r.WithdrawnAt = &past
			d.Operation = "withdraw"
		case "delta-remove":
			d.Operation = "remove"
			d.Record = nil
		case "delta-upsert":
			r.ID = "ZOLI-000000000000000000000002"
			d.ID = r.ID
		case "invalid-withdraw":
			d.Operation = "withdraw"
		case "remove-with-record":
			d.Operation = "remove"
		case "unknown-delta-operation":
			d.Operation = "unknown"
		case "delta-id-mismatch":
			d.ID = "different"
		}
		current, applyErr := feed.ApplyDelta(previous.Records, []feed.Delta{d})
		if applyErr != nil {
			current = []model.Record{record()}
		}
		m, responses, err := build(current, 2)
		if err != nil {
			return err
		}
		if name != "missing-delta-fallback" {
			row, err := rowBytes(d)
			if err != nil {
				return err
			}
			b, err := gzipBytes(row)
			if err != nil {
				return err
			}
			desc := feed.Artifact{Path: "delta.jsonl.gz", SHA256: model.Hash(b), Bytes: int64(len(b)), Kind: "delta", FromSequence: 1, ToSequence: 2, CreatedAt: past}
			if name == "overshoot-fallback" {
				desc.ToSequence = 3
			}
			if name == "bad-delta-hard-error" {
				b[0] ^= 1
			}
			if name == "delta-hash-mismatch" {
				m.RecordsSHA256 = fmt.Sprintf("%064d", 0)
			}
			responses[fixtureBase+"/delta.jsonl.gz"] = b
			m.Files = append([]feed.Artifact{desc}, m.Files...)
			if name == "delta-first-descriptor" {
				bad := desc
				bad.Path = "unavailable.jsonl.gz"
				m.Files = append([]feed.Artifact{bad}, m.Files...)
			}
		}
		if err := add(name, m, responses, previous, nil, false); err != nil {
			return err
		}
	}
	_ = baseResponses
	return writeJSON(dir, "feed-cases.json", cases)
}
