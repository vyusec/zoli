// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"zoli.dev/intel-feed/pkg/client"
)

func verifyRustCaches(dir string) error {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no Rust caches supplied")
	}
	for _, path := range files {
		encoded, err := os.ReadFile(strings.TrimSuffix(path, ".json") + ".key")
		if err != nil {
			return err
		}
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
		if err != nil {
			return err
		}
		if _, err = client.Load(path, key); err != nil {
			return fmt.Errorf("Rust cache %s: %w", filepath.Base(path), err)
		}
	}
	fmt.Printf("Go client.Load authenticated %d Rust-written caches.\n", len(files))
	return nil
}
