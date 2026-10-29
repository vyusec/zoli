// SPDX-License-Identifier: Apache-2.0
// Development-only transport seam, overlaid into the copied reference module.
package client

import (
	"crypto/ed25519"
	"net/http"
)

// ConformanceClient keeps the production update/verification logic unchanged.
func ConformanceClient(base string, key ed25519.PublicKey, transport http.RoundTripper) (*Client, error) {
	c, err := New(base, key)
	if err != nil {
		return nil, err
	}
	c.http.HTTP.Transport = transport
	return c, nil
}
