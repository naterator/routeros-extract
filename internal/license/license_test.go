// SPDX-License-Identifier: BSD-3-Clause
package license

import (
	"os"
	"testing"
)

func TestTextMatchesLicenseFile(t *testing.T) {
	text, err := os.ReadFile("../../LICENSE")
	if err != nil {
		t.Fatal(err)
	}
	if Text != string(text) {
		t.Fatal("license text is stale; run go generate ./internal/license")
	}
}
