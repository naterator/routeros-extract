// SPDX-License-Identifier: BSD-3-Clause
package data

import (
	"bytes"
	"strings"
	"testing"

	"github.com/CalebQ42/squashfs/internal/decompress"
)

func TestFullReaderRejectsOversizedEncodedBlock(t *testing.T) {
	f := NewFullReader(bytes.NewReader(nil), decompress.NewZlib(), 4096, 1, 0, []uint32{0x00ffffff})
	if _, err := f.Block(0); err == nil || !strings.Contains(err.Error(), "exceeds the 1 MiB maximum") {
		t.Fatalf("Block error = %v", err)
	}
	if err := f.AddFragData(0, 0x00ffffff, 0); err == nil || !strings.Contains(err.Error(), "exceeds the 1 MiB maximum") {
		t.Fatalf("AddFragData error = %v", err)
	}
}

func TestFullReaderRejectsInvalidFragmentOffset(t *testing.T) {
	// A flagged block is uncompressed, so no decoder input is required.
	f := NewFullReader(bytes.NewReader([]byte("fragment")), decompress.NewZlib(), 4096, 4, 0, nil)
	if err := f.AddFragData(0, uint32(len("fragment"))|1<<24, 100); err == nil || !strings.Contains(err.Error(), "fragment offset") {
		t.Fatalf("AddFragData error = %v", err)
	}
}
