// SPDX-License-Identifier: BSD-3-Clause
package directory

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestReadDirectoryRejectsUnderflowSize(t *testing.T) {
	if _, err := ReadDirectory(strings.NewReader(""), 2); err == nil || !strings.Contains(err.Error(), "invalid SquashFS directory size") {
		t.Fatalf("ReadDirectory error = %v", err)
	}
}

func TestReadDirectoryRejectsOverflowingHeaderCount(t *testing.T) {
	dat := make([]byte, 12)
	binary.LittleEndian.PutUint32(dat, ^uint32(0))
	if _, err := ReadDirectory(strings.NewReader(string(dat)), 15); err == nil || !strings.Contains(err.Error(), "too many entries") {
		t.Fatalf("ReadDirectory error = %v", err)
	}
}

func TestReadDirectoryRejectsTruncatedHeaderEntries(t *testing.T) {
	dat := make([]byte, 12)
	if _, err := ReadDirectory(strings.NewReader(string(dat)), 15); err == nil || !strings.Contains(err.Error(), "exceeds declared size") {
		t.Fatalf("ReadDirectory error = %v", err)
	}
}

func TestReadDirectoryRejectsOversizedName(t *testing.T) {
	dat := make([]byte, 12+8)
	binary.LittleEndian.PutUint32(dat, 0)
	binary.LittleEndian.PutUint16(dat[12+6:], 256)
	if _, err := ReadDirectory(strings.NewReader(string(dat)), uint32(len(dat)+3)); err == nil || !strings.Contains(err.Error(), "entry name is too large") {
		t.Fatalf("ReadDirectory error = %v", err)
	}
}
