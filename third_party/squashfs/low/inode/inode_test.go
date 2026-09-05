// SPDX-License-Identifier: BSD-3-Clause
package inode

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestReadEFileRejectsHugeBlockTable(t *testing.T) {
	dat := make([]byte, 40)
	binary.LittleEndian.PutUint64(dat[8:16], ^uint64(0))
	_, err := ReadEFile(strings.NewReader(string(dat)), 4096)
	if err == nil || !strings.Contains(err.Error(), "too many data blocks") {
		t.Fatalf("ReadEFile error = %v", err)
	}
}

func TestReadSymlinkRejectsHugeTarget(t *testing.T) {
	dat := make([]byte, 8)
	binary.LittleEndian.PutUint32(dat[4:], ^uint32(0))
	if _, err := ReadSym(strings.NewReader(string(dat))); err == nil || !strings.Contains(err.Error(), "target is too large") {
		t.Fatalf("ReadSym error = %v", err)
	}
	if _, err := ReadESym(strings.NewReader(string(dat))); err == nil || !strings.Contains(err.Error(), "target is too large") {
		t.Fatalf("ReadESym error = %v", err)
	}
}

func TestReadEDirRejectsHugeIndexName(t *testing.T) {
	dat := make([]byte, 24+12)
	binary.LittleEndian.PutUint16(dat[16:18], 1)
	binary.LittleEndian.PutUint32(dat[24+8:], 256)
	if _, err := ReadEDir(strings.NewReader(string(dat))); err == nil || !strings.Contains(err.Error(), "index name is too large") {
		t.Fatalf("ReadEDir error = %v", err)
	}
}
