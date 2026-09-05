// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyDetectsArtifactCorruption(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "extraction")
	d, err := newDisk(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.put("payload.bin", []byte("original")); err != nil {
		d.Close()
		t.Fatal(err)
	}
	if err := writeIntegrity(d); err != nil {
		d.Close()
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := Verify(dir, "")
	if err != nil || !result.Verified || result.Artifacts != 1 {
		t.Fatalf("initial verify result=%+v err=%v", result, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "payload.bin"), []byte("modified"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir, ""); err == nil || !strings.Contains(err.Error(), "artifact hash/size mismatch") {
		t.Fatalf("corruption error = %v", err)
	}
}

func TestVerifyRejectsUnsafeLedgerPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "extraction")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	ledger := []byte(`{"schema":1,"artifacts":[{"path":"../outside","type":"file","size":0,"sha256":""}]}`)
	if err := os.WriteFile(filepath.Join(dir, "integrity.json"), ledger, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir, ""); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("unsafe ledger error = %v", err)
	}
}

func TestWriteIntegrityIgnoresIncidentalDSStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "extraction")
	d, err := newDisk(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.put("payload.bin", []byte("payload")); err != nil {
		d.Close()
		t.Fatal(err)
	}
	// Finder metadata is present before the ledger is written, then changes as
	// the user browses the directory. It must remain outside the ledger.
	if err := d.put(".DS_Store", []byte("finder-v1")); err != nil {
		d.Close()
		t.Fatal(err)
	}
	if err := writeIntegrity(d); err != nil {
		d.Close()
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".DS_Store"), []byte("finder-v2"), 0644); err != nil {
		t.Fatal(err)
	}
	result, err := Verify(dir, "")
	if err != nil || !result.Verified {
		t.Fatalf("incidental .DS_Store should be ignored: result=%+v err=%v", result, err)
	}
	var ledger Integrity
	b, err := os.ReadFile(filepath.Join(dir, "integrity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &ledger); err != nil {
		t.Fatal(err)
	}
	for _, artifact := range ledger.Artifacts {
		if artifact.Path == ".DS_Store" {
			t.Fatal("incidental .DS_Store was recorded in the ledger")
		}
	}
}

func TestWriteIntegrityTracksDeclaredArchiveDSStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "extraction")
	d, err := newDisk(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.put("rootfs/.DS_Store", []byte("archive-v1")); err != nil {
		d.Close()
		t.Fatal(err)
	}
	manifest := []Entry{{Path: ".DS_Store", StoredPath: ".DS_Store", Type: "file", Size: int64(len("archive-v1")), SHA256: digest([]byte("archive-v1"))}}
	if err := d.json("rootfs-manifest.json", manifest); err != nil {
		d.Close()
		t.Fatal(err)
	}
	if err := writeIntegrity(d); err != nil {
		d.Close()
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := Verify(dir, "")
	if err != nil || !result.Verified {
		t.Fatalf("declared archive .DS_Store should verify: result=%+v err=%v", result, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rootfs", ".DS_Store"), []byte("archive-v2"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir, ""); err == nil || !strings.Contains(err.Error(), "artifact hash/size mismatch: rootfs/.DS_Store") {
		t.Fatalf("declared archive .DS_Store corruption error = %v", err)
	}
}
