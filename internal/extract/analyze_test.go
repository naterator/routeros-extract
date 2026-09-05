// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeAnalysisFixture(t *testing.T, files map[string][]byte) string {
	t.Helper()
	directory := t.TempDir()
	entries := make([]Entry, 0, len(files))
	for name, data := range files {
		stored := name
		entries = append(entries, Entry{
			Path:       name,
			StoredPath: stored,
			Type:       "file",
			Mode:       "0o100644",
			SHA256:     digest(data),
		})
		full := filepath.Join(directory, "rootfs", filepath.FromSlash(stored))
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "rootfs-manifest.json"), manifest, 0644); err != nil {
		t.Fatal(err)
	}
	metadata := Metadata{Sections: []Section{{Type: 0x15, ExtractedTo: "rootfs"}}}
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "metadata.json"), metadataBytes, 0644); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestAnalyzeKeepsIncidentalMalformedPayloadsBestEffort(t *testing.T) {
	badELF := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{0}, 12)...)
	badWebFig := []byte("this is not gzip")
	directory := writeAnalysisFixture(t, map[string][]byte{
		"bin/broken":       badELF,
		"webfig/broken.gz": badWebFig,
	})

	got, err := Analyze(directory, Options{})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if got.WebfigDecodedFiles != 0 {
		t.Fatalf("WebfigDecodedFiles = %d, want 0", got.WebfigDecodedFiles)
	}
	if len(got.ELFCounts) != 0 {
		t.Fatalf("ELFCounts = %#v, want empty", got.ELFCounts)
	}
	for _, want := range []string{
		"ELF rootfs/bin/broken:",
		"WebFig rootfs/webfig/broken.gz:",
		"original retained",
	} {
		found := false
		for _, note := range got.Notes {
			if strings.Contains(note, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Notes = %#v, missing %q", got.Notes, want)
		}
	}
	for name, want := range map[string][]byte{
		"rootfs/bin/broken":       badELF,
		"rootfs/webfig/broken.gz": badWebFig,
	} {
		gotBytes, err := os.ReadFile(filepath.Join(directory, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("read preserved %s: %v", name, err)
		}
		if !bytes.Equal(gotBytes, want) {
			t.Errorf("preserved %s changed", name)
		}
	}
	for _, name := range []string{"derived/summary.json", "integrity.json"} {
		if _, err := os.Stat(filepath.Join(directory, filepath.FromSlash(name))); err != nil {
			t.Errorf("expected analysis output %s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(directory, "derived/webfig/broken")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("malformed WebFig output stat error = %v, want not exist", err)
	}
}

func TestAnalyzeWebFigDecodedLimitRemainsFatal(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(bytes.Repeat([]byte("x"), 64)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	directory := writeAnalysisFixture(t, map[string][]byte{
		"webfig/oversized.gz": compressed.Bytes(),
	})

	_, err := Analyze(directory, Options{MaxBytes: 32})
	if err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("Analyze() error = %v, want decoded-size limit error", err)
	}
	got, readErr := os.ReadFile(filepath.Join(directory, "rootfs/webfig/oversized.gz"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(got, compressed.Bytes()) {
		t.Fatal("oversized WebFig original changed")
	}
}
