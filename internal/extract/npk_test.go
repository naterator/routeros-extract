// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type testNPKSection struct {
	kind uint16
	body []byte
}

func testNPK(sections ...testNPKSection) []byte {
	var b bytes.Buffer
	b.Write(npkMagic)
	b.Write(make([]byte, 4))
	for _, s := range sections {
		var h [6]byte
		binary.LittleEndian.PutUint16(h[0:2], s.kind)
		binary.LittleEndian.PutUint32(h[2:6], uint32(len(s.body)))
		b.Write(h[:])
		b.Write(s.body)
	}
	out := b.Bytes()
	binary.LittleEndian.PutUint32(out[4:8], uint32(len(out)-8))
	return out
}

func TestInspectRejectsMalformedNPKFraming(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"short", []byte{0x1e, 0xf1, 0xd0, 0xba}},
		{"magic", []byte{0, 1, 2, 3, 0, 0, 0, 0}},
		{"declared length", func() []byte {
			b := testNPK()
			binary.LittleEndian.PutUint32(b[4:8], 1)
			return b
		}()},
		{"truncated section header", func() []byte {
			b := testNPK()
			return append(b, 1, 0, 0)
		}()},
		{"truncated section body", func() []byte {
			b := testNPK()
			b = append(b, 1, 0, 5, 0, 0, 0, 1, 2)
			binary.LittleEndian.PutUint32(b[4:8], uint32(len(b)-8))
			return b
		}()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Inspect(tc.data, "synthetic.npk"); err == nil {
				t.Fatal("Inspect accepted malformed NPK")
			}
		})
	}
}

func TestInspectPreservesRepeatedSections(t *testing.T) {
	b := testNPK(
		testNPKSection{kind: 0x10, body: []byte("arm64")},
		testNPKSection{kind: 0x10, body: []byte("I")},
		testNPKSection{kind: 0x10, body: []byte("other")},
	)
	m, err := Inspect(b, "synthetic.npk")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Sections) != 3 {
		t.Fatalf("got %d sections, want 3", len(m.Sections))
	}
	for i, s := range m.Sections {
		if s.Index != i || s.Type != 0x10 || s.Label != "architecture_or_trailer" {
			t.Fatalf("section %d was not preserved: %+v", i, s)
		}
		want := "sections/0" + string(rune('0'+i)) + "-0x10-architecture_or_trailer.bin"
		if s.File != want {
			t.Errorf("section %d file = %q, want %q", i, s.File, want)
		}
	}
	if got := m.Sections[0].Text; got != "arm64" {
		t.Errorf("first repeated section text = %q", got)
	}
	if got := m.Sections[1].Text; got != "I" {
		t.Errorf("second repeated section text = %q", got)
	}
}

func TestInspectBoundsTextPreview(t *testing.T) {
	body := make([]byte, maxInlineMetadataBytes+1024)
	for i := range body {
		if i%2 == 0 {
			body[i] = 0xff
		} else {
			body[i] = 'x'
		}
	}
	m, err := Inspect(testNPK(testNPKSection{kind: 7, body: body}), "synthetic.npk")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(m.Sections[0].Text); got > maxInlineMetadataBytes {
		t.Fatalf("text preview length = %d, want at most %d", got, maxInlineMetadataBytes)
	}
	if !m.Sections[0].TextTruncated {
		t.Fatal("shortened text preview was not marked as truncated")
	}
}

func testFileRecordMode(name string, data []byte, tag [4]byte, mode uint16) []byte {
	h := make([]byte, 30)
	binary.LittleEndian.PutUint16(h[0:2], mode)
	binary.LittleEndian.PutUint32(h[8:12], 123)
	copy(h[20:24], tag[:])
	binary.LittleEndian.PutUint32(h[24:28], uint32(len(data)))
	binary.LittleEndian.PutUint16(h[28:30], uint16(len(name)))
	out := append(h, []byte(name)...)
	return append(out, data...)
}

func testFileRecord(name string, data []byte, tag [4]byte) []byte {
	return testFileRecordMode(name, data, tag, 0100644)
}

func testZlib(data []byte) []byte {
	var b bytes.Buffer
	z := zlib.NewWriter(&b)
	if _, err := z.Write(data); err != nil {
		panic(err)
	}
	if err := z.Close(); err != nil {
		panic(err)
	}
	return b.Bytes()
}

func TestDecodeFilesPreservesVariantTags(t *testing.T) {
	raw := append(
		testFileRecord("boot/kernel", []byte("arm kernel"), [4]byte{0, 1, 2, 3}),
		testFileRecord("boot/kernel", []byte("ppc kernel"), [4]byte{4, 5, 6, 7})...,
	)
	_, entries, err := decodeFiles(testZlib(raw), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Path != "boot/kernel" || entries[0].VariantTag != "00010203" {
		t.Fatalf("first variant = %+v", entries[0])
	}
	if entries[1].Path != "boot/kernel.__variant_04050607" || entries[1].ArchivePath != "boot/kernel" || entries[1].VariantTag != "04050607" {
		t.Fatalf("second variant = %+v", entries[1])
	}
	if !bytes.Equal(entries[0].data, []byte("arm kernel")) || !bytes.Equal(entries[1].data, []byte("ppc kernel")) {
		t.Fatal("variant payload was not retained")
	}

	dup := append(testFileRecord("same", []byte("one"), [4]byte{9, 9, 9, 9}), testFileRecord("same", []byte("two"), [4]byte{9, 9, 9, 9})...)
	if _, _, err := decodeFiles(testZlib(dup), Options{}); err == nil || !strings.Contains(err.Error(), "duplicate NPK path") {
		t.Fatalf("duplicate variant tag error = %v", err)
	}
}

func TestDecodeFilesBoundsMetadataAndPreservesRaw(t *testing.T) {
	tag := [4]byte{1, 2, 3, 4}
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{name: "oversized symlink", body: bytes.Repeat([]byte{'x'}, maxInlineMetadataBytes+1)},
		{name: "NUL symlink", body: []byte("target\x00suffix")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := testFileRecordMode("link", tc.body, tag, 0120777)
			if _, _, err := decodeFiles(testZlib(raw), Options{}); err == nil {
				t.Fatal("decodeFiles accepted malformed symlink target")
			}
		})
	}

	for _, tc := range []struct {
		name       string
		body       []byte
		wantInline bool
	}{
		{name: "inline special payload", body: bytes.Repeat([]byte{0xab}, maxInlineMetadataBytes), wantInline: true},
		{name: "raw special payload", body: bytes.Repeat([]byte{0xcd}, maxInlineMetadataBytes+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := testFileRecordMode("device", tc.body, tag, 0020600)
			gotRaw, entries, err := decodeFiles(testZlib(raw), Options{})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotRaw, raw) {
				t.Fatal("decoded container bytes were not preserved")
			}
			if len(entries) != 1 {
				t.Fatalf("got %d entries, want 1", len(entries))
			}
			entry := entries[0]
			if entry.Type != "special_metadata_only" || entry.Size != int64(len(tc.body)) || entry.SHA256 != digest(tc.body) || entry.HeaderHex == "" {
				t.Fatalf("special metadata was not retained: %+v", entry)
			}
			if tc.wantInline && len(entry.PayloadHex) != maxInlineMetadataBytes*2 {
				t.Fatalf("inline payload hex length = %d, want %d", len(entry.PayloadHex), maxInlineMetadataBytes*2)
			}
			if !tc.wantInline && entry.PayloadHex != "" {
				t.Fatal("oversized special payload was inlined")
			}
		})
	}
}

func TestExtractFileContainerHonorsSymlinkOption(t *testing.T) {
	tag := [4]byte{5, 6, 7, 8}
	raw := testFileRecordMode("link", []byte("target"), tag, 0120777)
	source := filepath.Join(t.TempDir(), "sample.npk")
	if err := os.WriteFile(source, testNPK(testNPKSection{kind: 4, body: testZlib(raw)}), 0644); err != nil {
		t.Fatal(err)
	}
	for _, noSymlinks := range []bool{false, true} {
		name := "symlinks-enabled"
		if noSymlinks {
			name = "no-symlinks"
		}
		t.Run(name, func(t *testing.T) {
			// Keep each extraction in a separate destination because Extract
			// intentionally requires a new output directory.
			out := filepath.Join(t.TempDir(), "extracted")
			if _, err := Extract(source, out, Options{MaxBytes: 1 << 20, NoDerived: true, NoSymlinks: noSymlinks}); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(out, "files", "link")
			info, err := os.Lstat(link)
			if noSymlinks {
				if !os.IsNotExist(err) {
					t.Fatalf("symlink output exists with NoSymlinks: info=%v err=%v", info, err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("output type = %s, want symlink", info.Mode())
				}
				target, err := os.Readlink(link)
				if err != nil || target != "target" {
					t.Fatalf("symlink target = %q, err=%v", target, err)
				}
			}
			manifestBytes, err := os.ReadFile(filepath.Join(out, "files-manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			var manifest []Entry
			if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
				t.Fatal(err)
			}
			if len(manifest) != 1 || manifest[0].Type != "symlink" || manifest[0].Target != "target" {
				t.Fatalf("symlink metadata = %+v", manifest)
			}
		})
	}
}

func TestPlanPathsRejectsTraversalAndSymlinkAncestors(t *testing.T) {
	for _, name := range []string{"../escape", "/absolute", "a/../b", "a\\b", "a:b", "a\x00b"} {
		if err := safePath(name); err == nil {
			t.Errorf("safePath accepted %q", name)
		}
	}
	if _, err := planPaths([]Entry{{Path: "link", Type: "symlink"}, {Path: "link/file", Type: "file"}}); err == nil {
		t.Fatal("planPaths accepted a file below a symlink ancestor")
	}
}

func TestPlanPathsCreatesDeterministicCaseAliases(t *testing.T) {
	entries, err := planPaths([]Entry{
		{Path: "A/file", Type: "file"},
		{Path: "a/file", Type: "file"},
		{Path: "a/other", Type: "file"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries", len(entries))
	}
	var aliasCount int
	for _, e := range entries {
		if e.StoredPath != e.Path {
			aliasCount++
			if !strings.Contains(e.StoredPath, ".__case_") {
				t.Errorf("case alias %q lacks deterministic suffix", e.StoredPath)
			}
		}
	}
	if aliasCount != 2 {
		t.Errorf("got %d case aliases, want 2", aliasCount)
	}
}
