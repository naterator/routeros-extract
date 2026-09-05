// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyRejectsInvalidLedger(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Integrity)
		want   string
	}{
		{"unsupported schema", func(l *Integrity) { l.Schema++ }, "unsupported integrity schema"},
		{"empty ledger", func(l *Integrity) { l.Artifacts = nil }, "no artifacts"},
		{"duplicate path", func(l *Integrity) { l.Artifacts = append(l.Artifacts, l.Artifacts[0]) }, "duplicate integrity path"},
		{"unknown type", func(l *Integrity) { l.Artifacts[0].Type = "device" }, "unknown artifact type"},
		{"file as directory", func(l *Integrity) { l.Artifacts[0].Type = "directory" }, "expected directory"},
		{"file as symlink", func(l *Integrity) { l.Artifacts[0].Type = "symlink" }, "expected symlink"},
		{"directory as file", func(l *Integrity) { l.Artifacts[0].Path = "folder" }, "expected regular file"},
		{"missing file", func(l *Integrity) { l.Artifacts[0].Path = "missing" }, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "payload"), []byte("bytes"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(dir, "folder"), 0755); err != nil {
				t.Fatal(err)
			}
			ledger := Integrity{Schema: 1, Artifacts: []Artifact{{Path: "payload", Type: "file", Size: 5, SHA256: digest([]byte("bytes"))}}}
			tc.change(&ledger)
			writeVerificationJSON(t, dir, "integrity.json", ledger)
			result, err := Verify(dir, "")
			if err == nil || result.Verified {
				t.Fatalf("invalid ledger verified: %+v, %v", result, err)
			}
			if tc.want == "" {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("missing artifact error = %v", err)
				}
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestVerifyDetectsSymlinkChanges(t *testing.T) {
	for _, replacement := range []string{"different target", "regular file"} {
		t.Run(replacement, func(t *testing.T) {
			dir := t.TempDir()
			link := filepath.Join(dir, "link")
			// Dangling links are valid extracted metadata; verification must
			// compare the link itself without opening its target.
			if err := os.Symlink("unavailable-target", link); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			refreshVerificationLedger(t, dir)
			if result, err := Verify(dir, ""); err != nil || !result.Verified || result.Artifacts != 1 {
				t.Fatalf("original link: %+v, %v", result, err)
			}
			if err := os.Remove(link); err != nil {
				t.Fatal(err)
			}
			want := "symlink target mismatch"
			if replacement == "regular file" {
				if err := os.WriteFile(link, []byte("unavailable-target"), 0644); err != nil {
					t.Fatal(err)
				}
				want = "expected symlink"
			} else if err := os.Symlink("another-target", link); err != nil {
				t.Fatal(err)
			}
			if result, err := Verify(dir, ""); err == nil || result.Verified || !strings.Contains(err.Error(), want) {
				t.Fatalf("changed link: %+v, %v; want %q", result, err, want)
			}
		})
	}
}

func TestVerifyReconstructsNPKIndependentlyOfLedger(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Metadata)
		want   string
	}{
		{"reordered sections", func(m *Metadata) { m.Sections[0], m.Sections[1] = m.Sections[1], m.Sections[0] }, "inconsistent section metadata"},
		{"wrong payload offset", func(m *Metadata) { m.Sections[0].PayloadOffset++ }, "inconsistent section metadata"},
		{"wrong section hash", func(m *Metadata) { m.Sections[0].SHA256 = strings.Repeat("0", 64) }, "section hash/size mismatch"},
		{"changed section type", func(m *Metadata) { m.Sections[0].Type++ }, "reconstruction hash mismatch"},
		{"missing section", func(m *Metadata) { m.Sections = m.Sections[:1] }, "reconstruction hash mismatch"},
		{"invalid package size", func(m *Metadata) { m.Size = 7 }, "invalid NPK size"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, _, metadata := verificationNPK(t)
			tc.change(&metadata)
			writeVerificationJSON(t, dir, "metadata.json", metadata)
			// Refresh the artifact hashes so this exercises the independent
			// section reconstruction, rather than the file-integrity check.
			refreshVerificationLedger(t, dir)
			if result, err := Verify(dir, ""); err == nil || result.Verified || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Verify = %+v, %v; want %q", result, err, tc.want)
			}
		})
	}
}

func TestVerifySourceRequirements(t *testing.T) {
	dir, source, _ := verificationNPK(t)
	if result, err := Verify(dir, source); err != nil || !result.Verified || !result.SourceVerified || !result.SectionRoundtrip || result.SignatureVerified {
		t.Fatalf("source verification = %+v, %v", result, err)
	}
	if result, err := Verify(dir, ""); err != nil || !result.Verified || result.SourceVerified || !result.SectionRoundtrip {
		t.Fatalf("without source = %+v, %v", result, err)
	}
	if err := os.WriteFile(source, testNPK(testNPKSection{kind: 2, body: []byte("different package")}), 0644); err != nil {
		t.Fatal(err)
	}
	if result, err := Verify(dir, source); err == nil || result.Verified || result.SourceVerified || !strings.Contains(err.Error(), "source NPK mismatch") {
		t.Fatalf("wrong source = %+v, %v", result, err)
	}
	if _, err := Verify(dir, t.TempDir()); err == nil || !strings.Contains(err.Error(), "not a readable regular file") {
		t.Fatalf("directory source error = %v", err)
	}
	standalone := t.TempDir()
	if err := os.WriteFile(filepath.Join(standalone, "payload"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	refreshVerificationLedger(t, standalone)
	if _, err := Verify(standalone, source); err == nil || !strings.Contains(err.Error(), "requires an extracted NPK or ZIP") {
		t.Fatalf("standalone source error = %v", err)
	}
}

func TestVerifyRejectsInconsistentZIPManifest(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*ZIPMetadata)
		want   string
	}{
		{"unknown schema", func(z *ZIPMetadata) { z.Schema++ }, "invalid ZIP package manifest"},
		{"empty package list", func(z *ZIPMetadata) { z.Packages = nil }, "invalid ZIP package manifest"},
		{"unsafe package directory", func(z *ZIPMetadata) { z.Packages[0].Directory = "../outside" }, "unsafe"},
		{"unsafe package path", func(z *ZIPMetadata) { z.Packages[0].NPKPath = "../outside.npk" }, "unsafe"},
		{"wrong member hash", func(z *ZIPMetadata) { z.Packages[0].SHA256 = strings.Repeat("0", 64) }, "ZIP member hash mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := writeTestZIP(t, testZIPMember{name: "test.npk", data: testZIPNPK("addon")})
			dir := filepath.Join(t.TempDir(), "extracted")
			if _, err := ExtractZIP(source, dir, Options{SectionsOnly: true}); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(filepath.Join(dir, "zip-metadata.json"))
			if err != nil {
				t.Fatal(err)
			}
			var metadata ZIPMetadata
			if err := json.Unmarshal(b, &metadata); err != nil {
				t.Fatal(err)
			}
			tc.change(&metadata)
			writeVerificationJSON(t, dir, "zip-metadata.json", metadata)
			refreshVerificationLedger(t, dir)
			if result, err := Verify(dir, source); err == nil || result.Verified || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Verify = %+v, %v; want %q", result, err, tc.want)
			}
		})
	}
}

func verificationNPK(t *testing.T) (string, string, Metadata) {
	t.Helper()
	source := filepath.Join(t.TempDir(), "test.npk")
	data := testNPK(testNPKSection{kind: 2, body: []byte("test package")}, testNPKSection{kind: 0x10, body: []byte("arm64")})
	if err := os.WriteFile(source, data, 0644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "extracted")
	metadata, err := Extract(source, dir, Options{SectionsOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	return dir, source, metadata
}

func writeVerificationJSON(t *testing.T, dir, name string, value any) {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), b, 0644); err != nil {
		t.Fatal(err)
	}
}

func refreshVerificationLedger(t *testing.T, dir string) {
	t.Helper()
	d, err := openDisk(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := writeIntegrity(d); err != nil {
		t.Fatal(err)
	}
}
