// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type testZIPMember struct {
	name   string
	data   []byte
	mode   os.FileMode
	method uint16
}

func testZIPNPK(description string) []byte {
	body := []byte(description)
	section := make([]byte, 6+len(body))
	binary.LittleEndian.PutUint16(section, 2)
	binary.LittleEndian.PutUint32(section[2:], uint32(len(body)))
	copy(section[6:], body)
	out := make([]byte, 8+len(section))
	copy(out, npkMagic)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)-8))
	copy(out[8:], section)
	return out
}

func writeTestZIP(t *testing.T, members ...testZIPMember) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "all_packages.zip")
	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for _, member := range members {
		method := member.method
		if method == 0 {
			method = zip.Store
		}
		h := &zip.FileHeader{Name: member.name, Method: method}
		if member.mode != 0 {
			h.SetMode(member.mode)
		}
		entry, err := w.CreateHeader(h)
		if err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
		if _, err = entry.Write(member.data); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
	}
	if err = w.Close(); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestExtractZIPTwoPackagesAndIgnoredMembers(t *testing.T) {
	first := testZIPNPK("arm package")
	second := testZIPNPK("addon package")
	source := writeTestZIP(t,
		testZIPMember{name: "routeros/arm/routeros-arm.npk", data: first},
		testZIPMember{name: "routeros/arm/README.txt", data: []byte("ignored")},
		testZIPMember{name: "addons/wireless/system.npk", data: second},
	)
	destination := filepath.Join(t.TempDir(), "extracted")
	metas, err := ExtractZIP(source, destination, Options{SectionsOnly: true, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 2 {
		t.Fatalf("got %d package metadata values, want 2", len(metas))
	}
	for _, member := range []string{
		"npk/routeros/arm/routeros-arm.npk",
		"npk/addons/wireless/system.npk",
		"packages/routeros-arm/metadata.json",
		"packages/system/metadata.json",
		"zip-metadata.json",
		"integrity.json",
	} {
		if _, err := os.Stat(filepath.Join(destination, filepath.FromSlash(member))); err != nil {
			t.Errorf("missing output %s: %v", member, err)
		}
	}
	if _, err := os.Stat(filepath.Join(destination, "npk/routeros/arm/README.txt")); !os.IsNotExist(err) {
		t.Errorf("non-NPK member was written: err=%v", err)
	}

	manifest, err := os.ReadFile(filepath.Join(destination, "zip-metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got ZIPMetadata
	if err = json.Unmarshal(manifest, &got); err != nil {
		t.Fatal(err)
	}
	if got.Source != filepath.Base(source) || got.SourceSize <= 0 || got.SourceSHA256 == "" {
		t.Fatalf("source metadata not preserved: %+v", got)
	}
	if len(got.Members) != 3 || len(got.Packages) != 2 {
		t.Fatalf("manifest counts: members=%d packages=%d", len(got.Members), len(got.Packages))
	}
	var foundIgnored bool
	for _, member := range got.Members {
		if member.Name == "routeros/arm/README.txt" {
			foundIgnored = member.Ignored && member.Type == "file" && member.StoredPath == "" && member.SHA256 != ""
		}
	}
	if !foundIgnored {
		t.Fatal("ignored non-NPK member was not listed with its hash")
	}

	for _, want := range [][]byte{first, second} {
		var found bool
		for _, p := range got.Packages {
			b, err := os.ReadFile(filepath.Join(destination, filepath.FromSlash(p.NPKPath)))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(b, want) {
				found = true
				break
			}
		}
		if !found {
			t.Fatal("raw NPK member was not preserved exactly")
		}
	}
}

func TestVerifyZIPCollectionAndDetectsNestedCorruption(t *testing.T) {
	first := testZIPNPK("arm package")
	second := testZIPNPK("addon package")
	source := writeTestZIP(t,
		testZIPMember{name: "routeros/arm/routeros-arm.npk", data: first},
		testZIPMember{name: "addons/wireless/system.npk", data: second},
	)
	destination := filepath.Join(t.TempDir(), "extracted")
	if _, err := ExtractZIP(source, destination, Options{SectionsOnly: true, MaxBytes: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(destination, source)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.Verified || !verified.SectionRoundtrip || !verified.SourceVerified || verified.Packages != 2 {
		t.Fatalf("unexpected ZIP verification result: %+v", verified)
	}

	section := filepath.Join(destination, "packages", "routeros-arm", "sections", "00-0x02-description.bin")
	b, err := os.ReadFile(section)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		t.Fatal("synthetic description section unexpectedly empty")
	}
	b[0] ^= 0xff
	if err = os.WriteFile(section, b, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(destination, source); err == nil || !strings.Contains(err.Error(), "artifact hash/size mismatch") {
		t.Fatalf("corrupted nested section verification error=%v", err)
	}
}

func TestExtractZIPRejectsUnsafeAndDuplicatePaths(t *testing.T) {
	npk := testZIPNPK("package")
	tests := []struct {
		name    string
		members []testZIPMember
		want    string
	}{
		{
			name:    "traversal",
			members: []testZIPMember{{name: "../escape.npk", data: npk}},
			want:    "unsafe ZIP member",
		},
		{
			name: "duplicate",
			members: []testZIPMember{
				{name: "same.npk", data: npk},
				{name: "same.npk", data: npk},
			},
			want: "duplicate ZIP member path",
		},
		{
			name: "case collision",
			members: []testZIPMember{
				{name: "one.npk", data: npk},
				{name: "ONE.npk", data: npk},
			},
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			source := writeTestZIP(t, tc.members...)
			destination := filepath.Join(t.TempDir(), "out")
			_, err := ExtractZIP(source, destination, Options{SectionsOnly: true, MaxBytes: 1 << 20})
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("error=%v, want substring %q", err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, dir := range []string{"packages/one", "packages/ONE.__case_" + digest([]byte("ONE.npk"))[:8]} {
				if _, err := os.Stat(filepath.Join(destination, filepath.FromSlash(dir))); err != nil {
					t.Errorf("missing case-safe package directory %s: %v", dir, err)
				}
			}
		})
	}
}

func TestExtractZIPDoesNotFollowSymlinksAndRequiresNPK(t *testing.T) {
	npk := testZIPNPK("package")
	source := writeTestZIP(t,
		testZIPMember{name: "good.npk", data: npk},
		testZIPMember{name: "escape.npk", data: []byte("../outside"), mode: os.ModeSymlink | 0777},
	)
	destination := filepath.Join(t.TempDir(), "out")
	if _, err := ExtractZIP(source, destination, Options{SectionsOnly: true, MaxBytes: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(destination, "escape.npk")); !os.IsNotExist(err) {
		t.Fatalf("ZIP symlink was materialized: %v", err)
	}
	var manifest ZIPMetadata
	b, err := os.ReadFile(filepath.Join(destination, "zip-metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, member := range manifest.Members {
		if member.Name == "escape.npk" && (member.Type != "symlink" || member.Target != "../outside") {
			t.Fatalf("symlink metadata not retained safely: %+v", member)
		}
	}

	noNPK := writeTestZIP(t, testZIPMember{name: "readme.txt", data: []byte("no package")})
	if _, err = ExtractZIP(noNPK, filepath.Join(t.TempDir(), "none"), Options{MaxBytes: 1 << 20}); err == nil || !strings.Contains(err.Error(), "no regular .npk") {
		t.Fatalf("no-NPK archive error=%v", err)
	}
}

func TestExtractZIPLimitsExpandedContents(t *testing.T) {
	source := writeTestZIP(t, testZIPMember{name: "readme.txt", data: bytes.Repeat([]byte{'x'}, 1<<20), method: zip.Deflate})
	_, err := ExtractZIP(source, filepath.Join(t.TempDir(), "out"), Options{MaxBytes: 1 << 16})
	if err == nil || !strings.Contains(err.Error(), "expanded contents exceed") {
		t.Fatalf("error=%v, want expanded-content limit", err)
	}
}
