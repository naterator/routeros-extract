// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeComparisonFixture(t *testing.T, directory string, rootfs, files []Entry) string {
	return writeComparisonSectionsFixture(t, directory, []Section{
		{Type: 0x15, ExtractedTo: "rootfs"},
		{Type: 4, ExtractedTo: "files"},
	}, map[string][]Entry{"rootfs": rootfs, "files": files})
}

func writeComparisonSectionsFixture(t *testing.T, directory string, sections []Section, manifests map[string][]Entry) string {
	t.Helper()
	if err := os.Mkdir(directory, 0755); err != nil {
		t.Fatal(err)
	}
	metadata := Metadata{Source: filepath.Base(directory) + ".npk", Sections: sections}
	write := func(name string, value any) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, name), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	write("metadata.json", metadata)
	for folder, entries := range manifests {
		write(folder+"-manifest.json", entries)
	}
	return directory
}

func comparisonFile(path, contents, mode string) Entry {
	return Entry{Path: path, Type: "file", Mode: mode, Size: int64(len(contents)), SHA256: digest([]byte(contents))}
}

func comparisonSymlink(path, target, mode string) Entry {
	return Entry{Path: path, Type: "symlink", Mode: mode, Target: target}
}

func readComparisonJSON[T any](t *testing.T, directory, name string) T {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(directory, name))
	if err != nil {
		t.Fatal(err)
	}
	var value T
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	return value
}

func statusCounts(rows []Diff) map[string]int {
	counts := map[string]int{}
	for _, row := range rows {
		counts[row.Status]++
	}
	return counts
}

func TestCompareWritesReportsAndMatchesFirmwareFamilies(t *testing.T) {
	parent := t.TempDir()
	before := writeComparisonFixture(t, filepath.Join(parent, "routeros-7.24.1"), []Entry{
		comparisonFile("etc/changed", "old", "0o100644"),
		comparisonFile("etc/removed", "removed", "0o100644"),
		comparisonFile("etc/same", "same", "0o100644"),
		comparisonSymlink("etc/link", "old,target \"quoted\"\nline", "0o120777"),
		comparisonFile("etc/pipe|line\nname", "old", "0o100644"),
		comparisonFile("etc/mode", "mode", "0o100644"),
		comparisonFile("etc/type", "type-old", "0o100644"),
		comparisonFile("boot/board-7.24.1.fwf", "routerboot", "0o100644"),
	}, []Entry{
		comparisonFile("pkg/changed", "old", "0o100644"),
		comparisonFile("pkg/removed", "removed", "0o100644"),
		comparisonFile("pkg/same", "same", "0o100644"),
	})
	after := writeComparisonFixture(t, filepath.Join(parent, "routeros-7.24.2"), []Entry{
		comparisonFile("etc/changed", "new", "0o100644"),
		comparisonFile("etc/added", "added", "0o100644"),
		comparisonFile("etc/same", "same", "0o100644"),
		comparisonSymlink("etc/link", "new,target \"quoted\"\nline", "0o120777"),
		comparisonFile("etc/pipe|line\nname", "new", "0o100644"),
		comparisonFile("etc/mode", "mode", "0o100755"),
		comparisonSymlink("etc/type", "type-new-target", "0o120777"),
		comparisonFile("boot/board-7.24.2.fwf", "routerboot", "0o100644"),
	}, []Entry{
		comparisonFile("pkg/changed", "new", "0o100644"),
		comparisonFile("pkg/added", "added", "0o100644"),
		comparisonFile("pkg/same", "same", "0o100644"),
	})
	report := filepath.Join(parent, "report")
	got, err := Compare(before, after, report)
	if err != nil {
		t.Fatalf("Compare() error = %v", err)
	}
	wantRoot := map[string]int{
		"added":           2,
		"removed":         2,
		"unchanged":       1,
		"content_changed": 2,
		"symlink_changed": 1,
		"mode_changed":    1,
		"type_changed":    1,
	}
	if !reflect.DeepEqual(got.RootFS, wantRoot) {
		t.Fatalf("RootFS = %#v, want %#v", got.RootFS, wantRoot)
	}
	wantRegular := map[string]int{
		"added":           2,
		"removed":         2,
		"unchanged":       1,
		"content_changed": 2,
		"mode_changed":    1,
	}
	if !reflect.DeepEqual(got.RegularFiles, wantRegular) {
		t.Fatalf("RegularFiles = %#v, want %#v", got.RegularFiles, wantRegular)
	}
	wantFiles := map[string]int{"added": 1, "removed": 1, "unchanged": 1, "content_changed": 1}
	if !reflect.DeepEqual(got.FileContainer, wantFiles) {
		t.Fatalf("FileContainer = %#v, want %#v", got.FileContainer, wantFiles)
	}
	if want := map[string]int{"unchanged": 1}; !reflect.DeepEqual(got.RouterBOOT, want) {
		t.Fatalf("RouterBOOT = %#v, want %#v", got.RouterBOOT, want)
	}

	if summary := readComparisonJSON[Comparison](t, report, "summary.json"); !reflect.DeepEqual(summary, got) {
		t.Fatalf("summary.json = %#v, Compare result = %#v", summary, got)
	}
	rootRows := readComparisonJSON[[]Diff](t, report, "rootfs-diff.json")
	if counts := statusCounts(rootRows); !reflect.DeepEqual(counts, wantRoot) {
		t.Fatalf("rootfs diff counts = %#v, want %#v", counts, wantRoot)
	}
	var changedType Diff
	for _, row := range rootRows {
		if row.Path == "etc/type" {
			changedType = row
		}
	}
	if changedType.Status != "type_changed" || changedType.Type != "symlink" || changedType.OldSize == nil || changedType.NewSize != nil {
		t.Fatalf("type change row = %#v", changedType)
	}

	data, err := os.ReadFile(filepath.Join(report, "rootfs-diff.csv"))
	if err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
	if err != nil {
		t.Fatalf("read rootfs CSV: %v", err)
	}
	wantHeader := []string{"path", "status", "type", "old_size", "new_size", "old_sha256", "new_sha256", "old_target", "new_target"}
	if len(records) != len(rootRows)+1 || !reflect.DeepEqual(records[0], wantHeader) {
		t.Fatalf("rootfs CSV header/row count = %d/%v, want %d/%v", len(records), records[0], len(rootRows)+1, wantHeader)
	}
	rowsByPath := map[string][]string{}
	for _, row := range records[1:] {
		rowsByPath[row[0]] = row
	}
	if row := rowsByPath["etc/mode"]; len(row) != 9 || row[1] != "mode_changed" || row[3] != "4" || row[4] != "4" {
		t.Fatalf("mode CSV row = %#v", row)
	}
	if row := rowsByPath["etc/link"]; len(row) != 9 || row[1] != "symlink_changed" || row[7] != "old,target \"quoted\"\nline" || row[8] != "new,target \"quoted\"\nline" {
		t.Fatalf("link CSV row = %#v", row)
	}
	if row := rowsByPath["etc/pipe|line\nname"]; len(row) != 9 || row[1] != "content_changed" {
		t.Fatalf("special-path CSV row = %#v", row)
	}

	readme, err := os.ReadFile(filepath.Join(report, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	readmeText := string(readme)
	for _, want := range []string{"# routeros-7.24.1 to routeros-7.24.2", "etc/changed", "content_changed", "RouterBOOT families"} {
		if !strings.Contains(readmeText, want) {
			t.Errorf("README.md missing %q", want)
		}
	}
	if !strings.Contains(readmeText, "etc/pipe\\|line name") || strings.Contains(readmeText, "etc/pipe|line\nname") {
		t.Errorf("README.md did not escape special path: %q", readmeText)
	}
	if strings.Contains(readmeText, "etc/same") {
		t.Error("README.md includes unchanged rootfs path")
	}
	verified, err := Verify(report, "")
	if err != nil || !verified.Verified || verified.Artifacts == 0 {
		t.Fatalf("Verify(report) = %+v, error = %v", verified, err)
	}
}

func TestDiffEntriesIgnoresMtimeAndBrowseAliasChanges(t *testing.T) {
	old := comparisonFile("etc/config", "same-bytes", "0o100644")
	old.Mtime = "2026-01-01T00:00:00+00:00"
	old.StoredPath = "etc/config-old"
	new := comparisonFile("etc/config", "same-bytes", "0o100644")
	new.Mtime = "2026-02-01T00:00:00+00:00"
	new.StoredPath = "etc/config-new"
	rows := diffEntries(map[string]Entry{old.Path: old}, map[string]Entry{new.Path: new})
	if len(rows) != 1 || rows[0].Status != "unchanged" {
		t.Fatalf("metadata-only diff = %#v, want one unchanged row", rows)
	}
}

func TestComparePrefixesRepeatedSectionsByExtractedTo(t *testing.T) {
	sections := []Section{
		{Type: 0x15, ExtractedTo: "rootfs-a"},
		{Type: 0x15, ExtractedTo: "rootfs-b"},
		{Type: 4, ExtractedTo: "files-a"},
		{Type: 4, ExtractedTo: "files-b"},
	}
	manifests := map[string][]Entry{
		"rootfs-a": {comparisonFile("etc/shared", "rootfs", "0o100644")},
		"rootfs-b": {comparisonFile("etc/shared", "rootfs", "0o100644")},
		"files-a":  {comparisonFile("pkg/shared", "files", "0o100644")},
		"files-b":  {comparisonFile("pkg/shared", "files", "0o100644")},
	}
	parent := t.TempDir()
	before := writeComparisonSectionsFixture(t, filepath.Join(parent, "before"), sections, manifests)
	after := writeComparisonSectionsFixture(t, filepath.Join(parent, "after"), sections, manifests)
	report := filepath.Join(parent, "report")
	if _, err := Compare(before, after, report); err != nil {
		t.Fatalf("Compare() error = %v", err)
	}
	rootRows := readComparisonJSON[[]Diff](t, report, "rootfs-diff.json")
	if len(rootRows) != 2 || rootRows[0].Path != "rootfs-a/etc/shared" || rootRows[1].Path != "rootfs-b/etc/shared" {
		t.Fatalf("rootfs rows = %#v", rootRows)
	}
	fileRows := readComparisonJSON[[]Diff](t, report, "file-container-diff.json")
	if len(fileRows) != 2 || fileRows[0].Path != "files-a/pkg/shared" || fileRows[1].Path != "files-b/pkg/shared" {
		t.Fatalf("file-container rows = %#v", fileRows)
	}
}

func TestDiffEntriesStatusPrecedence(t *testing.T) {
	tests := []struct {
		name string
		old  Entry
		new  Entry
		want string
	}{
		{
			name: "type before content target and mode",
			old:  Entry{Type: "file", Mode: "old-mode", SHA256: "old-hash", Target: "old-target"},
			new:  Entry{Type: "symlink", Mode: "new-mode", SHA256: "new-hash", Target: "new-target"},
			want: "type_changed",
		},
		{
			name: "content before target and mode",
			old:  Entry{Type: "file", Mode: "old-mode", SHA256: "old-hash", Target: "old-target"},
			new:  Entry{Type: "file", Mode: "new-mode", SHA256: "new-hash", Target: "new-target"},
			want: "content_changed",
		},
		{
			name: "target before mode",
			old:  Entry{Type: "symlink", Mode: "old-mode", Target: "old-target"},
			new:  Entry{Type: "symlink", Mode: "new-mode", Target: "new-target"},
			want: "symlink_changed",
		},
		{
			name: "mode after content",
			old:  Entry{Type: "file", Mode: "old-mode", SHA256: "same-hash"},
			new:  Entry{Type: "file", Mode: "new-mode", SHA256: "same-hash"},
			want: "mode_changed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rows := diffEntries(map[string]Entry{"item": test.old}, map[string]Entry{"item": test.new})
			if len(rows) != 1 || rows[0].Status != test.want {
				t.Fatalf("diff rows = %#v, want status %q", rows, test.want)
			}
		})
	}
}

func TestFirmwareSetNormalizesVersionedFamiliesAndRejectsAmbiguity(t *testing.T) {
	entry := comparisonFile("ignored", "firmware", "0o100644")
	entry.Path = "board-7.24.1.fwf"
	got, err := firmwareSet(map[string]Entry{
		entry.Path:  entry,
		"notes.txt": comparisonFile("notes.txt", "notes", "0o100644"),
	})
	if err != nil {
		t.Fatalf("firmwareSet() error = %v", err)
	}
	if _, ok := got["board.fwf"]; !ok {
		t.Fatalf("normalized firmware keys = %#v, want board.fwf", got)
	}
	if len(got) != 1 {
		t.Fatalf("normalized firmware set = %#v, want one entry", got)
	}

	second := comparisonFile("board-7.24.2.fwf", "different", "0o100644")
	if _, err := firmwareSet(map[string]Entry{
		entry.Path:  entry,
		second.Path: second,
	}); err == nil || !strings.Contains(err.Error(), "ambiguous firmware family: board.fwf") {
		t.Fatalf("ambiguous family error = %v", err)
	}
}

func TestCompareRejectsDuplicateAndUnsafeManifestEntries(t *testing.T) {
	tests := []struct {
		name    string
		entries []Entry
		wantErr string
	}{
		{
			name: "duplicate path",
			entries: []Entry{
				comparisonFile("etc/item", "one", "0o100644"),
				comparisonFile("etc/item", "two", "0o100644"),
			},
			wantErr: "duplicate manifest path: etc/item",
		},
		{
			name: "unsafe path",
			entries: []Entry{
				comparisonFile("../outside", "escape", "0o100644"),
			},
			wantErr: "unsafe or unsupported archive path",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parent := t.TempDir()
			before := writeComparisonFixture(t, filepath.Join(parent, "before"), nil, nil)
			after := writeComparisonFixture(t, filepath.Join(parent, "after"), test.entries, nil)
			report := filepath.Join(parent, "report")
			if _, err := Compare(before, after, report); err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Compare() error = %v, want substring %q", err, test.wantErr)
			}
			if _, err := os.Stat(report); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("report stat error = %v, want not exist", err)
			}
		})
	}
}
