// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/naterator/routeros-extract/internal/extract"
)

type corpusSection struct {
	kind uint16
	body []byte
}

func corpusNPK(sections ...corpusSection) []byte {
	var b bytes.Buffer
	b.Write([]byte{0x1e, 0xf1, 0xd0, 0xba})
	b.Write(make([]byte, 4))
	for _, section := range sections {
		var header [6]byte
		binary.LittleEndian.PutUint16(header[0:2], section.kind)
		binary.LittleEndian.PutUint32(header[2:6], uint32(len(section.body)))
		b.Write(header[:])
		b.Write(section.body)
	}
	data := b.Bytes()
	binary.LittleEndian.PutUint32(data[4:8], uint32(len(data)-8))
	return data
}

func writeCorpusNPK(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestFindPackagesFiltersSortsAndSkipsSymlinks(t *testing.T) {
	root := t.TempDir()
	valid := corpusNPK()
	writeCorpusNPK(t, filepath.Join(root, "z-last.NPK"), valid)
	writeCorpusNPK(t, filepath.Join(root, "a-first.npk"), valid)
	writeCorpusNPK(t, filepath.Join(root, "ignore.zip"), valid)
	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0755); err != nil {
		t.Fatal(err)
	}
	writeCorpusNPK(t, filepath.Join(nested, "middle.nPk"), valid)
	if err := os.WriteFile(filepath.Join(nested, "README"), []byte("not a package"), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := findPackages(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		filepath.Join(root, "a-first.npk"),
		filepath.Join(root, "nested", "middle.nPk"),
		filepath.Join(root, "z-last.NPK"),
	}
	if !slices.Equal(got, want) {
		t.Fatalf("findPackages() = %#v, want %#v", got, want)
	}

	got, err = findPackages(filepath.Join(root, "a-first.npk"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{filepath.Join(root, "a-first.npk")}) {
		t.Fatalf("single-file findPackages() = %#v", got)
	}
	if _, err := findPackages(filepath.Join(root, "ignore.zip")); err == nil {
		t.Fatal("findPackages accepted a non-NPK file")
	}

	t.Run("symlink", func(t *testing.T) {
		link := filepath.Join(root, "ignored-link.npk")
		if err := os.Symlink(filepath.Join(root, "a-first.npk"), link); err != nil {
			if runtime.GOOS == "windows" {
				t.Skipf("creating symlinks requires additional Windows privileges: %v", err)
			}
			t.Fatal(err)
		}
		got, err := findPackages(root)
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(got, link) {
			t.Fatalf("findPackages included symlink %q", link)
		}
	})
}

func TestArchitectureAndPackageResultAggregateSections(t *testing.T) {
	metadata := extract.Metadata{Sections: []extract.Section{
		{Type: 0x10, Text: "  I  "},
		{Type: 0x10, Text: " arm64\n"},
		{Type: 0x15, Counts: map[string]int{"file": 3, "directory": 2}},
		{Type: 0x15, Counts: map[string]int{"file": 4, "symlink": 1}},
		{Type: 4, Entries: 6},
		{Type: 4, Entries: 2},
	}}

	if got := architecture(metadata); got != "arm64" {
		t.Fatalf("architecture() = %q, want arm64", got)
	}
	result := packageResultFromMetadata("input.npk", "out", metadata)
	if result.Architecture != "arm64" || result.Sections != 6 || result.Files != 8 {
		t.Fatalf("package result metadata = %+v", result)
	}
	wantRootFS := map[string]int{"file": 7, "directory": 2, "symlink": 1}
	if !maps.Equal(result.RootFS, wantRootFS) {
		t.Fatalf("rootfs counts = %#v, want %#v", result.RootFS, wantRootFS)
	}

	if got := architecture(extract.Metadata{Sections: []extract.Section{
		{Type: 0x10, Text: "I"},
		{Type: 0x10, Text: "  "},
	}}); got != "unknown" {
		t.Fatalf("architecture without a value = %q, want unknown", got)
	}
}

func TestOutputNameIsReadableAndUnique(t *testing.T) {
	if got := outputName("release/routeros 7.24?.NPK", 0); got != "0001-routeros_7.24_" {
		t.Fatalf("sanitized output name = %q", got)
	}
	first := outputName("one/routeros.npk", 0)
	second := outputName("two/routeros.npk", 1)
	if first == second || first != "0001-routeros" || second != "0002-routeros" {
		t.Fatalf("duplicate basenames were not made unique: %q, %q", first, second)
	}
	if got := outputName("directory/...NPK", 4); got != "0005-.." {
		t.Fatalf("punctuation-preserving output name = %q", got)
	}
}

func TestWriteSummaryReplacesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "summary.json")
	old := corpusSummary{Schema: 1, Corpus: "old", Packages: 1, Results: []packageResult{{Source: "old.npk"}}}
	if err := writeSummary(path, old); err != nil {
		t.Fatal(err)
	}
	newSummary := corpusSummary{Schema: 1, Corpus: "new", Packages: 2, Results: []packageResult{{Source: "new-a.npk"}, {Source: "new-b.npk"}}}
	if err := writeSummary(path, newSummary); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got corpusSummary
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("replacement is not valid JSON: %v", err)
	}
	if got.Corpus != "new" || got.Packages != 2 || len(got.Results) != 2 || got.Results[0].Source != "new-a.npk" {
		t.Fatalf("replacement summary = %+v", got)
	}
	if _, err := os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary summary still exists, stat error = %v", err)
	}
}

func TestCorpusCommandContinuesAfterMalformedPackage(t *testing.T) {
	corpus := t.TempDir()
	bad := filepath.Join(corpus, "01-bad.npk")
	good := filepath.Join(corpus, "02-good.npk")
	writeCorpusNPK(t, bad, []byte("not an NPK"))
	writeCorpusNPK(t, good, corpusNPK(
		corpusSection{kind: 0x10, body: []byte("arm64")},
		corpusSection{kind: 2, body: []byte("synthetic package")},
	))

	executable := filepath.Join(t.TempDir(), "corpus-tool.exe")
	build := exec.Command("go", "build", "-o", executable, ".")
	buildDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = buildDir
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, output)
	}
	outputDir := filepath.Join(t.TempDir(), "output")
	command := exec.Command(executable, "-corpus", corpus, "-output", outputDir)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err = command.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("mixed corpus exit = %v, want exit code 1\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
	}

	b, err := os.ReadFile(filepath.Join(outputDir, "summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	var summary corpusSummary
	if err := json.Unmarshal(b, &summary); err != nil {
		t.Fatalf("summary JSON: %v", err)
	}
	if summary.Packages != 2 || summary.Succeeded != 1 || summary.Failed != 1 {
		t.Fatalf("summary counts = %+v", summary)
	}
	if summary.Architectures["arm64"] != 1 {
		t.Fatalf("architecture counts = %#v", summary.Architectures)
	}
	if len(summary.Results) != 2 {
		t.Fatalf("summary results = %#v, want two results", summary.Results)
	}
	if summary.Results[0].Source != bad || summary.Results[0].Error == "" {
		t.Fatalf("malformed result = %+v", summary.Results[0])
	}
	if summary.Results[1].Source != good || summary.Results[1].Architecture != "arm64" || !summary.Results[1].Verified {
		t.Fatalf("valid result after failure = %+v", summary.Results[1])
	}
	if _, err := os.Stat(summary.Results[0].Destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed package unexpectedly has output directory: %v", err)
	}
	if !strings.Contains(stderr.String(), "1/2 packages failed") {
		t.Fatalf("stderr did not include failure summary: %s", stderr.String())
	}
}
