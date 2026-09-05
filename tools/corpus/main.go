// SPDX-License-Identifier: BSD-3-Clause
// Command corpus runs the full extractor over every NPK below a directory.
// It is deliberately opt-in and continues after a package error, which makes
// it useful for validating a mixed RouterOS release archive as new fixtures
// are added.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/naterator/routeros-extract/internal/extract"
)

type packageResult struct {
	Source       string         `json:"source"`
	Destination  string         `json:"destination,omitempty"`
	Architecture string         `json:"architecture,omitempty"`
	Sections     int            `json:"sections,omitempty"`
	RootFS       map[string]int `json:"rootfs_counts,omitempty"`
	Files        int            `json:"file_container_entries,omitempty"`
	Verified     bool           `json:"verified"`
	Error        string         `json:"error,omitempty"`
}

type corpusSummary struct {
	Schema        int             `json:"schema"`
	Started       string          `json:"started_utc"`
	Finished      string          `json:"finished_utc"`
	Corpus        string          `json:"corpus"`
	Output        string          `json:"output"`
	Packages      int             `json:"packages"`
	Succeeded     int             `json:"succeeded"`
	Failed        int             `json:"failed"`
	Architectures map[string]int  `json:"architecture_package_counts"`
	Results       []packageResult `json:"results"`
}

func findPackages(root string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		if strings.EqualFold(filepath.Ext(root), ".npk") {
			return []string{root}, nil
		}
		return nil, fmt.Errorf("corpus path is neither a directory nor an NPK: %s", root)
	}
	var packages []string
	err = filepath.WalkDir(root, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if strings.EqualFold(filepath.Ext(name), ".npk") {
			packages = append(packages, name)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(packages)
	return packages, nil
}

func architecture(metadata extract.Metadata) string {
	for _, section := range metadata.Sections {
		if section.Type != 0x10 {
			continue
		}
		text := strings.TrimSpace(section.Text)
		if text != "" && text != "I" {
			return text
		}
	}
	return "unknown"
}

func outputName(source string, index int) string {
	base := strings.TrimSuffix(filepath.Base(source), filepath.Ext(source))
	// Keep output names readable while making duplicate names from separate
	// release directories impossible.  The index is stable because inputs are
	// sorted, and the original absolute source remains in summary.json.
	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			return r
		default:
			return '_'
		}
	}, base)
	if clean == "" {
		clean = "package"
	}
	return fmt.Sprintf("%04d-%s", index+1, clean)
}

func packageResultFromMetadata(source, destination string, metadata extract.Metadata) packageResult {
	r := packageResult{Source: source, Destination: destination, Architecture: architecture(metadata), Sections: len(metadata.Sections)}
	for _, section := range metadata.Sections {
		switch section.Type {
		case 0x15:
			for kind, count := range section.Counts {
				if r.RootFS == nil {
					r.RootFS = map[string]int{}
				}
				r.RootFS[kind] += count
			}
		case 4:
			r.Files += section.Entries
		}
	}
	return r
}

func writeSummary(path string, summary corpusSummary) error {
	b, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func main() {
	corpus := flag.String("corpus", os.Getenv("ROUTEROS_TEST_CORPUS"), "directory or .npk file to scan (or ROUTEROS_TEST_CORPUS)")
	output := flag.String("output", "", "persistent output directory (default: <corpus>/.routeros-extract-corpus)")
	maxBytes := flag.Int64("max-bytes", extract.DefaultMaxBytes, "maximum expanded size accepted per input")
	flag.Parse()
	if *corpus == "" {
		fmt.Fprintln(os.Stderr, "-corpus is required (or set ROUTEROS_TEST_CORPUS)")
		os.Exit(2)
	}
	packages, err := findPackages(*corpus)
	if err != nil {
		fmt.Fprintf(os.Stderr, "find packages: %v\n", err)
		os.Exit(2)
	}
	if len(packages) == 0 {
		fmt.Fprintln(os.Stderr, "corpus contains no .npk files")
		os.Exit(2)
	}
	if *output == "" {
		if info, statErr := os.Stat(*corpus); statErr == nil && info.IsDir() {
			*output = filepath.Join(*corpus, ".routeros-extract-corpus")
		} else {
			*output = filepath.Join(filepath.Dir(*corpus), ".routeros-extract-corpus")
		}
	}
	if err := os.MkdirAll(*output, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "create output: %v\n", err)
		os.Exit(2)
	}
	started := time.Now().UTC()
	summary := corpusSummary{Schema: 1, Started: started.Format(time.RFC3339), Corpus: *corpus, Output: *output, Packages: len(packages), Architectures: map[string]int{}, Results: make([]packageResult, 0, len(packages))}
	for i, source := range packages {
		destination := filepath.Join(*output, outputName(source, i))
		result := packageResult{Source: source, Destination: destination}
		metadata, extractErr := extract.Extract(source, destination, extract.Options{MaxBytes: *maxBytes, NoSymlinks: runtime.GOOS == "windows"})
		if extractErr != nil {
			result.Error = extractErr.Error()
			summary.Failed++
			summary.Results = append(summary.Results, result)
			fmt.Fprintf(os.Stderr, "FAIL %s: %s\n", source, result.Error)
			continue
		}
		result = packageResultFromMetadata(source, destination, metadata)
		verification, verifyErr := extract.Verify(destination, source)
		if verifyErr != nil {
			result.Error = verifyErr.Error()
			summary.Failed++
			fmt.Fprintf(os.Stderr, "FAIL %s: verify: %s\n", source, result.Error)
		} else if !verification.Verified || !verification.SourceVerified || !verification.SectionRoundtrip {
			result.Error = "verification did not report complete source and section validation"
			summary.Failed++
			fmt.Fprintf(os.Stderr, "FAIL %s: %s\n", source, result.Error)
		} else {
			result.Verified = true
			summary.Succeeded++
			summary.Architectures[result.Architecture]++
			fmt.Printf("OK   %s (%s)\n", source, result.Architecture)
		}
		summary.Results = append(summary.Results, result)
	}
	summary.Finished = time.Now().UTC().Format(time.RFC3339)
	if err := writeSummary(filepath.Join(*output, "summary.json"), summary); err != nil {
		fmt.Fprintf(os.Stderr, "write summary: %v\n", err)
		os.Exit(2)
	}
	if summary.Failed != 0 {
		fmt.Fprintf(os.Stderr, "%d/%d packages failed; complete results are in %s\n", summary.Failed, summary.Packages, filepath.Join(*output, "summary.json"))
		os.Exit(1)
	}
	fmt.Printf("validated %d packages; summary: %s\n", summary.Succeeded, filepath.Join(*output, "summary.json"))
}
