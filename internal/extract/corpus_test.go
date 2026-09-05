// SPDX-License-Identifier: BSD-3-Clause
package extract

// This file contains opt-in integration tests for a directory of real RouterOS
// packages.  The tests intentionally do not make the repository depend on
// external tools or on a checked-in firmware fixture.  Set
// ROUTEROS_TEST_CORPUS to a directory (or a single .npk file) when a local
// corpus is available:
//
//   ROUTEROS_TEST_CORPUS=/path/to/packages go test ./internal/extract -run Corpus
//
// ROUTEROS_PYTHON_REFERENCE may point at the old Python extraction's
// `extracted` directory.  When it is set, the two known arm64 packages are
// compared against that reference by original archive paths and payload
// hashes.  A missing reference package is ignored so that a partial reference
// directory remains useful for a larger corpus.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func corpusPackages(t *testing.T, root string) []string {
	t.Helper()
	var packages []string
	info, err := os.Stat(root)
	if err != nil {
		t.Fatalf("stat corpus %q: %v", root, err)
	}
	if !info.IsDir() {
		if strings.EqualFold(filepath.Ext(root), ".npk") {
			return []string{root}
		}
		t.Fatalf("corpus path is neither a directory nor an NPK: %s", root)
	}
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
		t.Fatalf("walk corpus %q: %v", root, err)
	}
	sort.Strings(packages)
	return packages
}

func corpusReadJSON[T any](t *testing.T, name string, value *T) {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if err := json.Unmarshal(b, value); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
}

func corpusManifestEntries(t *testing.T, root, name string) []Entry {
	t.Helper()
	var entries []Entry
	corpusReadJSON(t, filepath.Join(root, filepath.FromSlash(name)), &entries)
	return entries
}

func corpusCompareManifest(t *testing.T, gotRoot string, got Metadata, refRoot string) {
	t.Helper()
	// Compare each extracted section separately.  This keeps package and
	// rootfs paths distinct if an add-on happens to contain both containers.
	for _, section := range got.Sections {
		if section.ExtractedTo == "" {
			continue
		}
		refManifest := filepath.Join(refRoot, section.ExtractedTo+"-manifest.json")
		if _, err := os.Stat(refManifest); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			t.Errorf("reference manifest %s: %v", refManifest, err)
			continue
		}
		gotEntries := corpusManifestEntries(t, gotRoot, section.ExtractedTo+"-manifest.json")
		refEntries := corpusManifestEntries(t, refRoot, section.ExtractedTo+"-manifest.json")
		gotByPath := make(map[string]Entry, len(gotEntries))
		refByPath := make(map[string]Entry, len(refEntries))
		for _, entry := range gotEntries {
			gotByPath[entry.Path] = entry
		}
		for _, entry := range refEntries {
			refByPath[entry.Path] = entry
		}
		if len(gotByPath) != len(gotEntries) || len(refByPath) != len(refEntries) {
			t.Errorf("%s: duplicate original path in manifest", section.ExtractedTo)
		}
		if len(gotByPath) != len(refByPath) {
			t.Errorf("%s: manifest entry count = %d, reference = %d", section.ExtractedTo, len(gotByPath), len(refByPath))
		}
		for path, want := range refByPath {
			have, ok := gotByPath[path]
			if !ok {
				t.Errorf("%s: missing original path %q", section.ExtractedTo, path)
				continue
			}
			if have.Type != want.Type || have.Mode != want.Mode || have.UID != want.UID || have.GID != want.GID || have.Target != want.Target || have.SHA256 != want.SHA256 || have.Size != want.Size {
				t.Errorf("%s/%s: metadata/hash mismatch: got type=%s mode=%s uid=%d gid=%d size=%d sha=%s target=%q; reference type=%s mode=%s uid=%d gid=%d size=%d sha=%s target=%q", section.ExtractedTo, path, have.Type, have.Mode, have.UID, have.GID, have.Size, have.SHA256, have.Target, want.Type, want.Mode, want.UID, want.GID, want.Size, want.SHA256, want.Target)
			}
		}
		for path := range gotByPath {
			if _, ok := refByPath[path]; !ok {
				t.Errorf("%s: unexpected original path %q", section.ExtractedTo, path)
			}
		}
	}
}

func corpusReferencePackage(root, source string) (string, bool) {
	if root == "" {
		return "", false
	}
	base := strings.TrimSuffix(filepath.Base(source), filepath.Ext(source))
	candidates := []string{root, filepath.Join(root, "extracted")}
	for _, candidateRoot := range candidates {
		if info, err := os.Stat(candidateRoot); err == nil && info.IsDir() {
			if _, err := os.Stat(filepath.Join(candidateRoot, "metadata.json")); err == nil && filepath.Base(candidateRoot) == base {
				return candidateRoot, true
			}
			candidate := filepath.Join(candidateRoot, base)
			if info, err := os.Stat(candidate); err == nil && info.IsDir() {
				if _, err := os.Stat(filepath.Join(candidate, "metadata.json")); err == nil {
					return candidate, true
				}
			}
		}
	}
	// Accept a reference directory whose package folders have been renamed.
	// The metadata source field is the stable key from the old extractor.
	var found string
	for _, candidateRoot := range candidates {
		_ = filepath.WalkDir(candidateRoot, func(name string, entry fs.DirEntry, err error) error {
			if err != nil || found != "" {
				return err
			}
			if entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 || entry.Name() != "metadata.json" {
				return nil
			}
			var metadata Metadata
			b, readErr := os.ReadFile(name)
			if readErr == nil {
				if json.Unmarshal(b, &metadata) == nil && metadata.Source == filepath.Base(source) {
					found = filepath.Dir(name)
				}
			}
			return nil
		})
		if found != "" {
			return found, true
		}
	}
	return "", false
}

func corpusCompareDerivedPayloads(t *testing.T, gotRoot, refRoot string) {
	t.Helper()
	// JSON manifests, human-readable string dumps, and ELF reports are derived
	// descriptions.  The payload set consists of the decoded RouterBOOT images,
	// WebFig definitions, and kernel/initramfs payloads.  It is intentionally
	// compared as bytes so this check catches a decoder that merely emits a
	// plausible manifest.
	payload := func(root string) (map[string]string, error) {
		out := map[string]string{}
		err := filepath.WalkDir(filepath.Join(root, "derived"), func(name string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 {
				return nil
			}
			rel, err := filepath.Rel(filepath.Join(root, "derived"), name)
			if err != nil {
				return err
			}
			ext := strings.ToLower(filepath.Ext(rel))
			if ext == ".json" || ext == ".txt" || ext == ".md" {
				return nil
			}
			b, err := os.ReadFile(name)
			if err != nil {
				return err
			}
			h := sha256.Sum256(b)
			out[filepath.ToSlash(rel)] = hex.EncodeToString(h[:])
			return nil
		})
		return out, err
	}
	got, err := payload(gotRoot)
	if err != nil {
		t.Errorf("walk derived payloads: %v", err)
		return
	}
	want, err := payload(refRoot)
	if err != nil {
		t.Errorf("walk reference derived payloads: %v", err)
		return
	}
	for path, wantHash := range want {
		if got[path] != wantHash {
			t.Errorf("derived payload %s: hash = %s, reference = %s", path, got[path], wantHash)
		}
	}
	additional := []string{}
	for path := range got {
		if _, ok := want[path]; !ok {
			additional = append(additional, path)
		}
	}
	// The Go extractor may discover payloads that the older Python analyzer
	// did not recurse into (for example a built-in initramfs inside Image).
	// Every reference payload remains required above; additional Go payloads
	// are useful evidence and should not make the parity check fail.
	sort.Strings(additional)
	if len(additional) != 0 {
		t.Logf("Go emitted %d additional derived payload(s) beyond the reference: %s", len(additional), strings.Join(additional, ", "))
	}
}

func corpusCheckManifestHashes(t *testing.T, root string, metadata Metadata) {
	t.Helper()
	for _, section := range metadata.Sections {
		if section.ExtractedTo == "" {
			continue
		}
		manifestPath := filepath.Join(root, section.ExtractedTo+"-manifest.json")
		if _, err := os.Stat(manifestPath); err != nil {
			t.Errorf("section %d manifest %s: %v", section.Index, manifestPath, err)
			continue
		}
		var entries []Entry
		corpusReadJSON(t, manifestPath, &entries)
		for _, entry := range entries {
			if entry.Type != "file" {
				continue
			}
			stored := entry.StoredPath
			if stored == "" {
				stored = entry.Path
			}
			data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(section.ExtractedTo), filepath.FromSlash(stored)))
			if err != nil {
				t.Errorf("%s/%s: read extracted file: %v", section.ExtractedTo, entry.Path, err)
				continue
			}
			if int64(len(data)) != entry.Size || digest(data) != entry.SHA256 {
				t.Errorf("%s/%s: manifest file hash/size mismatch", section.ExtractedTo, entry.Path)
			}
		}
	}
}

func corpusCheckRootFSCounts(t *testing.T, root string, metadata Metadata) {
	t.Helper()
	for _, section := range metadata.Sections {
		if section.Type != 0x15 || section.ExtractedTo == "" {
			continue
		}
		// A SquashFS with only its root inode is valid and has no descendants.
		// For a real RouterOS rootfs, however, the manifest must contain entries
		// and the section count fields must agree with it.  Read the inode count
		// independently from the section bytes so a deliberately empty add-on
		// filesystem is still accepted.
		inodeCount := uint32(0)
		sectionBytes, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(section.File)))
		if err == nil && len(sectionBytes) >= 8 && string(sectionBytes[:4]) == "hsqs" {
			inodeCount = binary.LittleEndian.Uint32(sectionBytes[4:])
		}
		if section.Entries == 0 {
			if inodeCount > 1 {
				t.Errorf("SquashFS section %d has a non-empty image but zero extracted entries", section.Index)
			}
			continue
		}
		var entries []Entry
		corpusReadJSON(t, filepath.Join(root, section.ExtractedTo+"-manifest.json"), &entries)
		counts := map[string]int{}
		for _, entry := range entries {
			counts[entry.Type]++
		}
		if len(entries) != section.Entries {
			t.Errorf("SquashFS section %d entries = %d, manifest = %d", section.Index, section.Entries, len(entries))
		}
		for kind, count := range counts {
			if section.Counts[kind] != count {
				t.Errorf("SquashFS section %d %s count = %d, manifest = %d", section.Index, kind, section.Counts[kind], count)
			}
		}
	}
}

func TestCorpusExtractAndVerify(t *testing.T) {
	corpus := os.Getenv("ROUTEROS_TEST_CORPUS")
	if corpus == "" {
		t.Skip("set ROUTEROS_TEST_CORPUS to run RouterOS corpus integration tests")
	}
	packages := corpusPackages(t, corpus)
	if len(packages) == 0 {
		t.Fatal("corpus contains no .npk packages")
	}
	refRoot := os.Getenv("ROUTEROS_PYTHON_REFERENCE")
	for _, source := range packages {
		source := source
		t.Run(filepath.Base(source), func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "extracted")
			metadata, err := Extract(source, out, Options{MaxBytes: DefaultMaxBytes, NoSymlinks: runtime.GOOS == "windows"})
			if err != nil {
				t.Fatalf("extract %s: %v", source, err)
			}
			if !metadata.SectionRoundtripVerified {
				t.Error("metadata section roundtrip was not marked verified")
			}
			verification, err := Verify(out, source)
			if err != nil {
				t.Fatalf("verify %s: %v", source, err)
			}
			if !verification.Verified || !verification.SectionRoundtrip || !verification.SourceVerified {
				t.Fatalf("incomplete verification result: %+v", verification)
			}
			corpusCheckManifestHashes(t, out, metadata)
			corpusCheckRootFSCounts(t, out, metadata)
			if reference, ok := corpusReferencePackage(refRoot, source); ok {
				corpusCompareManifest(t, out, metadata, reference)
				corpusCompareDerivedPayloads(t, out, reference)
			}
		})
	}
}

func TestCorpusPathSafetyHelpers(t *testing.T) {
	// Keep the opt-in integration test independent from the host platform's
	// path separator.  This also documents the paths accepted by manifests.
	for _, name := range []string{"bin/foo", "rootfs/etc/rc.d", "boot/kernel"} {
		if err := safePath(name); err != nil {
			t.Errorf("safe path %q rejected: %v", name, err)
		}
	}
	for _, name := range []string{"../escape", "/absolute", `back\\slash`, "a\x00b"} {
		if err := safePath(name); err == nil {
			t.Errorf("unsafe path %q accepted", name)
		}
	}
}
