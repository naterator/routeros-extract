// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// ZIPMember describes one central-directory member.  StoredPath is relative
// to the extraction directory's npk/ folder and is present only when the
// member was copied to disk. Name is retained exactly as it appeared in the
// archive.
type ZIPMember struct {
	Name             string `json:"name"`
	StoredPath       string `json:"stored_path,omitempty"`
	Type             string `json:"type"`
	Mode             string `json:"mode,omitempty"`
	Mtime            string `json:"mtime_utc,omitempty"`
	Size             uint64 `json:"size"`
	CompressedSize   uint64 `json:"compressed_size"`
	CRC32            string `json:"crc32"`
	SHA256           string `json:"sha256,omitempty"`
	Comment          string `json:"comment,omitempty"`
	Target           string `json:"target,omitempty"`
	NPK              bool   `json:"npk,omitempty"`
	Ignored          bool   `json:"ignored,omitempty"`
	PackageDirectory string `json:"package_directory,omitempty"`
}

// ZIPPackage records the files used to extract one NPK member.  The raw NPK
// is intentionally kept in the output so Verify can be run against it later.
type ZIPPackage struct {
	Member       string `json:"member"`
	NPKPath      string `json:"npk_path"`
	Directory    string `json:"directory"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
	MetadataPath string `json:"metadata_path"`
}

// ZIPMetadata is written to zip-metadata.json in the output directory.  It
// describes the source archive and every member, including ignored entries.
// Archive content is not copied a second time; SourceSHA256 provides a stable
// check against the original archive.
type ZIPMetadata struct {
	Schema       int          `json:"schema"`
	Source       string       `json:"source"`
	SourceSize   int64        `json:"source_size"`
	SourceSHA256 string       `json:"source_sha256"`
	SourceMode   string       `json:"source_mode,omitempty"`
	SourceMtime  string       `json:"source_mtime_utc,omitempty"`
	Comment      string       `json:"comment,omitempty"`
	Members      []ZIPMember  `json:"members"`
	Packages     []ZIPPackage `json:"packages"`
}

// zipMemberWork keeps decoded data until all archive paths have been checked.
// This makes path validation happen before the first output write and keeps
// NPK inputs available for Extract without a temporary file outside the root.
type zipMemberWork struct {
	member ZIPMember
	path   string
	data   []byte
}

func zipTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func zipMode(mode fs.FileMode) string {
	if mode == 0 {
		return ""
	}
	return fmt.Sprintf("0o%o", uint32(mode.Perm()))
}

// zipMemberPath validates a ZIP name while accepting the conventional
// trailing slash used for directory records.  The normalized path is only
// used internally; the original name is retained in ZIPMember.Name.
func zipMemberPath(name string, mode fs.FileMode) (string, error) {
	normalized := name
	if mode.IsDir() || strings.HasSuffix(normalized, "/") {
		normalized = strings.TrimRight(normalized, "/")
	}
	if normalized == "" {
		return "", fmt.Errorf("invalid empty ZIP member name %q", name)
	}
	if err := safePath(normalized); err != nil {
		return "", fmt.Errorf("unsafe ZIP member %q: %w", name, err)
	}
	return normalized, nil
}

func zipIsSymlink(mode fs.FileMode) bool {
	return mode&fs.ModeSymlink != 0
}

func readZIPMember(f *zip.File, limit int64) ([]byte, error) {
	if f.UncompressedSize64 > uint64(limit) {
		return nil, fmt.Errorf("ZIP member %q exceeds byte limit of %d", f.Name, limit)
	}
	r, err := f.Open()
	if err != nil {
		return nil, err
	}
	b, readErr := bounded(r, limit)
	closeErr := r.Close()
	if err = errors.Join(readErr, closeErr); err != nil {
		return nil, err
	}
	return b, nil
}

func zipPackageStem(name string) string {
	base := path.Base(name)
	ext := path.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	if stem == "" || stem == "." || stem == ".." {
		return "package"
	}
	return stem
}

func uniqueZIPPackagePath(stem, member string, used map[string]bool) (string, error) {
	if err := safePath(stem); err != nil {
		return "", err
	}
	component := portableComponent(stem)
	candidate := path.Join("packages", component)
	for attempt := 1; used[portablePathKey(candidate)]; attempt++ {
		candidate = path.Join("packages", collisionComponent(component, member, attempt))
	}
	used[portablePathKey(candidate)] = true
	return candidate, nil
}

func zipSourceMetadata(source string, data []byte) (ZIPMetadata, error) {
	info, err := os.Stat(source)
	if err != nil {
		return ZIPMetadata{}, err
	}
	if !info.Mode().IsRegular() {
		return ZIPMetadata{}, fmt.Errorf("ZIP source is not a regular file: %s", source)
	}
	return ZIPMetadata{
		Schema:       1,
		Source:       filepath.Base(source),
		SourceSize:   info.Size(),
		SourceSHA256: digest(data),
		SourceMode:   zipMode(info.Mode()),
		SourceMtime:  zipTime(info.ModTime()),
	}, nil
}

// ExtractZIP extracts every regular .npk member from source.  Package output
// directories are created below destination/packages and the exact member
// bytes are preserved below destination/npk.  Non-NPK files, directories, and
// symlinks are listed in zip-metadata.json but are not written or followed.
//
// The source and the aggregate decoded ZIP contents are both bounded by
// Options.MaxBytes.  A new destination is required, just like Extract.
func ExtractZIP(source, destination string, opt Options) ([]Metadata, error) {
	data, err := ReadInput(source, opt)
	if err != nil {
		return nil, err
	}
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("read ZIP archive: %w", err)
	}
	if len(archive.File) == 0 {
		return nil, errors.New("ZIP archive contains no members")
	}
	if len(archive.File) > MaxEntries {
		return nil, fmt.Errorf("ZIP archive contains too many members: %d", len(archive.File))
	}

	zipMeta, err := zipSourceMetadata(source, data)
	if err != nil {
		return nil, err
	}
	zipMeta.Comment = archive.Comment

	work := make([]zipMemberWork, 0, len(archive.File))
	planned := make([]Entry, 0, len(archive.File))
	seenPaths := map[string]bool{}
	var expanded uint64
	var npkCount int
	for _, f := range archive.File {
		mode := f.Mode()
		name, err := zipMemberPath(f.Name, mode)
		if err != nil {
			return nil, err
		}
		if seenPaths[name] {
			return nil, fmt.Errorf("duplicate ZIP member path: %s", f.Name)
		}
		seenPaths[name] = true
		kind := "file"
		switch {
		case mode.IsDir() || strings.HasSuffix(f.Name, "/"):
			kind = "directory"
		case zipIsSymlink(mode):
			kind = "symlink"
		}
		if kind == "symlink" && f.UncompressedSize64 > maxInlineMetadataBytes {
			return nil, fmt.Errorf("ZIP symlink %q target exceeds %d bytes", f.Name, maxInlineMetadataBytes)
		}
		if uint64(opt.limit()) < f.UncompressedSize64 || expanded > uint64(opt.limit())-f.UncompressedSize64 {
			return nil, fmt.Errorf("ZIP expanded contents exceed byte limit of %d", opt.limit())
		}
		expanded += f.UncompressedSize64

		member := ZIPMember{
			Name:           f.Name,
			Type:           kind,
			Mode:           zipMode(mode),
			Mtime:          zipTime(f.Modified),
			Size:           f.UncompressedSize64,
			CompressedSize: f.CompressedSize64,
			CRC32:          fmt.Sprintf("%08x", f.CRC32),
			Comment:        f.Comment,
		}
		w := zipMemberWork{member: member, path: name}
		if kind == "file" || kind == "symlink" {
			memberLimit := opt.limit()
			if kind == "symlink" && memberLimit > maxInlineMetadataBytes {
				memberLimit = maxInlineMetadataBytes
			}
			w.data, err = readZIPMember(f, memberLimit)
			if err != nil {
				if kind == "symlink" && memberLimit == maxInlineMetadataBytes && strings.Contains(err.Error(), "exceeds limit") {
					return nil, fmt.Errorf("ZIP symlink %q target exceeds %d bytes", f.Name, maxInlineMetadataBytes)
				}
				return nil, fmt.Errorf("read ZIP member %q: %w", f.Name, err)
			}
			// A malformed central directory can under-report the uncompressed
			// size.  Account for bytes actually returned as well as the
			// declared size so aggregate expansion remains bounded.
			actual := uint64(len(w.data))
			if actual > f.UncompressedSize64 {
				extra := actual - f.UncompressedSize64
				if expanded > uint64(opt.limit())-extra {
					return nil, fmt.Errorf("ZIP expanded contents exceed byte limit of %d", opt.limit())
				}
				expanded += extra
			}
			w.member.Size = uint64(len(w.data))
			w.member.SHA256 = digest(w.data)
			if kind == "symlink" {
				if len(w.data) > maxInlineMetadataBytes {
					return nil, fmt.Errorf("ZIP symlink %q target exceeds %d bytes", f.Name, maxInlineMetadataBytes)
				}
				if bytes.IndexByte(w.data, 0) >= 0 {
					return nil, fmt.Errorf("ZIP symlink %q target contains NUL", f.Name)
				}
				w.member.Target = strings.ToValidUTF8(string(w.data), "�")
			}
			if kind == "file" && strings.EqualFold(path.Ext(name), ".npk") {
				w.member.NPK = true
				npkCount++
			}
			if kind == "file" && !w.member.NPK {
				w.member.Ignored = true
			}
		} else {
			w.member.Ignored = true
		}
		planned = append(planned, Entry{Path: name, Type: kind})
		work = append(work, w)
	}
	if npkCount == 0 {
		return nil, errors.New("ZIP archive contains no regular .npk members")
	}

	planned, err = planPaths(planned)
	if err != nil {
		return nil, fmt.Errorf("plan ZIP member paths: %w", err)
	}
	stored := make(map[string]string, len(planned))
	for _, e := range planned {
		stored[e.Path] = e.StoredPath
	}
	for i := range work {
		if work[i].member.NPK {
			work[i].member.StoredPath = stored[work[i].path]
		}
	}

	// Allocate package output names only after all member paths have been
	// validated.  The suffix matches planPaths' case-collision convention and
	// remains stable if two nested directories contain the same basename.
	usedPackages := map[string]bool{}
	for i := range work {
		if !work[i].member.NPK {
			continue
		}
		outPath, e := uniqueZIPPackagePath(zipPackageStem(work[i].path), work[i].path, usedPackages)
		if e != nil {
			return nil, e
		}
		work[i].member.PackageDirectory = outPath
	}

	d, err := newDisk(destination)
	if err != nil {
		return nil, err
	}
	defer d.Close()

	// Raw NPK bytes are stored first.  Extract reads these paths directly and
	// therefore uses exactly the bytes represented in the ZIP manifest.
	for i := range work {
		if !work[i].member.NPK {
			continue
		}
		rawPath := path.Join("npk", work[i].member.StoredPath)
		if err = d.put(rawPath, work[i].data); err != nil {
			return nil, fmt.Errorf("preserve ZIP member %q: %w", work[i].member.Name, err)
		}
	}

	metas := make([]Metadata, 0, npkCount)
	zipMeta.Packages = make([]ZIPPackage, 0, npkCount)
	for i := range work {
		if !work[i].member.NPK {
			continue
		}
		rawPath := path.Join("npk", work[i].member.StoredPath)
		packageDir := work[i].member.PackageDirectory
		sourcePath := filepath.Join(destination, filepath.FromSlash(rawPath))
		outputPath := filepath.Join(destination, filepath.FromSlash(packageDir))
		m, e := Extract(sourcePath, outputPath, opt)
		if e != nil {
			return metas, fmt.Errorf("extract ZIP member %q: %w", work[i].member.Name, e)
		}
		metas = append(metas, m)
		zipMeta.Packages = append(zipMeta.Packages, ZIPPackage{
			Member:       work[i].member.Name,
			NPKPath:      rawPath,
			Directory:    packageDir,
			Size:         int64(len(work[i].data)),
			SHA256:       digest(work[i].data),
			MetadataPath: path.Join(packageDir, "metadata.json"),
		})
	}

	zipMeta.Members = make([]ZIPMember, len(work))
	for i := range work {
		zipMeta.Members[i] = work[i].member
	}
	if err = d.json("zip-metadata.json", zipMeta); err != nil {
		return metas, err
	}
	if err = writeIntegrity(d); err != nil {
		return metas, err
	}
	return metas, nil
}
