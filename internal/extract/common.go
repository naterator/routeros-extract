// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const DefaultMaxBytes int64 = 512 << 20
const MaxEntries = 100000

// errByteLimit identifies bounded reads that exceeded their caller's limit.
// Callers can use errors.Is while the wrapped message retains the limit for
// human-readable diagnostics.
var errByteLimit = errors.New("decoded/input size exceeds limit")

type Options struct {
	MaxBytes      int64
	SectionsOnly  bool
	NoDerived     bool
	NoSymlinks    bool
	ConsoleParser string
}

func (o Options) limit() int64 {
	if o.MaxBytes > 0 {
		return o.MaxBytes
	}
	return DefaultMaxBytes
}

// Entry records original archive metadata; stored_path identifies the browse copy.
type Entry struct {
	Path        string `json:"path"`
	StoredPath  string `json:"stored_path,omitempty"`
	Type        string `json:"type"`
	Mode        string `json:"mode"`
	UID         int    `json:"uid"`
	GID         int    `json:"gid"`
	Mtime       string `json:"mtime_utc"`
	Size        int64  `json:"size,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	Target      string `json:"target,omitempty"`
	HeaderHex   string `json:"header_hex,omitempty"`
	ArchivePath string `json:"archive_path,omitempty"`
	VariantTag  string `json:"variant_tag_hex,omitempty"`
	PayloadHex  string `json:"payload_hex,omitempty"`
	RdevMajor   uint32 `json:"rdev_major,omitempty"`
	RdevMinor   uint32 `json:"rdev_minor,omitempty"`
	Inode       uint32 `json:"inode,omitempty"`
	Links       uint32 `json:"links,omitempty"`
	data        []byte
}

func digest(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func utc(t uint32) string    { return time.Unix(int64(t), 0).UTC().Format("2006-01-02T15:04:05+00:00") }
func octal(v uint32) string  { return fmt.Sprintf("0o%o", v) }
func modeValue(s string) (uint32, error) {
	n, e := strconv.ParseUint(strings.TrimPrefix(s, "0o"), 8, 32)
	return uint32(n), e
}

func bounded(r io.Reader, max int64) ([]byte, error) {
	if max < 1 {
		return nil, errors.New("invalid byte limit")
	}
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%w of %d bytes", errByteLimit, max)
	}
	return b, nil
}

func ReadInput(name string, opt Options) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !s.Mode().IsRegular() {
		return nil, fmt.Errorf("input is not a regular file: %s", name)
	}
	if s.Size() > opt.limit() {
		return nil, fmt.Errorf("input exceeds limit of %d bytes", opt.limit())
	}
	return bounded(f, opt.limit())
}

func safePath(name string) error {
	if name == "." || !fs.ValidPath(name) || !utf8.ValidString(name) || strings.ContainsAny(name, "\x00\\:") {
		return fmt.Errorf("unsafe or unsupported archive path %q", name)
	}
	if len(name) > 4096 || strings.Count(name, "/") > 64 {
		return fmt.Errorf("archive path too deep/long: %q", name)
	}
	return nil
}

// A portable component is deliberately a little shorter than the common
// 255-byte filesystem limit.  Derived reports append names such as .txt,
// .parts, and .strings.txt to stored paths, so keeping aliases below this
// limit leaves room for those suffixes on filesystems with that limit.
const (
	portableComponentMax = 240
	portableHashLength   = 12
)

// portableComponent returns a component that can be created on the supported
// Unix and Windows filesystems.  Ordinary ASCII names retain their original
// spelling.  Names that need an alias retain a readable ASCII prefix and end
// in a deterministic hash of the original component.
//
// Non-ASCII components are aliased as a simple normalization policy.  That
// keeps composed/decomposed Unicode spellings from becoming the same browse
// path on normalization-insensitive filesystems without adding a Unicode
// normalization dependency.  The original spelling remains in Entry.Path and
// in the TAR archive.
func portableComponent(name string) string {
	if !portableComponentNeedsAlias(name) {
		return name
	}
	return portableAlias(name, name)
}

func portableComponentNeedsAlias(name string) bool {
	if name == "" || name == "." || name == ".." || !utf8.ValidString(name) || len(name) > portableComponentMax {
		return true
	}
	if strings.TrimRight(name, " .") != name || windowsReservedComponent(name) {
		return true
	}
	for _, r := range name {
		if r > 0x7f || r < 0x20 || r == 0x7f || strings.ContainsRune(`<>:"/\\|?*`, r) {
			return true
		}
	}
	return false
}

func windowsReservedComponent(name string) bool {
	stem := name
	if i := strings.IndexByte(stem, '.'); i >= 0 {
		stem = stem[:i]
	}
	stem = strings.TrimRight(stem, " .")
	upper := strings.ToUpper(stem)
	switch upper {
	case "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$":
		return true
	}
	if len(upper) == 4 && (strings.HasPrefix(upper, "COM") || strings.HasPrefix(upper, "LPT")) {
		return upper[3] >= '1' && upper[3] <= '9'
	}
	return false
}

func portableAlias(name, seed string) string {
	prefix := portableReadablePrefix(name)
	hash := digest([]byte(seed))[:portableHashLength]
	const marker = "_ros_"
	maxPrefix := portableComponentMax - len(marker) - 1 - len(hash)
	if len(prefix) > maxPrefix {
		prefix = prefix[:maxPrefix]
	}
	if prefix == "" {
		prefix = "path"
	}
	return marker + prefix + "_" + hash
}

func portableReadablePrefix(name string) string {
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return strings.TrimRight(b.String(), " .")
}

func collisionComponent(base, seed string, attempt int) string {
	marker := ".__case_" + digest([]byte(seed))[:8]
	if attempt > 1 {
		marker += "_" + strconv.Itoa(attempt)
	}
	maxPrefix := portableComponentMax - len(marker)
	if len(base) > maxPrefix {
		base = base[:maxPrefix]
	}
	if base == "" {
		base = "_"
	}
	return base + marker
}

func portablePathKey(name string) string {
	// All components returned by portableComponent are ASCII.  Lowercasing
	// therefore covers case-insensitive Unix and Windows browse filesystems;
	// non-ASCII names were aliased before reaching this key.
	return strings.ToLower(name)
}

// disk confines all reads/writes beneath a directory using Go's os.Root.
type disk struct{ *os.Root }

func openDisk(dir string) (*disk, error) { r, e := os.OpenRoot(dir); return &disk{r}, e }
func newDisk(dir string) (*disk, error) {
	if err := os.MkdirAll(filepath.Dir(dir), 0755); err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, 0755); err != nil {
		return nil, fmt.Errorf("output must be a new directory: %w", err)
	}
	return openDisk(dir)
}
func (d *disk) put(name string, b []byte) error {
	if err := safePath(name); err != nil {
		return err
	}
	if err := d.MkdirAll(path.Dir(name), 0755); err != nil {
		return err
	}
	f, e := d.OpenFile(filepath.FromSlash(name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	return errors.Join(e, f.Close())
}
func (d *disk) json(name string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return d.put(name, append(b, '\n'))
}
func (d *disk) read(name string, max int64) ([]byte, error) {
	if e := safePath(name); e != nil {
		return nil, e
	}
	s, e := d.Lstat(name)
	if e != nil {
		return nil, e
	}
	if !s.Mode().IsRegular() {
		return nil, fmt.Errorf("expected regular file: %s", name)
	}
	f, e := d.Open(name)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return bounded(f, max)
}
func readJSON[T any](d *disk, name string) (T, error) {
	var v T
	b, e := d.read(name, DefaultMaxBytes)
	if e != nil {
		return v, e
	}
	e = json.Unmarshal(b, &v)
	return v, e
}

// planPaths rejects duplicate nodes and symlink/file ancestors before any writes.
// Portable aliases are deterministic across case-sensitive and
// case-insensitive hosts while Entry.Path remains the original archive path.
func planPaths(entries []Entry) ([]Entry, error) {
	if len(entries) > MaxEntries {
		return nil, errors.New("too many archive entries")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	types := map[string]string{".": "directory"}
	for _, e := range entries {
		if err := safePath(e.Path); err != nil {
			return nil, err
		}
		if _, ok := types[e.Path]; ok {
			return nil, fmt.Errorf("duplicate archive path: %s", e.Path)
		}
		types[e.Path] = e.Type
	}
	for _, e := range entries {
		for p := path.Dir(e.Path); p != "."; p = path.Dir(p) {
			if t, ok := types[p]; ok && t != "directory" {
				return nil, fmt.Errorf("non-directory archive ancestor %q of %q", p, e.Path)
			}
			if _, ok := types[p]; !ok {
				types[p] = "directory"
			}
		}
	}
	names := make([]string, 0, len(types))
	for p := range types {
		if p != "." {
			names = append(names, p)
		}
	}
	sort.Strings(names)
	mapped := map[string]string{".": "."}
	used := map[string]bool{}
	for _, p := range names {
		parent := mapped[path.Dir(p)]
		component := portableComponent(path.Base(p))
		candidate := path.Join(parent, component)
		for attempt := 1; used[portablePathKey(candidate)]; attempt++ {
			component = collisionComponent(component, p, attempt)
			candidate = path.Join(parent, component)
		}
		used[portablePathKey(candidate)] = true
		mapped[p] = candidate
	}
	for i := range entries {
		entries[i].StoredPath = mapped[entries[i].Path]
	}
	return entries, nil
}

func writeEntries(d *disk, folder string, entries []Entry, noSymlinks bool) error {
	if e := d.MkdirAll(folder, 0755); e != nil {
		return e
	}
	// Write every ordinary node before creating links. No archive link is followed.
	for _, e := range entries {
		n := path.Join(folder, e.StoredPath)
		switch e.Type {
		case "directory":
			if err := d.MkdirAll(n, 0755); err != nil {
				return err
			}
		case "file":
			if err := d.put(n, e.data); err != nil {
				return err
			}
		}
	}
	for _, e := range entries {
		if e.Type == "symlink" && !noSymlinks {
			n := path.Join(folder, e.StoredPath)
			if err := d.MkdirAll(path.Dir(n), 0755); err != nil {
				return err
			}
			if err := d.Symlink(e.Target, n); err != nil {
				return err
			}
		}
	}
	return nil
}

func asciiStrings(b []byte, min int) []string {
	out := []string{}
	start := 0
	for i := 0; i <= len(b); i++ {
		if i == len(b) || b[i] < 32 || b[i] > 126 {
			if i-start >= min {
				out = append(out, string(b[start:i]))
			}
			start = i + 1
		}
	}
	return out
}
func stringDump(b []byte) []byte { return []byte(strings.Join(asciiStrings(b, 6), "\n") + "\n") }
func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return strings.ToValidUTF8(string(b), "�")
}

func folderName(base string, n int) string {
	if n == 1 {
		return base
	}
	return fmt.Sprintf("%s-%d", base, n)
}
