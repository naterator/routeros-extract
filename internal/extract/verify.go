// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

type Artifact struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Size   int64  `json:"size,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Target string `json:"target,omitempty"`
}
type Integrity struct {
	Schema    int        `json:"schema"`
	Artifacts []Artifact `json:"artifacts"`
}
type Verification struct {
	Verified          bool `json:"verified"`
	Artifacts         int  `json:"artifacts"`
	SectionRoundtrip  bool `json:"section_roundtrip_verified"`
	SourceVerified    bool `json:"source_verified"`
	SignatureVerified bool `json:"signature_verified"`
	Packages          int  `json:"packages,omitempty"`
}

func fileHash(d *disk, name string) (string, int64, error) {
	if e := safePath(name); e != nil {
		return "", 0, e
	}
	s, e := d.Lstat(name)
	if e != nil {
		return "", 0, e
	}
	if !s.Mode().IsRegular() {
		return "", 0, fmt.Errorf("expected regular file: %s", name)
	}
	f, e := d.Open(name)
	if e != nil {
		return "", 0, e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, e
}

// declaredArchivePaths returns the host paths represented by archive-entry
// manifests. Finder can create .DS_Store files while a user browses an
// extraction, so writeIntegrity must distinguish those incidental files from
// a real archive member named .DS_Store. StoredPath is used because it is the
// path actually written to the case-safe browse copy.
func declaredArchivePaths(d *disk) (map[string]bool, error) {
	declared := map[string]bool{}
	err := fs.WalkDir(d.FS(), ".", func(p string, de fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if de.IsDir() || !strings.HasSuffix(p, "-manifest.json") {
			return nil
		}
		b, err := d.read(p, DefaultMaxBytes)
		if err != nil {
			return err
		}
		var entries []Entry
		if err := json.Unmarshal(b, &entries); err != nil {
			// Other generated JSON files may use the suffix in future versions.
			// Preserve the old ledger behavior if one is not an Entry manifest.
			return nil
		}
		folder := strings.TrimSuffix(p, "-manifest.json")
		for _, entry := range entries {
			stored := entry.StoredPath
			if stored == "" {
				stored = entry.Path
			}
			if safePath(stored) != nil {
				continue
			}
			declared[path.Join(folder, stored)] = true
		}
		return nil
	})
	return declared, err
}

func writeIntegrity(d *disk) error {
	r := Integrity{Schema: 1, Artifacts: []Artifact{}}
	declared, e := declaredArchivePaths(d)
	if e != nil {
		return e
	}
	e = fs.WalkDir(d.FS(), ".", func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == "." || p == "integrity.json" {
			return nil
		}
		if e := safePath(p); e != nil {
			return e
		}
		if path.Base(p) == ".DS_Store" && de.Type().IsRegular() && !declared[p] {
			return nil
		}
		v := Artifact{Path: p}
		switch {
		case de.IsDir():
			v.Type = "directory"
		case de.Type()&fs.ModeSymlink != 0:
			v.Type = "symlink"
			v.Target, err = d.Readlink(p)
		case de.Type().IsRegular():
			v.Type = "file"
			v.SHA256, v.Size, err = fileHash(d, p)
		default:
			return fmt.Errorf("unexpected special host file: %s", p)
		}
		if err != nil {
			return err
		}
		r.Artifacts = append(r.Artifacts, v)
		return nil
	})
	if e != nil {
		return e
	}
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		return e
	}
	b = append(b, '\n')
	// Analyze can add derived outputs to an existing extraction. Replace only this
	// generated ledger, atomically, after every output has been written successfully.
	tmp := ".integrity.tmp"
	if e = d.put(tmp, b); e != nil {
		return e
	}
	if e = d.Rename(tmp, "integrity.json"); e != nil {
		_ = d.Remove(tmp)
		return e
	}
	return nil
}

func verifySections(d *disk, m Metadata) error {
	if m.Size < 8 || uint64(m.Size-8) > 0xffffffff {
		return errors.New("invalid NPK size in metadata")
	}
	h := sha256.New()
	header := make([]byte, 8)
	copy(header, npkMagic)
	binary.LittleEndian.PutUint32(header[4:], uint32(m.Size-8))
	_, _ = h.Write(header)
	off := 8
	for i, s := range m.Sections {
		if s.Index != i || s.HeaderOffset != off || s.PayloadOffset != off+6 || s.Size < 0 || s.Size > m.Size-off-6 {
			return fmt.Errorf("inconsistent section metadata at index %d", i)
		}
		b, e := d.read(s.File, int64(s.Size)+1)
		if e != nil {
			return e
		}
		if len(b) != s.Size || digest(b) != s.SHA256 {
			return fmt.Errorf("section hash/size mismatch: %s", s.File)
		}
		tlv := make([]byte, 6)
		binary.LittleEndian.PutUint16(tlv, s.Type)
		binary.LittleEndian.PutUint32(tlv[2:], uint32(s.Size))
		_, _ = h.Write(tlv)
		_, _ = h.Write(b)
		off += 6 + s.Size
	}
	if off != m.Size || hex.EncodeToString(h.Sum(nil)) != m.SHA256 {
		return errors.New("NPK section reconstruction hash mismatch")
	}
	return nil
}

// Verify checks the complete artifact ledger and independently reconstructs the
// NPK hash. Extra host files are ignored; missing/modified artifacts are errors.
func Verify(directory, source string) (Verification, error) {
	r := Verification{}
	d, e := openDisk(directory)
	if e != nil {
		return r, e
	}
	defer d.Close()
	ledger, e := readJSON[Integrity](d, "integrity.json")
	if e != nil {
		return r, e
	}
	if ledger.Schema != 1 {
		return r, errors.New("unsupported integrity schema")
	}
	if len(ledger.Artifacts) == 0 {
		return r, errors.New("integrity ledger contains no artifacts")
	}
	seen := map[string]bool{}
	for _, a := range ledger.Artifacts {
		if e = safePath(a.Path); e != nil {
			return r, e
		}
		if seen[a.Path] {
			return r, fmt.Errorf("duplicate integrity path: %s", a.Path)
		}
		seen[a.Path] = true
		s, e := d.Lstat(a.Path)
		if e != nil {
			return r, e
		}
		switch a.Type {
		case "file":
			hash, n, e := fileHash(d, a.Path)
			if e != nil {
				return r, e
			}
			if n != a.Size || hash != a.SHA256 {
				return r, fmt.Errorf("artifact hash/size mismatch: %s", a.Path)
			}
		case "directory":
			if !s.IsDir() {
				return r, fmt.Errorf("expected directory: %s", a.Path)
			}
		case "symlink":
			if s.Mode()&fs.ModeSymlink == 0 {
				return r, fmt.Errorf("expected symlink: %s", a.Path)
			}
			target, e := d.Readlink(a.Path)
			if e != nil {
				return r, e
			}
			if target != a.Target {
				return r, fmt.Errorf("symlink target mismatch: %s", a.Path)
			}
		default:
			return r, fmt.Errorf("unknown artifact type %q", a.Type)
		}
		r.Artifacts++
	}
	if seen["metadata.json"] {
		m, e := readJSON[Metadata](d, "metadata.json")
		if e != nil {
			return r, e
		}
		if e = verifySections(d, m); e != nil {
			return r, e
		}
		r.SectionRoundtrip = true
		if source != "" {
			f, e := os.Open(source)
			if e != nil {
				return r, e
			}
			info, e := f.Stat()
			if e != nil || !info.Mode().IsRegular() {
				_ = f.Close()
				return r, fmt.Errorf("source is not a readable regular file: %s", source)
			}
			h := sha256.New()
			n, e := io.Copy(h, f)
			e = errors.Join(e, f.Close())
			if e != nil {
				return r, e
			}
			if n != int64(m.Size) || hex.EncodeToString(h.Sum(nil)) != m.SHA256 {
				return r, fmt.Errorf("source NPK mismatch: %s", filepath.Base(source))
			}
			r.SourceVerified = true
		}
	} else if seen["zip-metadata.json"] {
		z, e := readJSON[ZIPMetadata](d, "zip-metadata.json")
		if e != nil {
			return r, e
		}
		if z.Schema != 1 || len(z.Packages) == 0 {
			return r, errors.New("invalid ZIP package manifest")
		}
		for _, pkg := range z.Packages {
			if e = safePath(pkg.Directory); e != nil {
				return r, e
			}
			if e = safePath(pkg.NPKPath); e != nil {
				return r, e
			}
			sub, e := d.OpenRoot(pkg.Directory)
			if e != nil {
				return r, e
			}
			sd := &disk{sub}
			m, e := readJSON[Metadata](sd, "metadata.json")
			if e == nil {
				e = verifySections(sd, m)
			}
			_ = sd.Close()
			if e != nil {
				return r, e
			}
			h, n, e := fileHash(d, pkg.NPKPath)
			if e != nil {
				return r, e
			}
			if h != m.SHA256 || n != int64(m.Size) || h != pkg.SHA256 {
				return r, fmt.Errorf("ZIP member hash mismatch: %s", pkg.NPKPath)
			}
			r.Packages++
		}
		r.SectionRoundtrip = true
		if source != "" {
			b, e := ReadInput(source, Options{MaxBytes: z.SourceSize + 1})
			if e != nil {
				return r, e
			}
			if int64(len(b)) != z.SourceSize || digest(b) != z.SourceSHA256 {
				return r, errors.New("source ZIP hash mismatch")
			}
			r.SourceVerified = true
		}
	} else if source != "" {
		return r, errors.New("--source requires an extracted NPK or ZIP collection")
	}
	r.Verified = true
	return r, nil
}
