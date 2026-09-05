// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"bytes"
	"io"
	"io/fs"
	"slices"
	"testing"

	"github.com/CalebQ42/squashfs"
)

func TestSquashFSNestedArchivePaths(t *testing.T) {
	const name = "nested/small.txt"
	const contents = "BSD extraction fixture\n"
	tests := map[string]func(*testing.T, squashfs.Reader){
		"open": func(t *testing.T, r squashfs.Reader) {
			f, err := r.Open(name)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			b, err := io.ReadAll(f)
			if err != nil || string(b) != contents {
				t.Fatalf("read %s = %q, %v", name, b, err)
			}
		},
		"readfile": func(t *testing.T, r squashfs.Reader) {
			b, err := fs.ReadFile(r.FS, name)
			if err != nil || string(b) != contents {
				t.Fatalf("ReadFile(%q) = %q, %v", name, b, err)
			}
		},
		"stat": func(t *testing.T, r squashfs.Reader) {
			info, err := fs.Stat(r.FS, name)
			if err != nil {
				t.Fatal(err)
			}
			if info.Name() != "small.txt" || info.Size() != int64(len(contents)) || !info.Mode().IsRegular() {
				t.Fatalf("unexpected nested file metadata: %+v", info)
			}
		},
		"readdir": func(t *testing.T, r squashfs.Reader) {
			entries, err := fs.ReadDir(r.FS, "nested")
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Name() != "small.txt" {
				t.Fatalf("unexpected nested directory entries: %+v", entries)
			}
		},
		"sub": func(t *testing.T, r squashfs.Reader) {
			sub, err := fs.Sub(r.FS, "nested")
			if err != nil {
				t.Fatal(err)
			}
			b, err := fs.ReadFile(sub, "small.txt")
			if err != nil || string(b) != contents {
				t.Fatalf("subfilesystem ReadFile = %q, %v", b, err)
			}
		},
		"low-level-open": func(t *testing.T, r squashfs.Reader) {
			file, err := r.Low.Root.Open(r.Low, name)
			if err != nil {
				t.Fatal(err)
			}
			if file.Name != "small.txt" || !file.IsRegular() {
				t.Fatalf("unexpected nested file: %+v", file)
			}
		},
		"glob": func(t *testing.T, r squashfs.Reader) {
			for _, pattern := range []string{"nested/*.txt", "*/*.txt"} {
				matches, err := r.Glob(pattern)
				if err != nil || !slices.Equal(matches, []string{name}) {
					t.Fatalf("Glob(%q) = %q, %v", pattern, matches, err)
				}
				matches, err = fs.Glob(r.FS, pattern)
				if err != nil || !slices.Equal(matches, []string{name}) {
					t.Fatalf("fs.Glob(%q) = %q, %v", pattern, matches, err)
				}
			}
		},
	}
	for name, check := range tests {
		t.Run(name, func(t *testing.T) {
			r, err := squashfs.NewReader(bytes.NewReader(lzoSquashFS))
			if err != nil {
				t.Fatal(err)
			}
			check(t, r)
		})
	}
}
