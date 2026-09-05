// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"testing"
)

// This fixture is generated from a directory containing one empty regular
// file and one non-empty regular file.  The empty record is the case that
// exposed the upstream reader's attempt to read block zero from a file with
// no data blocks.
//
//go:embed testdata/empty-file.squashfs
var emptyFileSquashFS []byte

//go:embed testdata/lzo.squashfs
var lzoSquashFS []byte

func TestUnpackLZOSquashFS(t *testing.T) {
	if binary.LittleEndian.Uint16(lzoSquashFS[20:]) != 3 {
		t.Fatal("fixture must exercise the LZO compression type")
	}
	d, err := newDisk(t.TempDir() + "/extracted")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	entries, err := unpackSquashFS(lzoSquashFS, d, "rootfs", Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]byte{
		"empty":            {},
		"repeat.txt":       bytes.Repeat([]byte("RouterOS LZO fixture\n"), 12000),
		"nested/small.txt": []byte("BSD extraction fixture\n"),
	}
	for _, entry := range entries {
		if entry.Type != "file" {
			continue
		}
		contents, ok := want[entry.Path]
		if !ok || !bytes.Equal(entry.data, contents) {
			t.Fatalf("unexpected LZO file contents: %s", entry.Path)
		}
		delete(want, entry.Path)
	}
	if len(want) != 0 {
		t.Fatalf("missing files: %v", want)
	}
}

func TestUnpackSquashFSAllowsEmptyRegularFiles(t *testing.T) {
	output := t.TempDir() + "/extracted"
	d, err := newDisk(output)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	entries, err := unpackSquashFS(emptyFileSquashFS, d, "rootfs", Options{MaxBytes: DefaultMaxBytes})
	if err != nil {
		t.Fatalf("unpack synthetic SquashFS: %v", err)
	}
	if len(entries) != 2 { // root directory is not returned by WalkDir
		t.Fatalf("entry count = %d, want 2", len(entries))
	}

	var emptyFound, nonemptyFound bool
	for _, entry := range entries {
		switch entry.Path {
		case "empty":
			emptyFound = true
			if entry.Type != "file" || entry.Size != 0 || len(entry.data) != 0 {
				t.Fatalf("empty entry = %#v, want zero-length regular file", entry)
			}
		case "nonempty":
			nonemptyFound = true
			if entry.Type != "file" || string(entry.data) != "routeros squashfs fixture\n" {
				t.Fatalf("non-empty entry = %#v, want fixture contents", entry)
			}
		}
	}
	if !emptyFound || !nonemptyFound {
		t.Fatalf("entries did not include empty and non-empty fixture files: %#v", entries)
	}

	f, err := d.Open("rootfs/empty")
	if err != nil {
		t.Fatal(err)
	}
	info, err := f.Stat()
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("exported empty file size = %d, want 0", info.Size())
	}
}
