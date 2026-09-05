// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestKernelDataSharesDecodedBudgetAcrossNestedStreams(t *testing.T) {
	const limit = int64(1024)

	// The outer stream expands to copies of a stream that expands to copies of
	// the leaf. The compressed input remains small, but the recursive decoded
	// output is much larger than the single extraction budget.
	leaf := testGzip(t, bytes.Repeat([]byte{'A'}, int(limit)))
	nodePayload := bytes.Join([][]byte{[]byte("junk"), leaf}, nil)
	node := testGzip(t, nodePayload)
	rootPayload := bytes.Repeat(node, 2)
	root := testGzip(t, rootPayload)
	if int64(len(root)) >= limit {
		t.Fatalf("test input compressed size=%d, want less than limit=%d", len(root), limit)
	}

	dir := filepath.Join(t.TempDir(), "out")
	d, err := newDisk(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = kernelData(root, d, "kernel", Options{MaxBytes: limit}, 0)
	closeErr := d.Close()
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "limit") {
		t.Fatalf("nested decoded expansion error=%v, want byte-limit error", err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
}

func TestParseCPIORejectsOversizedOrNULTerminatedSymlinkMetadata(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		want string
	}{
		{name: "oversized", body: bytes.Repeat([]byte{'x'}, maxInlineMetadataBytes+1), want: "exceeds"},
		{name: "NUL", body: []byte("target\x00suffix"), want: "NUL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			archive := testCPIORecord("070701", 7, 0120000, 1000, 1000, 1, 7, tt.body, "link")
			archive = append(archive, testCPIORecord("070701", 0, 0, 0, 0, 1, 0, nil, "TRAILER!!!")...)
			_, _, err := parseCPIO(archive, Options{MaxBytes: 1 << 20})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("parseCPIO error=%v, want %q", err, tt.want)
			}
		})
	}
}

func TestExtractCPIOHardlinkMaterializationHonorsByteLimit(t *testing.T) {
	const limit = int64(1000)
	data := bytes.Repeat([]byte{'B'}, 600)
	archive := testCPIORecord("070701", 5, 0100644, 1000, 1000, 3, 7, data, "source")
	archive = append(archive, testCPIORecord("070701", 5, 0100644, 1000, 1000, 3, 7, nil, "link-a")...)
	archive = append(archive, testCPIORecord("070701", 5, 0100644, 1000, 1000, 3, 7, nil, "link-b")...)
	archive = append(archive, testCPIORecord("070701", 0, 0, 0, 0, 1, 0, nil, "TRAILER!!!")...)

	d, err := newDisk(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	err = extractCPIO(archive, d, "rootfs", Options{MaxBytes: limit})
	closeErr := d.Close()
	if err == nil || !strings.Contains(err.Error(), "materialized file data") {
		t.Fatalf("extractCPIO error=%v, want materialization limit error", err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
}
