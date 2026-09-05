// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A tiny CRC32 XZ stream generated once with the system xz/lzma encoder. It
// deliberately lives in the test so tests do not depend on an external tool.
const testXZHex = "fd377a585a0000016922de360200210116000000742fe5a301001168656c6c6f20787a207061796c6f61645c6e000000745ac510000126124747e1109042990d010000000001595a"

func testXZ(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(testXZHex)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testGzip(t *testing.T, payload []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	if _, err := z.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func cpioPad(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func testCPIORecord(magic string, inode, mode, uid, gid, links, mtime uint32, data []byte, name string) []byte {
	fields := []uint32{inode, mode, uid, gid, links, mtime, uint32(len(data)), 0, 0, 0, 0, uint32(len(name) + 1), 0}
	h := make([]byte, 0, 110+len(name)+len(data)+8)
	h = append(h, magic...)
	for _, field := range fields {
		h = append(h, []byte(fmtHex8(field))...)
	}
	h = append(h, name...)
	h = append(h, 0)
	h = cpioPad(h)
	h = append(h, data...)
	return cpioPad(h)
}

func fmtHex8(v uint32) string {
	const hexDigits = "0123456789abcdef"
	b := [8]byte{}
	for i := 7; i >= 0; i-- {
		b[i] = hexDigits[v&0xf]
		v >>= 4
	}
	return string(b[:])
}

func testCPIOHardlinks() []byte {
	b := testCPIORecord("070701", 5, 0100644, 1000, 1000, 2, 7, []byte("abc"), "foo")
	b = append(b, testCPIORecord("070701", 5, 0100644, 1000, 1000, 2, 7, nil, "bar")...)
	b = append(b, testCPIORecord("070701", 0, 0, 0, 0, 1, 0, nil, "TRAILER!!!")...)
	return b
}

func TestDecodeXZAndGzipReportExactConsumption(t *testing.T) {
	xzBytes := testXZ(t)
	xzPayload, consumed, check, err := decodeXZ(append(append([]byte{}, xzBytes...), []byte("TAIL")...), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != len(xzBytes) || check != 1 || !bytes.Equal(xzPayload, []byte("hello xz payload\\n")) {
		t.Fatalf("XZ payload=%q consumed=%d check=%d, want exact stream=%d/check1", xzPayload, consumed, check, len(xzBytes))
	}
	corrupt := append([]byte{}, xzBytes...)
	corrupt[len(corrupt)-8] ^= 0x01
	if _, _, _, err := decodeXZ(corrupt, 1<<20); err == nil {
		t.Fatal("decodeXZ accepted a stream with a damaged integrity field")
	}

	gzipBytes := testGzip(t, []byte("gzip payload"))
	gzipPayload, gzipConsumed, err := decodeGzip(append(append([]byte{}, gzipBytes...), []byte("TAIL")...), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if gzipConsumed != len(gzipBytes) || !bytes.Equal(gzipPayload, []byte("gzip payload")) {
		t.Fatalf("gzip payload=%q consumed=%d, want %d", gzipPayload, gzipConsumed, len(gzipBytes))
	}
}

func TestParseAndExtractCPIOHardlinks(t *testing.T) {
	archive := testCPIOHardlinks()
	entries, end, err := parseCPIO(append(append([]byte{}, archive...), 0, 0, 0), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if end != len(archive) || len(entries) != 2 {
		t.Fatalf("parseCPIO end=%d entries=%d, want %d/2", end, len(entries), len(archive))
	}
	if entries[0].Inode != entries[1].Inode || entries[0].Size != 0 || entries[1].Size != 3 || entries[0].Links != 2 || entries[1].Links != 2 {
		t.Fatalf("hardlink metadata was not retained: %+v", entries)
	}

	root := t.TempDir()
	dir := filepath.Join(root, "out")
	d, err := newDisk(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := extractCPIO(archive, d, "rootfs", Options{}); err != nil {
		d.Close()
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"foo", "bar"} {
		data, err := os.ReadFile(filepath.Join(dir, "rootfs", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, []byte("abc")) {
			t.Errorf("%s = %q, want hardlink content abc", name, data)
		}
	}
}

func TestKernelDataFindsEmbeddedStreamsAndHardlinkArchive(t *testing.T) {
	archive := testCPIOHardlinks()
	gzipBytes := testGzip(t, archive)
	input := append(testXZ(t), gzipBytes...)
	dir := filepath.Join(t.TempDir(), "out")
	d, err := newDisk(dir)
	if err != nil {
		t.Fatal(err)
	}
	report, err := kernelData(input, d, "kernel", Options{}, 0)
	if err != nil {
		d.Close()
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if len(report.Streams) != 2 || len(report.CPIOArchives) != 1 {
		t.Fatalf("report streams=%d cpio=%d: %+v", len(report.Streams), len(report.CPIOArchives), report)
	}
	if report.Streams[0].CompressedSize != len(testXZ(t)) || report.Streams[1].CompressedSize != len(gzipBytes) {
		t.Fatalf("embedded compressed sizes = %d/%d", report.Streams[0].CompressedSize, report.Streams[1].CompressedSize)
	}
	for _, name := range []string{"foo", "bar"} {
		data, err := os.ReadFile(filepath.Join(dir, "kernel", "initramfs", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, []byte("abc")) {
			t.Errorf("embedded %s = %q", name, data)
		}
	}
}

func TestKernelDataRejectsCorruptValidXZBody(t *testing.T) {
	corrupt := testXZ(t)
	corrupt[len(corrupt)-8] ^= 0x01
	dir := filepath.Join(t.TempDir(), "out")
	d, err := newDisk(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = kernelData(corrupt, d, "kernel", Options{}, 0)
	_ = d.Close()
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "xz") {
		t.Fatalf("corrupt valid XZ body error = %v", err)
	}
}
