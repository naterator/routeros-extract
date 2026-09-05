// SPDX-License-Identifier: 0BSD
package xz

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"testing"
)

// The synthetic fixture was encoded independently with XZ Utils:
// xz --check=crc32 --arm64 --lzma2=dict=4KiB -c
// It exercises BL, ADRP, unchanged instructions, page boundaries, negative
// offsets and the unaligned suffix, across several output-buffer sizes.
func TestRouterOSARM64BCJAndExactBoundary(t *testing.T) {
	compressed, err := os.ReadFile("testdata/routeros-arm64-bcj.xz")
	if err != nil {
		t.Fatal(err)
	}
	var block bytes.Buffer
	for _, v := range []uint32{0x94000001, 0x90000000, 0xffffffff, 0xd503201f, 0x97ffffff, 0xd0000021} {
		if err := binary.Write(&block, binary.LittleEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	want := append(bytes.Repeat(block.Bytes(), 1024), []byte("abc")...)
	for _, size := range []int{1, 3, 4, 7, 4096, 8192, 65536} {
		z, err := NewReader(bytes.NewReader(append(append([]byte{}, compressed...), 0, 0, 0, 0, 1, 2, 3)), 4096)
		if err != nil {
			t.Fatal(err)
		}
		z.StopAtStreamEnd()
		var out bytes.Buffer
		buf := make([]byte, size)
		for {
			n, e := z.Read(buf)
			out.Write(buf[:n])
			if e == io.EOF {
				break
			}
			if e != nil {
				t.Fatal(e)
			}
		}
		if !bytes.Equal(out.Bytes(), want) {
			t.Fatalf("ARM64 BCJ mismatch with %d-byte output buffer", size)
		}
		if z.InputConsumed() != int64(len(compressed)) {
			t.Fatalf("consumed %d, want %d", z.InputConsumed(), len(compressed))
		}
		if err = z.Reset(bytes.NewReader(compressed)); err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(z)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("reset changed BCJ output")
		}
	}
}
