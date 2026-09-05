// SPDX-License-Identifier: BSD-3-Clause
package decompress

import (
	"bytes"
	"errors"
	"testing"

	"github.com/anchore/go-lzo"
)

// literalLZO builds a synthetic literal-only LZO1X stream from the documented
// stream format; no compressor implementation is included in this fixture.
func literalLZO(data []byte) []byte {
	var out []byte
	if len(data) < 239 {
		out = append(out, byte(len(data)+17))
	} else {
		out = append(out, 0)
		extra := len(data) - 18
		for extra > 255 {
			out = append(out, 0)
			extra -= 255
		}
		out = append(out, byte(extra))
	}
	out = append(out, data...)
	return append(out, 0x11, 0, 0)
}

func TestLZOBlockSizesAndErrors(t *testing.T) {
	d, err := NewLzo()
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{1, 8192, 8193, 128 << 10, 1 << 20} {
		want := bytes.Repeat([]byte("x"), size)
		got, err := d.Decompress(literalLZO(want))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("size %d: got %d bytes, err %v", size, len(got), err)
		}
	}
	if _, err := d.Decompress(literalLZO(make([]byte, 1<<20+1))); !errors.Is(err, lzo.ErrOutputOverrun) {
		t.Fatalf("oversized block: %v", err)
	}
	for _, invalid := range [][]byte{nil, {0x12, 'a'}, {0x12, 'a', 0x40, 0xff, 0x11, 0, 0}} {
		if _, err := d.Decompress(invalid); err == nil {
			t.Fatal("accepted malformed LZO")
		}
	}
}
