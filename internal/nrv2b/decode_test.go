// SPDX-License-Identifier: BSD-3-Clause
package nrv2b

import (
	"bytes"
	"encoding/binary"
	"math/bits"
	"testing"
)

// Synthetic wire-format fixtures: reserve control words as bits are emitted,
// interleaving literal and low-distance bytes with the control stream.
type fixture struct {
	data      []byte
	word      int
	remaining int
}

func (f *fixture) bit(value uint32) {
	if f.remaining == 0 {
		f.word = len(f.data)
		f.data = append(f.data, 0, 0, 0, 0)
		f.remaining = 32
	}
	f.remaining--
	word := binary.LittleEndian.Uint32(f.data[f.word:])
	binary.LittleEndian.PutUint32(f.data[f.word:], word|value<<uint(f.remaining))
}

func (f *fixture) integer(value uint32) {
	for i := bits.Len32(value) - 2; i >= 0; i-- {
		f.bit(value >> uint(i) & 1)
		if i == 0 {
			f.bit(1)
		} else {
			f.bit(0)
		}
	}
}

func (f *fixture) literal(data []byte) {
	for _, b := range data {
		f.bit(1)
		f.data = append(f.data, b)
	}
}

func (f *fixture) match(distance, length uint32, repeat bool) {
	f.bit(0)
	if repeat {
		f.integer(2)
	} else {
		f.integer((distance-1)>>8 + 3)
		f.data = append(f.data, byte(distance-1))
	}
	code := length - 1
	if distance > 0xd00 {
		code--
	}
	if code <= 3 {
		f.bit(code >> 1)
		f.bit(code & 1)
	} else {
		f.bit(0)
		f.bit(0)
		f.integer(code - 2)
	}
}

func (f *fixture) end() []byte {
	f.bit(0)
	f.integer(0x01000002)
	f.data = append(f.data, 0xff)
	return f.data
}

func TestDecodeMatches(t *testing.T) {
	var repeated fixture
	repeated.literal([]byte("abc"))
	repeated.match(3, 6, false)
	repeated.match(3, 3, true)
	var overlap fixture
	overlap.literal([]byte("A"))
	overlap.match(1, 10000, false)
	farBytes := bytes.Repeat([]byte("x"), 0xd01)
	copy(farBytes, "abc")
	var far fixture
	far.literal(farBytes)
	far.match(0xd01, 3, false)
	for _, tc := range []struct {
		name             string
		compressed, want []byte
	}{
		{"repeat previous distance", repeated.end(), []byte("abcabcabcabc")},
		{"overlap and long length", overlap.end(), bytes.Repeat([]byte("A"), 10001)},
		{"far distance length adjustment", far.end(), append(append([]byte{}, farBytes...), 'a', 'b', 'c')},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, used, err := Decode(tc.compressed, len(tc.want))
			if err != nil || used != len(tc.compressed) || !bytes.Equal(out, tc.want) {
				t.Fatalf("Decode: used=%d/%d size=%d/%d err=%v", used, len(tc.compressed), len(out), len(tc.want), err)
			}
			if _, _, err = Decode(tc.compressed, len(tc.want)-1); err == nil {
				t.Fatal("accepted undersized output buffer")
			}
			for i := range len(tc.compressed) {
				if _, _, err = Decode(tc.compressed[:i], len(tc.want)); err == nil {
					t.Fatalf("accepted truncation at %d", i)
				}
			}
		})
	}
}

func TestDecodeRejectsInvalidMatch(t *testing.T) {
	var f fixture
	f.match(1, 2, true)
	if _, _, err := Decode(f.end(), 16); err != ErrOffset {
		t.Fatalf("invalid lookbehind: %v", err)
	}
	var overflow fixture
	overflow.bit(0)
	overflow.integer(0x01000003)
	if _, _, err := Decode(overflow.data, 16); err != ErrCode {
		t.Fatalf("oversized distance: %v", err)
	}
}

func FuzzDecode(f *testing.F) {
	var seed fixture
	seed.literal([]byte("abc"))
	seed.match(3, 99, false)
	f.Add(seed.end())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			t.Skip()
		}
		out, used, err := Decode(data, 4096)
		if used < 0 || used > len(data) || len(out) > 4096 {
			t.Fatal("decoder exceeded input/output bounds")
		}
		if err != nil && out != nil {
			t.Fatal("decoder returned partial output on failure")
		}
	})
}
