// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"strings"
	"testing"
)

// packNRVWord uses the NRV2B wire order: a little-endian uint32
// whose most significant bit is the first bit in the stream.
func packNRVWord(bits []uint32) []byte {
	if len(bits) != 32 {
		panic("NRV test words must contain 32 bits")
	}
	var word uint32
	for _, bit := range bits {
		word = (word << 1) | bit
	}
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, word)
	return b
}

// testNRVLiteral produces one literal followed by the NRV2B end marker. The
// marker is the long-distance sentinel used by the RouterBOOT decoder.
func testNRVLiteral(value byte) []byte {
	// (0x01000002-3)*256 + 0xff == 0xffffffff. The decoder's guard
	// intentionally permits this largest distance code as the end marker.
	target := uint32(0x01000002)
	bits := []uint32{1, 0} // literal, then the back-reference branch
	for i := 23; i >= 0; i-- {
		bits = append(bits, (target>>uint(i))&1)
		if i == 0 {
			bits = append(bits, 1) // end of the distance code
		} else {
			bits = append(bits, 0)
		}
	}
	for len(bits) < 64 {
		bits = append(bits, 0)
	}
	out := packNRVWord(bits[:32])
	out = append(out, value)
	out = append(out, packNRVWord(bits[32:])...)
	out = append(out, 0xff)
	return out
}

func testFWF(expected uint32, compressed []byte, trailer []byte) []byte {
	block := uint32(8 + len(compressed))
	end := 36 + int(block)
	b := make([]byte, 40)
	copy(b[:4], []byte{0xa3, 0x70, 0x00, 0x01})
	copy(b[12:32], []byte("synthetic-routerboot"))
	binary.LittleEndian.PutUint32(b[32:36], block)
	binary.LittleEndian.PutUint32(b[36:40], expected)
	b = append(b, compressed...)
	b = append(b, make([]byte, 4)...)
	binary.LittleEndian.PutUint32(b[end-4:end], crc32.ChecksumIEEE(b[32:end-4]))
	return append(b, trailer...)
}

func TestNRV2BLiteralAndMalformedInputs(t *testing.T) {
	compressed := testNRVLiteral('A')
	out, consumed, err := decodeRouterBOOTStream(compressed, 1)
	if err != nil {
		t.Fatalf("valid literal: %v", err)
	}
	if !bytes.Equal(out, []byte("A")) || consumed != len(compressed) {
		t.Fatalf("decoded %q consumed %d, want A/%d", out, consumed, len(compressed))
	}
	for _, tc := range []struct {
		name     string
		input    []byte
		expected int
	}{
		{"truncated", compressed[:len(compressed)-1], 1},
		{"bad padding", append(append([]byte{}, compressed...), 0, 0, 1, 0), 1},
		{"zero output", compressed, 0},
		{"too large", compressed, 16<<20 + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := decodeRouterBOOTStream(tc.input, tc.expected); err == nil {
				t.Fatal("nrv2b accepted malformed input")
			}
		})
	}
}

func TestDecodeFirmwareChecksCRCAndMetadata(t *testing.T) {
	compressed := testNRVLiteral('A')
	b := testFWF(1, compressed, []byte{0xde, 0xad, 0xbe})
	out, info, err := DecodeFirmware(b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, []byte("A")) {
		t.Fatalf("decoded firmware = %q", out)
	}
	if info.PlatformTag != "a3700001" || info.Version != "synthetic-routerboot" || !info.CRC32Verified || info.TrailingBytes != 3 || info.Consumed != len(compressed) {
		t.Fatalf("unexpected firmware metadata: %+v", info)
	}

	badCRC := append([]byte{}, b...)
	badCRC[40] ^= 0x01
	if _, _, err := DecodeFirmware(badCRC, Options{}); err == nil || !strings.Contains(err.Error(), "CRC32") {
		t.Fatalf("bad CRC error = %v", err)
	}

	limited := testFWF(2, compressed, nil)
	if _, _, err := DecodeFirmware(limited, Options{MaxBytes: 1}); err == nil || !strings.Contains(err.Error(), "expanded size") {
		t.Fatalf("limit error = %v", err)
	}
}
