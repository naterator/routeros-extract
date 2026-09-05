// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func syntheticLegacyFWF(tag, version string, payload []byte) []byte {
	b := make([]byte, 32, 32+len(payload))
	copy(b[:4], tag)
	copy(b[12:32], version+"\x00")
	return append(b, payload...)
}

func syntheticELF64() []byte {
	b := make([]byte, 64)
	copy(b[:4], []byte{0x7f, 'E', 'L', 'F'})
	b[4] = 2  // ELFCLASS64
	b[5] = 1  // ELFDATA2LSB
	b[6] = 1  // EV_CURRENT
	b[16] = 2 // ET_EXEC
	b[18] = 0x3e
	b[19] = 0x00 // EM_X86_64
	b[20] = 1    // EV_CURRENT
	b[52] = 64   // ELF header size
	return b
}

func TestDecodeLegacyFirmwareKnownRawTag(t *testing.T) {
	payload := []byte{0x10, 0x00, 0x00, 0x79, 'R', 'B', 'O', 'K'}
	out, info, err := DecodeFirmware(syntheticLegacyFWF("0339", "7.24.2", payload), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, payload) {
		t.Fatalf("payload = %x, want %x", out, payload)
	}
	if info.Format != "routerboot-legacy-raw" || info.Codec != "none" || info.Decoded || info.CRC32Available || info.CRC32Verified {
		t.Fatalf("unexpected legacy metadata: %+v", info)
	}
	if info.HeaderBytes != 32 || info.PayloadOffset != 32 || info.PayloadSize != len(payload) || info.DecodedSize != len(payload) {
		t.Fatalf("unexpected legacy sizes: %+v", info)
	}
}

func TestDecodeLegacyFirmwareLargeConfiguredLimit(t *testing.T) {
	// Keep the comparison in int64 even when compiled for 32-bit hosts.
	payload := []byte("legacy payload")
	b := syntheticLegacyFWF("0339", "7.24.2", payload)
	if _, _, err := DecodeFirmware(b, Options{MaxBytes: 4 << 30}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := DecodeFirmware(b, Options{MaxBytes: 2}); err == nil {
		t.Fatal("accepted legacy payload larger than the configured limit")
	}
}

func TestDecodeLegacyFirmwareUnknownTagRequiresValidELF(t *testing.T) {
	payload := syntheticELF64()
	out, info, err := DecodeFirmware(syntheticLegacyFWF("new?", "7.24rc1", payload), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, payload) || info.Format != "routerboot-legacy-elf" || info.Decoded {
		t.Fatalf("unexpected ELF legacy result: format=%s decoded=%t bytes=%d", info.Format, info.Decoded, len(out))
	}
}

func TestDecodeFirmwareRejectsCorruptModernPrintableHeader(t *testing.T) {
	b := make([]byte, 44)
	copy(b[:4], "0x07")
	copy(b[12:32], "7.24.2\x00")
	binary.LittleEndian.PutUint32(b[8:12], uint32(len(b)-32))
	binary.LittleEndian.PutUint32(b[32:36], 0xffffffff)
	if _, _, err := DecodeFirmware(b, Options{}); err == nil || !strings.Contains(err.Error(), "invalid RouterBOOT FWF block length") {
		t.Fatalf("corrupt modern header error = %v", err)
	}
}

func TestDecodeFirmwareRejectsTruncatedModernPrintableHeader(t *testing.T) {
	b := make([]byte, 32)
	copy(b[:4], "0x07")
	copy(b[12:32], "7.24.2\x00")
	if _, _, err := DecodeFirmware(b, Options{}); err == nil {
		t.Fatal("truncated modern header was accepted")
	}
}
