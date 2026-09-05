// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/naterator/routeros-extract/internal/nrv2b"
)

type FirmwareInfo struct {
	Source            string `json:"source,omitempty"`
	File              string `json:"file,omitempty"`
	SHA256            string `json:"sha256"`
	Format            string `json:"format"`
	Codec             string `json:"codec"`
	PlatformTag       string `json:"platform_tag_hex"`
	Version           string `json:"version"`
	HeaderBytes       int    `json:"header_bytes"`
	PayloadOffset     int    `json:"payload_offset"`
	PayloadSize       int    `json:"payload_size"`
	CompressedOffset  int    `json:"compressed_offset"`
	Consumed          int    `json:"compressed_bytes_consumed"`
	DecodedSize       int    `json:"decoded_size"`
	Decoded           bool   `json:"decoded"`
	CRC32Available    bool   `json:"crc32_available"`
	CRC32Verified     bool   `json:"crc32_verified"`
	TrailingBytes     int    `json:"trailing_bytes"`
	SignatureVerified bool   `json:"trailing_signature_verified"`
}

var legacyFirmwareTags = map[string]bool{
	"0017": true, "1427": true, "0339": true, "L339": true,
	"0439": true, "l439": true, "4439": true, "L439": true,
	"8513": true, "851L": true, "871L": true, "0359": true,
	"L359": true, "0559": true, "L559": true, "1267": true,
	"a460": true, "8323": true, "8343": true, "8544": true,
	"85xx": true, "1023": true, "2020": true, "eliT": true,
}

var firmwareVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[A-Za-z][A-Za-z0-9.-]*)?$`)

func legacyVersion(b []byte) (string, bool) {
	if len(b) < 32 {
		return "", false
	}
	versionField := b[12:32]
	nul := bytes.IndexByte(versionField, 0)
	if nul < 1 {
		return "", false
	}
	for _, c := range versionField[nul+1:] {
		if c != 0 {
			return "", false
		}
	}
	for _, c := range versionField[:nul] {
		if c < 0x20 || c > 0x7e {
			return "", false
		}
	}
	version := string(versionField[:nul])
	return version, firmwareVersionPattern.MatchString(version)
}

func validFirmwareELF(payload []byte) bool {
	if len(payload) < 4 || !bytes.Equal(payload[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return false
	}
	f, err := elf.NewFile(bytes.NewReader(payload))
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func decodeRouterBOOTStream(src []byte, expected int) ([]byte, int, error) {
	if expected <= 0 || expected > 16<<20 {
		return nil, 0, errors.New("invalid RouterBOOT decompressed length")
	}
	decoded, used, err := nrv2b.Decode(src, expected)
	if err != nil {
		return nil, 0, fmt.Errorf("RouterBOOT NRV2B: %w", err)
	}
	if len(decoded) != expected {
		return nil, 0, errors.New("RouterBOOT decoded size does not match header")
	}
	padding := src[used:]
	if len(padding) > 3 || !bytes.Equal(padding, make([]byte, len(padding))) {
		return nil, 0, errors.New("invalid RouterBOOT NRV2B padding")
	}
	return decoded, used, nil
}

// legacyFWF recognizes the pre-NRV2B RouterBOOT envelope used by the older
// MIPS, PowerPC, TILE-Gx, and some other cores.  Those files have a 32-byte
// header followed by the raw RouterBOOT image.  The size field at offset 8 is
// encoded in the target's byte order for the formats that carry it; a few
// older MIPS headers instead carry a board-specific value there, so the
// header length is deliberately not required to match it.
//
// The legacy header has no CRC32 field with the semantics of the modern
// NRV2B envelope.  Keep the payload intact and report that fact explicitly
// instead of pretending that an uncompressed image was decoded.
func legacyFWF(b []byte, opt Options) ([]byte, FirmwareInfo, bool, error) {
	if len(b) < 32 {
		return nil, FirmwareInfo{}, false, nil
	}
	// A RouterBOOT FWF header has a four-byte platform identifier and a
	// NUL-padded version string.  Require the complete field to be ASCII and
	// NUL-padded; a printable prefix alone is not enough to classify a
	// malformed modern envelope as a legacy image.
	tag := string(b[:4])
	version, validVersion := legacyVersion(b)
	if !validVersion {
		return nil, FirmwareInfo{}, false, nil
	}
	if len(b) == 32 {
		return nil, FirmwareInfo{}, true, errors.New("empty RouterBOOT legacy payload")
	}
	if !legacyFirmwareTags[tag] && !validFirmwareELF(b[32:]) {
		return nil, FirmwareInfo{}, false, nil
	}
	if int64(len(b)-32) > opt.limit() {
		return nil, FirmwareInfo{}, true, errors.New("RouterBOOT raw payload exceeds byte limit")
	}
	payload := b[32:]
	format := "routerboot-legacy-raw"
	if validFirmwareELF(payload) {
		format = "routerboot-legacy-elf"
	}
	info := FirmwareInfo{
		Format:           format,
		Codec:            "none",
		PlatformTag:      hex.EncodeToString(b[:4]),
		Version:          version,
		HeaderBytes:      32,
		PayloadOffset:    32,
		PayloadSize:      len(payload),
		CompressedOffset: 32,
		Consumed:         len(payload),
		DecodedSize:      len(payload),
		Decoded:          false,
		CRC32Available:   false,
		CRC32Verified:    false,
		TrailingBytes:    0,
		SHA256:           digest(payload),
	}
	return payload, info, true, nil
}

func DecodeFirmware(b []byte, opt Options) ([]byte, FirmwareInfo, error) {
	m := FirmwareInfo{}
	if len(b) < 32 {
		return nil, m, errors.New("truncated RouterBOOT FWF header")
	}
	// Known legacy platform tags take precedence over the modern framing
	// fields.  Some old raw images begin with bytes that happen to look like a
	// valid modern block length.
	if out, legacy, ok, e := legacyFWF(b, opt); ok {
		return out, legacy, e
	}
	// Modern RouterBOOT files use the 40-byte NRV2B envelope documented by
	// the current RouterBOOT encoder. Once classified as modern, any framing,
	// checksum, or decompression error is fatal.
	if len(b) >= 44 {
		block := uint64(binary.LittleEndian.Uint32(b[32:]))
		expected := uint64(binary.LittleEndian.Uint32(b[36:]))
		end := 36 + block
		if block >= 8 && end <= uint64(len(b)) {
			if expected > uint64(opt.limit()) {
				return nil, m, errors.New("RouterBOOT expanded size exceeds byte limit")
			}
			if crc32.ChecksumIEEE(b[32:end-4]) != binary.LittleEndian.Uint32(b[end-4:end]) {
				return nil, m, errors.New("RouterBOOT FWF CRC32 mismatch")
			}
			out, n, e := decodeRouterBOOTStream(b[40:end-4], int(expected))
			if e != nil {
				return nil, m, e
			}
			m = FirmwareInfo{
				Format:            "routerboot-nrv2b",
				Codec:             "nrv2b",
				PlatformTag:       hex.EncodeToString(b[:4]),
				Version:           cstring(b[12:32]),
				HeaderBytes:       40,
				PayloadOffset:     40,
				PayloadSize:       len(b[40 : end-4]),
				CompressedOffset:  40,
				Consumed:          n,
				DecodedSize:       len(out),
				Decoded:           true,
				CRC32Available:    true,
				CRC32Verified:     true,
				TrailingBytes:     len(b) - int(end),
				SignatureVerified: false,
				SHA256:            digest(out),
			}
			return out, m, nil
		}
	}
	return nil, m, errors.New("invalid RouterBOOT FWF block length")
}

func Firmware(source, destination string, opt Options) (FirmwareInfo, error) {
	b, e := ReadInput(source, opt)
	if e != nil {
		return FirmwareInfo{}, e
	}
	out, m, e := DecodeFirmware(b, opt)
	if e != nil {
		return m, e
	}
	d, e := newDisk(destination)
	if e != nil {
		return m, e
	}
	defer d.Close()
	stem := strings.TrimSuffix(filepath.Base(source), filepath.Ext(source))
	if e = safePath(stem); e != nil {
		return m, e
	}
	m.Source = filepath.Base(source)
	m.File = stem + ".bin"
	for name, data := range map[string][]byte{"source.fwf": b, m.File: out, stem + ".strings.txt": stringDump(out)} {
		if e = d.put(name, data); e != nil {
			return m, fmt.Errorf("firmware output: %w", e)
		}
	}
	if e = d.json("manifest.json", []FirmwareInfo{m}); e != nil {
		return m, e
	}
	return m, writeIntegrity(d)
}
