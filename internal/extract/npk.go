// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

var npkMagic = []byte{0x1e, 0xf1, 0xd0, 0xba}
var labels = map[uint16]string{1: "package_info", 2: "description", 3: "dependencies", 4: "file_container", 7: "install_script", 8: "uninstall_script", 9: "signature", 0x10: "architecture_or_trailer", 0x12: "main_info", 0x15: "squashfs", 0x16: "padding_unknown", 0x17: "digest_metadata", 0x18: "channel", 0x19: "bundle_marker"}

const maxInlineMetadataBytes = 4096

func metadataText(body []byte) (string, bool) {
	truncated := len(body) > maxInlineMetadataBytes
	if len(body) > maxInlineMetadataBytes {
		body = body[:maxInlineMetadataBytes]
	}
	s := strings.ToValidUTF8(string(body), "�")
	if len(s) > maxInlineMetadataBytes {
		truncated = true
		s = s[:maxInlineMetadataBytes]
	}
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s, truncated
}

type Section struct {
	Index              int            `json:"index"`
	Type               uint16         `json:"type"`
	TypeHex            string         `json:"type_hex"`
	Label              string         `json:"label"`
	HeaderOffset       int            `json:"header_offset"`
	PayloadOffset      int            `json:"payload_offset"`
	Size               int            `json:"size"`
	SHA256             string         `json:"sha256"`
	File               string         `json:"file"`
	Name               string         `json:"name,omitempty"`
	Version            string         `json:"version,omitempty"`
	VersionChannelByte byte           `json:"version_channel_byte,omitempty"`
	BuildTime          string         `json:"build_time_utc,omitempty"`
	Text               string         `json:"text,omitempty"`
	TextTruncated      bool           `json:"text_truncated,omitempty"`
	ExtractedTo        string         `json:"extracted_to,omitempty"`
	DecodedSize        int            `json:"decoded_size,omitempty"`
	Entries            int            `json:"entries,omitempty"`
	Counts             map[string]int `json:"counts,omitempty"`
}

type Metadata struct {
	Source                   string    `json:"source"`
	Size                     int       `json:"size"`
	SHA256                   string    `json:"sha256"`
	SignatureVerified        bool      `json:"signature_verified"`
	SectionRoundtripVerified bool      `json:"section_roundtrip_verified"`
	Sections                 []Section `json:"sections"`
}

func Inspect(data []byte, source string) (Metadata, error) {
	m := Metadata{Source: filepath.Base(source), Size: len(data), SHA256: digest(data), Sections: []Section{}}
	if len(data) < 8 || !bytes.Equal(data[:4], npkMagic) {
		return m, errors.New("not an NPK: invalid magic/header")
	}
	if uint64(binary.LittleEndian.Uint32(data[4:])) != uint64(len(data)-8) {
		return m, errors.New("NPK declared length does not match input length")
	}
	for off := 8; off < len(data); {
		if len(m.Sections) >= MaxEntries {
			return m, errors.New("too many NPK sections")
		}
		if len(data)-off < 6 {
			return m, fmt.Errorf("truncated section header at %d", off)
		}
		kind := binary.LittleEndian.Uint16(data[off:])
		size := uint64(binary.LittleEndian.Uint32(data[off+2:]))
		if size > uint64(len(data)-off-6) {
			return m, fmt.Errorf("section at %d exceeds NPK length", off)
		}
		body := data[off+6 : off+6+int(size)]
		label, ok := labels[kind]
		if !ok {
			label = "unknown"
		}
		ext := ".bin"
		if kind == 0x15 {
			ext = ".squashfs"
		}
		s := Section{Index: len(m.Sections), Type: kind, TypeHex: fmt.Sprintf("0x%02x", kind), Label: label, HeaderOffset: off, PayloadOffset: off + 6, Size: len(body), SHA256: digest(body)}
		s.File = fmt.Sprintf("sections/%02d-0x%02x-%s%s", s.Index, kind, label, ext)
		if (kind == 1 || kind == 0x12) && len(body) >= 24 {
			s.Name = cstring(body[:16])
			s.Version = fmt.Sprintf("%d.%d.%d", body[19], body[18], body[16])
			s.VersionChannelByte = body[17]
			s.BuildTime = utc(binary.LittleEndian.Uint32(body[20:]))
		}
		switch kind {
		case 2, 7, 8, 0x10, 0x17, 0x18:
			s.Text, s.TextTruncated = metadataText(body)
		}
		m.Sections = append(m.Sections, s)
		off += 6 + len(body)
	}
	return m, nil
}

func decodeFiles(payload []byte, opt Options) ([]byte, []Entry, error) {
	r := bytes.NewReader(payload)
	z, e := zlib.NewReader(r)
	if e != nil {
		return nil, nil, e
	}
	raw, e := bounded(z, opt.limit())
	ce := z.Close()
	if e = errors.Join(e, ce); e != nil {
		return nil, nil, e
	}
	if r.Len() != 0 {
		return nil, nil, errors.New("unexpected data after zlib file container")
	}
	entries := []Entry{}
	variants := map[string]map[string]bool{}
	for off := 0; off < len(raw); {
		if len(entries) >= MaxEntries {
			return nil, nil, errors.New("too many file container records")
		}
		if len(raw)-off < 30 {
			return nil, nil, errors.New("truncated NPK file header")
		}
		h := raw[off : off+30]
		size := uint64(binary.LittleEndian.Uint32(h[24:]))
		ns := int(binary.LittleEndian.Uint16(h[28:]))
		start := off + 30 + ns
		if start > len(raw) || size > uint64(len(raw)-start) {
			return nil, nil, errors.New("NPK file exceeds container bounds")
		}
		mode := uint32(binary.LittleEndian.Uint16(h))
		body := raw[start : start+int(size)]
		item := Entry{Path: string(raw[off+30 : start]), Mode: octal(mode), Size: int64(size), Mtime: utc(binary.LittleEndian.Uint32(h[8:])), HeaderHex: hex.EncodeToString(h), SHA256: digest(body), data: body}
		if err := safePath(item.Path); err != nil {
			return nil, nil, err
		}
		// PPC packages contain several boot/kernel records selected by the four
		// bytes at header[20:24]. Preserve each variant without overwriting one.
		tag := hex.EncodeToString(h[20:24])
		item.VariantTag = tag
		if seen, ok := variants[item.Path]; ok {
			if seen[tag] {
				return nil, nil, fmt.Errorf("duplicate NPK path and variant tag: %s (%s)", item.Path, tag)
			}
			seen[tag] = true
			item.ArchivePath = item.Path
			item.Path += ".__variant_" + tag
		} else {
			variants[item.Path] = map[string]bool{tag: true}
		}
		switch mode & 0170000 {
		case 0040000:
			item.Type = "directory"
		case 0100000:
			item.Type = "file"
		case 0120000:
			if len(body) > maxInlineMetadataBytes {
				return nil, nil, fmt.Errorf("NPK symlink %q target exceeds %d bytes", item.Path, maxInlineMetadataBytes)
			}
			if bytes.IndexByte(body, 0) >= 0 {
				return nil, nil, fmt.Errorf("NPK symlink %q target contains NUL", item.Path)
			}
			item.Type = "symlink"
			item.Target = string(body)
		default:
			item.Type = "special_metadata_only"
			if len(body) <= maxInlineMetadataBytes {
				item.PayloadHex = hex.EncodeToString(body)
			}
		}
		entries = append(entries, item)
		off = start + int(size)
	}
	entries, e = planPaths(entries)
	return raw, entries, e
}

// Extract creates one new output directory, preserves all sections, and by
// default also extracts the filesystem and every supported nested payload.
func Extract(source, destination string, opt Options) (Metadata, error) {
	data, e := ReadInput(source, opt)
	if e != nil {
		return Metadata{}, e
	}
	m, e := Inspect(data, source)
	if e != nil {
		return m, e
	}
	d, e := newDisk(destination)
	if e != nil {
		return m, e
	}
	defer d.Close()
	counts := map[uint16]int{}
	for i := range m.Sections {
		s := &m.Sections[i]
		body := data[s.PayloadOffset : s.PayloadOffset+s.Size]
		counts[s.Type]++
		if e = d.put(s.File, body); e != nil {
			return m, e
		}
		if opt.SectionsOnly {
			continue
		}
		switch s.Type {
		case 4:
			folder := folderName("files", counts[s.Type])
			raw, entries, err := decodeFiles(body, opt)
			if err != nil {
				return m, fmt.Errorf("section %d file container: %w", i, err)
			}
			if e = writeEntries(d, folder, entries, opt.NoSymlinks); e != nil {
				return m, e
			}
			if e = d.put(folder+"-container.decoded", raw); e != nil {
				return m, e
			}
			if e = d.json(folder+"-manifest.json", entries); e != nil {
				return m, e
			}
			s.ExtractedTo = folder
			s.DecodedSize = len(raw)
			s.Entries = len(entries)
		case 0x15:
			folder := folderName("rootfs", counts[s.Type])
			entries, err := unpackSquashFS(body, d, folder, opt)
			if err != nil {
				return m, fmt.Errorf("section %d SquashFS: %w", i, err)
			}
			s.ExtractedTo = folder
			s.Entries = len(entries)
			s.Counts = map[string]int{}
			for _, v := range entries {
				s.Counts[v.Type]++
			}
		}
	}
	// Re-read exported sections and reconstruct the original hash, including TLVs.
	if e = verifySections(d, m); e != nil {
		return m, e
	}
	m.SectionRoundtripVerified = true
	if e = d.json("metadata.json", m); e != nil {
		return m, e
	}
	if !opt.SectionsOnly && !opt.NoDerived {
		if _, e = analyze(d, m, opt); e != nil {
			return m, e
		}
	}
	if e = writeIntegrity(d); e != nil {
		return m, e
	}
	return m, nil
}
