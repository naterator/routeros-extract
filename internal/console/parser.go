// SPDX-License-Identifier: BSD-3-Clause

// Package console reads the fixed-address console object images in the
// examined RouterOS builds. It never maps or executes RouterOS code.
package console

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
)

const MaxInputBytes = 64 << 20

var ErrUnsupportedParser = errors.New("unsupported console parser build")

type profile struct {
	name  string
	stamp uint32
}

// Layouts and accessor semantics were checked against these exact binaries.
// A version string or ELF architecture alone cannot establish compatibility.
var profiles = map[string]profile{
	"d6ecbb1b0c0dbe3e96ccf1fb0ed617a5cfaef4f2697f67ee7436019203045156": {"7.24.1-arm64", 0x6a884e5a},
	"4e84fcf7a7e450f4633e4857273c0b465ddf4c59c9fc5c04b4492fb59b3ab8f8": {"7.24.2-arm64", 0x6a994576},
}

type Parser struct {
	SHA256  string
	Profile string
	stamp   uint32
	data    []byte
	elf     *elf.File
	vtables map[uint32][21]uint32
}

type nodeClass struct{ kind, layout string }

func hash(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }

func NewParser(data []byte) (*Parser, error) {
	if len(data) > MaxInputBytes {
		return nil, errors.New("console parser exceeds 64 MiB limit")
	}
	h := hash(data)
	profile, ok := profiles[h]
	if !ok {
		return nil, fmt.Errorf("%w (SHA256 %s); supported profiles: 7.24.1-arm64, 7.24.2-arm64", ErrUnsupportedParser, h)
	}
	return parseELF(data, h, profile)
}

func parseELF(data []byte, hash string, profile profile) (*Parser, error) {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("console parser ELF: %w", err)
	}
	if f.Class != elf.ELFCLASS32 || f.Data != elf.ELFDATA2LSB || f.Machine != elf.EM_ARM || f.Type != elf.ET_EXEC {
		return nil, errors.New("console layout requires a little-endian ARM32 executable")
	}
	p := &Parser{SHA256: hash, Profile: profile.name, stamp: profile.stamp, data: data, elf: f, vtables: map[uint32][21]uint32{}}
	ro := f.Section(".rodata")
	if ro == nil {
		return nil, errors.New("console parser has no .rodata section")
	}
	raw, err := p.read(ro.Addr, ro.Size)
	if err != nil {
		return nil, err
	}
	for offset := 8; offset+84 <= len(raw); offset += 4 {
		if binary.LittleEndian.Uint64(raw[offset-8:]) != 0 {
			continue
		}
		var methods [21]uint32
		valid := true
		for i := range methods {
			methods[i] = binary.LittleEndian.Uint32(raw[offset+4*i:])
			if i < 4 && !p.executable(uint64(methods[i])) {
				valid = false
			}
		}
		if valid && ro.Addr+uint64(offset) < 1<<32 {
			p.vtables[uint32(ro.Addr+uint64(offset))] = methods
		}
	}
	return p, nil
}

func (p *Parser) executable(address uint64) bool {
	for _, s := range p.elf.Sections {
		if s.Flags&elf.SHF_EXECINSTR != 0 && address >= s.Addr && address-s.Addr < s.Size {
			return true
		}
	}
	return false
}

func (p *Parser) read(address, size uint64) ([]byte, error) {
	for _, s := range p.elf.Sections {
		if s.Flags&elf.SHF_ALLOC == 0 || s.Type == elf.SHT_NOBITS || address < s.Addr {
			continue
		}
		rel := address - s.Addr
		if rel <= s.Size && size <= s.Size-rel && s.Offset <= uint64(len(p.data)) && rel <= uint64(len(p.data))-s.Offset {
			start := s.Offset + rel
			if size <= uint64(len(p.data))-start {
				return p.data[start : start+size], nil
			}
		}
	}
	return nil, fmt.Errorf("unmapped parser address %#x, length %#x", address, size)
}

func (p *Parser) nodeClasses(root uint32) (map[uint32]nodeClass, error) {
	rootMethods, ok := p.vtables[root]
	if !ok {
		return nil, errors.New("root vtable is absent from the matching parser")
	}
	classes := map[uint32]nodeClass{}
	for address, methods := range p.vtables {
		// Slot 20 is the shared optional-field method in these two builds.
		if methods[20] != rootMethods[20] {
			continue
		}
		returnsThis := func(slot int) bool {
			b, err := p.read(uint64(methods[slot]), 4)
			return err == nil && binary.LittleEndian.Uint32(b) == 0xe12fff1e // bx lr
		}
		c := nodeClass{"other", "unknown"}
		switch {
		case returnsThis(12):
			c = nodeClass{"menu", "directory"}
			if returnsThis(14) {
				c.layout = "item-table"
			} else {
				b, err := p.read(uint64(methods[8]), 8)
				if err != nil {
					return nil, err
				}
				if !bytes.Equal(b, []byte{0, 0, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1}) {
					c.layout = "settings"
				}
			}
		case returnsThis(11):
			c = nodeClass{"command", "command"}
		case returnsThis(10):
			c = nodeClass{"parameter", "parameter"}
		}
		classes[address] = c
	}
	return classes, nil
}
