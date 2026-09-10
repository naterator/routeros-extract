// SPDX-License-Identifier: BSD-3-Clause

// Package console reads fixed-address RouterOS console object images.
// It never maps or executes RouterOS code.
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

var ErrUnsupportedParser = errors.New("unsupported console parser ABI")

type Parser struct {
	SHA256  string
	Profile string
	data    []byte
	elf     *elf.File
	order   binary.ByteOrder
	vtables map[uint32][21]uint32
}

type nodeClass struct{ kind, layout string }

func hash(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }

// NewParser recognizes an executable's ABI and C++ vtables, rather than a
// release number or an exact binary hash. Decode validates the image's root
// against that executable before interpreting the object graph.
func NewParser(data []byte) (*Parser, error) {
	if len(data) > MaxInputBytes {
		return nil, errors.New("console parser exceeds 64 MiB limit")
	}
	return parseELF(data, hash(data))
}

func parseELF(data []byte, hash string) (*Parser, error) {
	if err := checkELFBounds(data); err != nil {
		return nil, err
	}
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%w: ELF: %w", ErrUnsupportedParser, err)
	}
	if len(f.Sections) > 1024 {
		return nil, errors.New("too many console parser ELF sections")
	}
	if f.Class != elf.ELFCLASS32 || f.Type != elf.ET_EXEC {
		return nil, fmt.Errorf("%w: requires a 32-bit ELF executable", ErrUnsupportedParser)
	}
	var arch string
	switch {
	case f.Machine == elf.EM_ARM && f.Data == elf.ELFDATA2LSB:
		arch = "arm"
	case f.Machine == elf.EM_386 && f.Data == elf.ELFDATA2LSB:
		arch = "i386"
	case f.Machine == elf.EM_MIPS:
		arch = "mips"
	case f.Machine == elf.EM_PPC && f.Data == elf.ELFDATA2MSB:
		arch = "ppc"
	case f.Machine == elf.EM_TILEGX && f.Data == elf.ELFDATA2LSB:
		arch = "tilegx"
	default:
		return nil, fmt.Errorf("%w: %s/%s", ErrUnsupportedParser, f.Machine, f.Data)
	}
	endian := "le"
	if f.Data == elf.ELFDATA2MSB {
		endian = "be"
	}
	p := &Parser{SHA256: hash, Profile: "console32/" + arch + "-" + endian, data: data, elf: f, order: f.ByteOrder, vtables: map[uint32][21]uint32{}}
	ro := f.Section(".rodata")
	if ro == nil {
		return nil, errors.New("console parser has no .rodata section")
	}
	raw, err := p.read(ro.Addr, ro.Size)
	if err != nil {
		return nil, err
	}
	for offset := 8; offset+84 <= len(raw); offset += 4 {
		// The observed non-RTTI vtables have zero offset-to-top and typeinfo.
		if p.order.Uint64(raw[offset-8:]) != 0 {
			continue
		}
		var methods [21]uint32
		valid := true
		for i := range methods {
			methods[i] = p.order.Uint32(raw[offset+4*i:])
			if i < 4 && !p.executable(uint64(methods[i])) {
				valid = false
				break
			}
		}
		if valid && ro.Addr+uint64(offset) < 1<<32 {
			if len(p.vtables) >= 16384 {
				return nil, errors.New("too many console parser vtables")
			}
			p.vtables[uint32(ro.Addr+uint64(offset))] = methods
		}
	}
	if len(p.vtables) == 0 {
		return nil, fmt.Errorf("%w: no console vtable candidates", ErrUnsupportedParser)
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

type accessor uint8

const (
	accessorUnknown accessor = iota
	accessorThis
	accessorZero
	accessorVoid
)

// These are complete trivial accessors, not instruction emulation. Recognize
// only checked encodings; an unfamiliar compiler sequence remains unknown.
func (p *Parser) accessor(address uint32) accessor {
	if !p.executable(uint64(address)) {
		return accessorUnknown
	}
	match := func(want []byte) bool {
		b, err := p.read(uint64(address), uint64(len(want)))
		return err == nil && bytes.Equal(b, want)
	}
	words := func(values ...uint32) []byte {
		b := make([]byte, 4*len(values))
		for i, v := range values {
			p.order.PutUint32(b[i*4:], v)
		}
		return b
	}
	var this, zero []byte
	switch p.elf.Machine {
	case elf.EM_ARM:
		this, zero = words(0xe12fff1e), words(0xe3a00000, 0xe12fff1e)
	case elf.EM_MIPS:
		this, zero = words(0x03e00008, 0x00801025), words(0x03e00008, 0x00001025)
	case elf.EM_PPC:
		this, zero = words(0x4e800020), words(0x38600000, 0x4e800020)
	case elf.EM_386:
		this, zero = []byte{0x55, 0x89, 0xe5, 0x8b, 0x45, 0x08, 0x5d, 0xc3}, []byte{0x31, 0xc0, 0xc3}
	case elf.EM_TILEGX:
		// One eight-byte bundle: return r0 unchanged or set r0 to zero.
		this, zero = []byte{0x00, 0x30, 0x48, 0x51, 0xe0, 0x6e, 0x6a, 0x28}, []byte{0xc0, 0x0f, 0x10, 0x40, 0xe0, 0x6e, 0x6a, 0x28}
	}
	if p.elf.Machine == elf.EM_386 && match([]byte{0xc3}) {
		return accessorVoid
	}
	if p.elf.Machine == elf.EM_MIPS && match(words(0x03e00008, 0)) {
		return accessorVoid
	}
	if len(this) > 0 && match(this) {
		return accessorThis
	}
	if len(zero) > 0 && match(zero) {
		return accessorZero
	}
	return accessorUnknown
}

func (p *Parser) nodeClasses(root uint32) (map[uint32]nodeClass, error) {
	rootMethods, ok := p.vtables[root]
	if !ok {
		return nil, errors.New("root vtable is absent from the matching parser")
	}
	if p.accessor(rootMethods[12]) != accessorThis || p.accessor(rootMethods[10]) != accessorZero || p.accessor(rootMethods[11]) != accessorZero || p.accessor(rootMethods[8]) != accessorZero {
		return nil, fmt.Errorf("%w: unrecognized root menu accessors", ErrUnsupportedParser)
	}
	classes := map[uint32]nodeClass{}
	for address, methods := range p.vtables {
		// Slot 9 is inherited by the console node family.
		if p.forwarder(methods[10], 10) && p.forwarder(methods[11], 11) && p.forwarder(methods[12], 12) {
			classes[address] = nodeClass{"alias", "alias"}
			continue
		}
		if methods[9] != rootMethods[9] {
			continue
		}
		returnsThis := func(slot int) bool { return p.accessor(methods[slot]) == accessorThis }
		returnsZero := func(slot int) bool { return p.accessor(methods[slot]) == accessorZero }
		c := nodeClass{"other", "unknown"}
		switch {
		case returnsThis(12) && returnsZero(10) && returnsZero(11):
			c = nodeClass{"menu", "directory"}
			if returnsThis(13) || returnsThis(14) {
				c.layout = "item-table"
			} else if p.accessor(methods[8]) != accessorZero {
				c.layout = "settings"
			}
		case returnsThis(11) && returnsZero(10) && returnsZero(12):
			c = nodeClass{"command", "command"}
		case returnsThis(10) && returnsZero(11) && returnsZero(12):
			c = nodeClass{"parameter", "parameter"}
		}
		if c.kind == "other" {
			continue
		}
		classes[address] = c
	}
	return classes, nil
}

// Older console aliases forward virtual calls through the object at +0x10.
func (p *Parser) forwarder(address uint32, slot uint32) bool {
	var want []byte
	words := func(values ...uint32) []byte {
		b := make([]byte, 4*len(values))
		for i, v := range values {
			p.order.PutUint32(b[i*4:], v)
		}
		return b
	}
	switch p.elf.Machine {
	case elf.EM_ARM:
		for _, v := range []uint32{0xe5900010, 0xe5903000, 0xe5933000 + slot*4, 0xe12fff13} {
			var b [4]byte
			p.order.PutUint32(b[:], v)
			want = append(want, b[:]...)
		}
	case elf.EM_MIPS:
		want = words(0x8c840010, 0x8c820000, 0x8c590000+slot*4, 0x03200008, 0)
	case elf.EM_PPC:
		want = words(0x80630010, 0x81230000, 0x81290000+slot*4, 0x7d2903a6, 0x4e800420)
	case elf.EM_386:
		want = []byte{0x55, 0x89, 0xe5, 0x8b, 0x45, 0x08, 0x8b, 0x40, 0x10, 0x8b, 0x10, 0x89, 0x45, 0x08, 0x5d, 0x8b, 0x42, byte(slot * 4), 0xff, 0xe0}
	default:
		return false
	}
	b, err := p.read(uint64(address), uint64(len(want)))
	return err == nil && p.executable(uint64(address)) && bytes.Equal(b, want)
}

// Bound the header tables and section-name data before debug/elf reads them.
// In particular, NewFile decompresses a compressed section-name table itself.
func checkELFBounds(data []byte) error {
	bad := func(reason string) error { return fmt.Errorf("%w: %s", ErrUnsupportedParser, reason) }
	if len(data) < 52 || !bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}) || data[4] != byte(elf.ELFCLASS32) {
		return bad("requires a 32-bit ELF executable")
	}
	var order binary.ByteOrder
	switch elf.Data(data[5]) {
	case elf.ELFDATA2LSB:
		order = binary.LittleEndian
	case elf.ELFDATA2MSB:
		order = binary.BigEndian
	default:
		return bad("invalid ELF byte order")
	}
	shoff := uint64(order.Uint32(data[32:]))
	shentsize := uint64(order.Uint16(data[46:]))
	shnum := uint64(order.Uint16(data[48:]))
	if shnum == 0 || shnum > 1024 || shentsize < 40 || shoff > uint64(len(data)) || shnum*shentsize > uint64(len(data))-shoff {
		return bad("invalid or excessive ELF section table")
	}
	phoff := uint64(order.Uint32(data[28:]))
	phentsize := uint64(order.Uint16(data[42:]))
	phnum := uint64(order.Uint16(data[44:]))
	if phnum > 1024 || (phnum > 0 && (phentsize < 32 || phoff > uint64(len(data)) || phnum*phentsize > uint64(len(data))-phoff)) {
		return bad("invalid or excessive ELF program table")
	}
	for i := uint64(0); i < shnum; i++ {
		s := data[shoff+i*shentsize:]
		kind := elf.SectionType(order.Uint32(s[4:]))
		flags := elf.SectionFlag(order.Uint32(s[8:]))
		if flags&elf.SHF_COMPRESSED != 0 {
			return bad("compressed parser ELF sections are not supported")
		}
		offset, size := uint64(order.Uint32(s[16:])), uint64(order.Uint32(s[20:]))
		if kind != elf.SHT_NOBITS && (offset > uint64(len(data)) || size > uint64(len(data))-offset) {
			return bad("ELF section extends outside the input")
		}
	}
	return nil
}
