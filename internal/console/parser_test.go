// SPDX-License-Identifier: BSD-3-Clause
package console

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func TestNewParserRejectsUnknownAndOversizedInputs(t *testing.T) {
	if _, err := NewParser([]byte("not an ELF parser")); !errors.Is(err, ErrUnsupportedParser) {
		t.Fatalf("unknown parser error = %v, want ErrUnsupportedParser", err)
	}
	if _, err := NewParser(make([]byte, MaxInputBytes+1)); err == nil || !strings.Contains(err.Error(), "64 MiB") {
		t.Fatalf("oversized parser error = %v, want size limit", err)
	}
}

func TestParseELFRequiresRouterOSParserABI(t *testing.T) {
	_, parser := fixture(t)
	data := append([]byte(nil), parser.data...)
	cases := []struct {
		name string
		edit func([]byte)
		want string
	}{
		{"class", func(b []byte) { b[4] = 2 }, ""},
		{"byte order", func(b []byte) { b[5] = 2 }, ""},
		{"machine", func(b []byte) { binary.LittleEndian.PutUint16(b[18:], 62) }, "unsupported console parser ABI"},
		{"type", func(b []byte) { binary.LittleEndian.PutUint16(b[16:], 3) }, "unsupported console parser ABI"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := append([]byte(nil), data...)
			tc.edit(b)
			if _, err := NewParser(b); err == nil || (tc.want != "" && !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("parseELF error = %v, want rejection containing %q", err, tc.want)
			}
		})
	}
}

func TestParserReadHonorsSectionBounds(t *testing.T) {
	_, p := fixture(t)
	section := p.elf.Section(".text")
	if section == nil {
		t.Fatal("synthetic parser has no .text section")
	}
	if got, err := p.read(section.Addr, section.Size); err != nil || len(got) != int(section.Size) {
		t.Fatalf("read exact section = (%d, %v), want %d bytes", len(got), err, section.Size)
	}
	if _, err := p.read(section.Addr+section.Size, 1); err == nil {
		t.Fatal("read accepted address immediately beyond section")
	}
	if _, err := p.read(^uint64(0), 1); err == nil {
		t.Fatal("read accepted overflowing address")
	}
}

func TestNodeClassesRejectsUnknownRootVtable(t *testing.T) {
	_, p := fixture(t)
	if _, err := p.nodeClasses(0xdeadbeef); err == nil || !strings.Contains(err.Error(), "root vtable") {
		t.Fatalf("nodeClasses error = %v, want missing-root-vtable error", err)
	}
}

func TestELFPreflightRejectsExpandingMetadata(t *testing.T) {
	_, p := fixture(t)
	for _, tc := range []struct {
		name   string
		offset int
		value  uint32
	}{
		{"oversized string table", 0x800 + 3*40 + 20, 0xffffffff},
		{"compressed string table", 0x800 + 3*40 + 8, 0x800},
		{"oversized section table", 32, 0xfffffffc},
		{"extended section count", 48, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := append([]byte(nil), p.data...)
			binary.LittleEndian.PutUint32(b[tc.offset:], tc.value)
			if _, err := NewParser(b); !errors.Is(err, ErrUnsupportedParser) {
				t.Fatalf("unchecked ELF metadata: %v", err)
			}
		})
	}
}
