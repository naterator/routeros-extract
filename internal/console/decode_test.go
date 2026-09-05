// SPDX-License-Identifier: BSD-3-Clause
package console

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

// The fixture contains no MikroTik code or data. Its tiny ELF supplies only
// return-zero/return-this stubs, exercising vtable recognition independently
// from the production SHA256 allowlist.
func fixture(t testing.TB) ([]byte, *Parser) {
	t.Helper()
	elfBytes := make([]byte, 0x1000)
	copy(elfBytes, []byte{0x7f, 'E', 'L', 'F', 1, 1, 1})
	u16 := func(o int, v uint16) { binary.LittleEndian.PutUint16(elfBytes[o:], v) }
	u32 := func(o int, v uint32) { binary.LittleEndian.PutUint32(elfBytes[o:], v) }
	u16(16, 2)
	u16(18, 40)
	u32(20, 1)
	u32(32, 0x800)
	u16(40, 52)
	u16(46, 40)
	u16(48, 4)
	u16(50, 3)
	copy(elfBytes[0x100:], []byte{0, 0, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1, 0x1e, 0xff, 0x2f, 0xe1})
	copy(elfBytes[0x700:], []byte("\x00.text\x00.rodata\x00.shstrtab\x00"))
	for i, s := range [][6]uint32{{1, 1, 6, 0x10000, 0x100, 16}, {7, 1, 2, 0x20000, 0x200, 0x500}, {15, 3, 0, 0, 0x700, 25}} {
		for j, v := range s {
			u32(0x800+(i+1)*40+j*4, v)
		}
	}
	for i := 0; i < 5; i++ {
		start := 0x208 + i*0x100
		for slot := 0; slot < 21; slot++ {
			u32(start+slot*4, 0x10000)
		}
		switch i {
		case 0:
			u32(start+12*4, 0x10008)
		case 1:
			u32(start+11*4, 0x10008)
		case 2:
			u32(start+10*4, 0x10008)
		case 3:
			u32(start+12*4, 0x10008)
			u32(start+14*4, 0x10008)
		case 4:
			u32(start+12*4, 0x10008)
			u32(start+8*4, 0x10008)
		}
	}
	p, err := parseELF(elfBytes, hash(elfBytes), profile{"synthetic", 0x6a994576})
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 0x1000)
	w := func(o int, v uint32) { binary.LittleEndian.PutUint32(data[o:], v) }
	next := 0x600
	text := func(s string) uint32 {
		a := uint32(0x40000000 + next)
		copy(data[next:], s)
		next += len(s) + 1
		return a
	}
	empty, yes, no := text(""), text("yes"), text("no")
	names := map[string]uint32{}
	for _, s := range []string{"root", "show", "value", "items", "settings"} {
		names[s] = text(s)
	}
	short, long := text("Short help"), text("Long\r\nhelp\xa0text")
	w(0, 0x6a994576)
	w(0x1c, 0x40000100)
	w(0x3c, empty)
	w(0x40, yes)
	w(0x44, no)
	for _, node := range []struct {
		o         int
		vt, flags uint32
		name      string
	}{{0x100, 0x20008, 0x1a20, "root"}, {0x140, 0x20108, 0x1e28, "show"}, {0x180, 0x20208, 0xa14, "value"}, {0x1a0, 0x20308, 0x200, "items"}, {0x240, 0x20408, 0x200, "settings"}} {
		w(node.o, node.vt)
		w(node.o+4, node.flags)
		w(node.o+12, names[node.name])
	}
	w(0x110, 0x40000300)
	w(0x114, 12)
	w(0x120, short)
	w(0x124, long)
	w(0x158, 0x40000320)
	w(0x15c, 4)
	w(0x168, 0xcafebeef)
	w(0x16c, short)
	w(0x170, long)
	w(0x194, short)
	w(0x1b0, 0x40000310)
	w(0x1b4, 4)
	w(0x1b8, 0x40000100)
	w(0x200, 0x40000330)
	w(0x204, 8)
	w(0x258, 0x40000100)
	w(0x260, 0x40000340)
	w(0x264, 4)
	w(0x300, 0x40000140)
	w(0x304, 0x400001a0)
	w(0x308, 0x40000240)
	w(0x310, 0x40000140)
	w(0x320, 0x40000180)
	w(0x330, 0x40000180)
	w(0x334, 0xb)
	w(0x340, 0x40000180)
	return data, p
}

func TestDecodeObjectGraphAndText(t *testing.T) {
	data, p := fixture(t)
	got, err := Decode(data, 0x40000000, p, "1073741824.mem")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Nodes) != 5 || got.Metadata.NodeCounts["menu"] != 3 || got.Metadata.NodeCounts["command"] != 1 || got.Metadata.NodeCounts["parameter"] != 1 {
		t.Fatalf("wrong nodes: %+v", got.Metadata)
	}
	command, parameter, table := got.Nodes[1], got.Nodes[2], got.Nodes[3]
	if command.Optional0400 == nil || *command.Optional0400 != 0xcafebeef || command.Summary == nil || *command.Summary != "Short help" || command.Description == nil || *command.Description != "Long\r\nhelp\u00a0text" {
		t.Fatalf("optional fields: %+v", command)
	}
	if !slices.Equal(command.Paths, []string{"/items/show", "/show"}) {
		t.Fatalf("shared command paths: %v", command.Paths)
	}
	want := []string{"/items :: value", "/items/show :: value", "/settings :: value", "/show :: value"}
	if !slices.Equal(parameter.Paths, want) {
		t.Fatalf("property paths: %v", parameter.Paths)
	}
	if table.Properties[0].Flags == nil || *table.Properties[0].Flags != 0xb {
		t.Fatal("lost property flags")
	}
	if !strings.Contains(string(got.StringsTSV()), "\tlatin-1\t") || !strings.Contains(string(got.Commands()), "/items/show [command] — Short help") {
		t.Fatal("missing readable output")
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip Image
	if err = json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if roundTrip.Metadata.Root != 0x40000100 || roundTrip.Nodes[1].Address != command.Address {
		t.Fatal("hex addresses did not round trip")
	}
	if _, err = NewParser(p.data); !errors.Is(err, ErrUnsupportedParser) {
		t.Fatalf("synthetic ELF must not bypass production allowlist: %v", err)
	}
}

func TestDecodeRejectsMalformedImages(t *testing.T) {
	data, p := fixture(t)
	cases := []struct {
		name    string
		offset  int
		value   uint32
		message string
	}{
		{"build", 0, 1, "build word"},
		{"root", 0x1c, 0xffffffff, "root pointer"},
		{"vtable", 0x100, 0, "root vtable"},
		{"name", 0x10c, 0xffffffff, "name string"},
		{"help", 0x120, 0xffffffff, "summary string"},
		{"optional offset", 0x144, 0x1e00, "optional-field"},
		{"misaligned vector", 0x114, 3, "misaligned"},
		{"huge vector", 0x114, 0xfffffffc, "outside"},
		{"bad vector pointer", 0x110, 0xfffffffc, "outside"},
		{"unknown child", 0x300, 0x40000700, "unresolved"},
		{"non-menu parent", 0x1b8, 0x40000180, "parent"},
		{"cycle", 0x300, 0x40000100, "cycle"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := slices.Clone(data)
			binary.LittleEndian.PutUint32(b[tc.offset:], tc.value)
			if _, err := Decode(b, 0x40000000, p, "fixture"); err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("error = %v, want %s", err, tc.message)
			}
		})
	}
	if _, err := Decode(data[:0x50], 0x40000000, p, "fixture"); err == nil {
		t.Fatal("accepted short header")
	}
	if _, err := Decode(append(data, 0), 0xfffff000, p, "fixture"); err == nil {
		t.Fatal("accepted overflowing mapping")
	}
	if _, err := Decode(data, 0x40000000, nil, "fixture"); err == nil {
		t.Fatal("accepted missing parser")
	}
}

func TestConsoleFilenames(t *testing.T) {
	for _, name := range []string{"0.mem", "1.mem", "4294967296.mem", "1073741824 2.mem", "-1.mem", "0x40000000.mem", "file.mem", "1073741824.bin", ".mem"} {
		if _, err := BaseName(name); err == nil {
			t.Errorf("accepted %q", name)
		}
	}
	if base, err := BaseName("1073741824.mem"); err != nil || base != 0x40000000 {
		t.Fatalf("base=%#x error=%v", base, err)
	}
}

func TestConsoleWorkBudgets(t *testing.T) {
	data, _ := fixture(t)
	r := &reader{data: data, base: 0x40000000, nodes: map[uint32]*Node{}, references: maxReferences}
	r.vector(0x110, 4)
	if r.err == nil || !strings.Contains(r.err.Error(), "too many") {
		t.Fatalf("unbounded vector: %v", r.err)
	}
	r = &reader{data: data, base: 0x40000000, cache: map[uint32]*String{}, strings: map[uint32]*String{}}
	r.text(0x40000600, "")
	if r.err == nil || !strings.Contains(r.err.Error(), "work limit") {
		t.Fatalf("unbounded strings: %v", r.err)
	}
	r = &reader{textBytes: maxTextBytes}
	r.chargeText(1)
	if r.err == nil || !strings.Contains(r.err.Error(), "text exceeds") {
		t.Fatalf("unbounded repeated report text: %v", r.err)
	}
}

func FuzzDecode(f *testing.F) {
	data, p := fixture(f)
	f.Add(data)
	f.Add([]byte("not a console image"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		_, _ = Decode(data, 0x40000000, p, "fuzz")
	})
}
