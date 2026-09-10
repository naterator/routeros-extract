// SPDX-License-Identifier: BSD-3-Clause
package console

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestPortableConsoleABIs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		machine elf.Machine
		order   binary.ByteOrder
	}{
		{"arm", elf.EM_ARM, binary.LittleEndian}, {"i386", elf.EM_386, binary.LittleEndian},
		{"mips-le", elf.EM_MIPS, binary.LittleEndian}, {"mips-be", elf.EM_MIPS, binary.BigEndian},
		{"ppc", elf.EM_PPC, binary.BigEndian}, {"tilegx", elf.EM_TILEGX, binary.LittleEndian},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, p := fixtureABI(t, tc.machine, tc.order)
			// Neither a new binary hash nor a new module compatibility word requires
			// a release-specific entry in the decoder.
			raw := append(slices.Clone(p.data), []byte("different build")...)
			fresh, err := NewParser(raw)
			if err != nil {
				t.Fatal(err)
			}
			if fresh.SHA256 == p.SHA256 {
				t.Fatal("fixture did not change the binary hash")
			}
			tc.order.PutUint32(data, 0x12345678)
			got, err := Decode(data, 0x40000000, fresh, "fixture")
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Nodes) != 5 || got.Metadata.Compatibility != 0x12345678 {
				t.Fatalf("unexpected metadata: %+v", got.Metadata)
			}
			wantOrder := "little"
			if tc.order == binary.BigEndian {
				wantOrder = "big"
			}
			if got.Metadata.ByteOrder != wantOrder {
				t.Fatal(got.Metadata.ByteOrder)
			}
			command := got.Nodes[1]
			if command.OptionalOffset != 0x28 || command.Optional0400 == nil || *command.Optional0400 != 0xcafebeef || command.Summary == nil || *command.Summary != "Short help" {
				t.Fatalf("packed flags or help were misread: %+v", command)
			}
			if !slices.Equal(command.Paths, []string{"/items/show", "/show"}) || len(got.Nodes[3].Properties) != 1 || got.Nodes[3].PropertyVectorOffset != 0x60 {
				t.Fatalf("wrong graph: %+v", got.Nodes)
			}
		})
	}
}

func TestRelocatedConsoleVtables(t *testing.T) {
	data, p := fixture(t)
	raw := slices.Clone(p.data)
	const delta = 0x30000
	binary.LittleEndian.PutUint32(raw[0x800+40+12:], 0x10000+delta)
	binary.LittleEndian.PutUint32(raw[0x800+80+12:], 0x20000+delta)
	for i := 0; i < 5; i++ {
		for slot := 0; slot < 21; slot++ {
			o := 0x208 + i*0x100 + slot*4
			binary.LittleEndian.PutUint32(raw[o:], binary.LittleEndian.Uint32(raw[o:])+delta)
		}
	}
	for _, o := range []int{0x100, 0x140, 0x180, 0x1a0, 0x240} {
		binary.LittleEndian.PutUint32(data[o:], binary.LittleEndian.Uint32(data[o:])+delta)
	}
	relocated, err := NewParser(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(data, 0x40000000, relocated, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Nodes) != 5 || got.Nodes[0].Vtable != 0x50008 {
		t.Fatal("relocation lost nodes")
	}
	if _, err = Decode(data, 0x40000000, p, "fixture"); err == nil {
		t.Fatal("accepted the unrelated parser")
	}
}

func TestUnsupportedAccessorIsNotGuessed(t *testing.T) {
	data, p := fixture(t)
	raw := slices.Clone(p.data)
	binary.LittleEndian.PutUint32(raw[0x108:], 0xe0800001) // add r0, r0, r1
	p, err := NewParser(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Decode(data, 0x40000000, p, "fixture"); !errors.Is(err, ErrUnsupportedParser) {
		t.Fatalf("unknown accessor: %v", err)
	}
}

func TestPropertyLayoutsAndAmbiguity(t *testing.T) {
	for _, field := range []int{0x60, 0x68} {
		t.Run(Address(field).String(), func(t *testing.T) {
			data, p := fixture(t)
			pair := slices.Clone(data[0x200:0x208])
			clear(data[0x200:0x208])
			copy(data[0x1a0+field:], pair)
			got, err := Decode(data, 0x40000000, p, "fixture")
			if err != nil {
				t.Fatal(err)
			}
			if got.Nodes[3].PropertyVectorOffset != Address(field) || len(got.Nodes[3].Properties) != 1 {
				t.Fatal("lost moved property vector")
			}
		})
	}
	data, p := fixture(t)
	copy(data[0x208:0x210], data[0x200:0x208])
	if _, err := Decode(data, 0x40000000, p, "fixture"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous property vector accepted: %v", err)
	}
	data, p = fixture(t)
	binary.LittleEndian.PutUint32(data[0x200:], 0xffffffff)
	if _, err := Decode(data, 0x40000000, p, "fixture"); err == nil {
		t.Fatal("malformed vector became an empty property list")
	}
}

func TestOlderFlagAndHeaderLayouts(t *testing.T) {
	for _, layout := range []string{"legacy", "shifted", "compact"} {
		t.Run(layout, func(t *testing.T) {
			data, p := fixture(t)
			raw := slices.Clone(p.data)
			stringField := 0x38
			optional, summary, description := byte(4), byte(16), byte(32)
			if layout == "legacy" {
				stringField = 0x28
				summary, description = 8, 16
				copy(data[0x10:0x14], data[0x1c:0x20])
				clear(data[0x1c:0x20])
			}
			if layout == "compact" {
				optional, summary, description = 2, 4, 8
			}
			triplet := slices.Clone(data[0x3c:0x48])
			clear(data[0x3c:0x48])
			copy(data[stringField:], triplet)
			for _, offset := range []int{0x100, 0x140, 0x180, 0x1a0, 0x240} {
				old := data[offset+5]
				flags := byte(1)
				if old&4 != 0 {
					flags |= optional
				}
				if old&8 != 0 {
					flags |= summary
				}
				if old&16 != 0 {
					flags |= description
				}
				data[offset+5] = flags
			}
			if layout == "shifted" {
				for i := 0; i < 5; i++ {
					binary.LittleEndian.PutUint32(raw[0x208+i*0x100+20*4:], 0x10008)
				}
			}
			if layout == "legacy" {
				// Earlier tables do not have a dedicated return-this cast.
				binary.LittleEndian.PutUint32(raw[0x508+14*4:], 0x10000)
				binary.LittleEndian.PutUint32(raw[0x508+8*4:], 0x10008)
			}
			tableField := 0x68
			if layout == "legacy" {
				tableField = 0x64
			}
			pair := slices.Clone(data[0x200:0x208])
			clear(data[0x200:0x208])
			copy(data[0x1a0+tableField:], pair)
			if layout != "legacy" {
				copy(data[0x268:0x270], data[0x260:0x268])
				clear(data[0x260:0x268])
			}
			if layout != "compact" {
				value, short, long := binary.LittleEndian.Uint32(data[0x168:]), binary.LittleEndian.Uint32(data[0x16c:]), binary.LittleEndian.Uint32(data[0x170:])
				data[0x145] |= 2
				clear(data[0x168:0x17c])
				data[0x168] = 42
				binary.LittleEndian.PutUint32(data[0x16c:], value)
				at := 0x170
				if layout == "shifted" {
					data[0x145] |= 8
					binary.LittleEndian.PutUint32(data[at:], 1)
					at += 4
				}
				binary.LittleEndian.PutUint32(data[at:], short)
				binary.LittleEndian.PutUint32(data[at+4:], long)
			}
			p, err := NewParser(raw)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Decode(data, 0x40000000, p, "fixture")
			if err != nil {
				t.Fatal(err)
			}
			if layout != "compact" {
				if got.Nodes[1].OptionalByte == nil || *got.Nodes[1].OptionalByte != 42 {
					t.Fatal("lost optional byte")
				}
			}
			if layout == "shifted" {
				if got.Nodes[1].OptionalExtra == nil || *got.Nodes[1].OptionalExtra != 1 {
					t.Fatal("lost extra optional word")
				}
			}
			if !reflect.DeepEqual(got.Metadata.NodeCounts, map[string]int{"menu": 3, "command": 1, "parameter": 1}) || *got.Nodes[1].Summary != "Short help" || *got.Nodes[1].Optional0400 != 0xcafebeef {
				t.Fatalf("wrong decoded legacy graph: %+v", got)
			}
		})
	}
}

func TestAliasPathsAndCycles(t *testing.T) {
	data, p := fixture(t)
	// Supply a sixth, minimal forwarder vtable. No executable is ever run.
	raw := slices.Clone(p.data)
	binary.LittleEndian.PutUint32(raw[0x800+40+20:], 0x100) // larger .text
	for _, slot := range []int{10, 11, 12} {
		o := 0x120 + (slot-10)*16
		for i, w := range []uint32{0xe5900010, 0xe5903000, 0xe5933000 + uint32(slot*4), 0xe12fff13} {
			binary.LittleEndian.PutUint32(raw[o+i*4:], w)
		}
	}
	p, err := NewParser(raw)
	if err != nil {
		t.Fatal(err)
	}
	methods := p.vtables[0x20108]
	for _, slot := range []int{10, 11, 12} {
		methods[slot] = 0x10020 + uint32(slot-10)*16
	}
	p.vtables[0x20508] = methods
	binary.LittleEndian.PutUint32(data[0x140:], 0x20508)
	// Alias called show points to the existing settings menu.
	binary.LittleEndian.PutUint32(data[0x150:], 0x40000240)
	got, err := Decode(data, 0x40000000, p, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if got.Nodes[1].Target == nil || !slices.Contains(got.Nodes[4].Paths, "/show") {
		t.Fatal("alias path not followed")
	}
	binary.LittleEndian.PutUint32(data[0x150:], 0x40000140)
	if _, err = Decode(data, 0x40000000, p, "fixture"); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("alias cycle accepted: %v", err)
	}
}

func FuzzConsoleParser(f *testing.F) {
	_, p := fixture(f)
	f.Add(p.data)
	f.Add([]byte("not ELF"))
	f.Fuzz(func(t *testing.T, data []byte) {
		parser, err := NewParser(data)
		if err == nil && parser == nil {
			t.Fatal("successful parse returned no parser")
		}
	})
}
