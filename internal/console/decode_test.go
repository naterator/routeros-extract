// SPDX-License-Identifier: BSD-3-Clause
package console

import (
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"github.com/naterator/routeros-extract/internal/testutil"
	"slices"
	"strings"
	"testing"
)

// The fixture contains no MikroTik code or data. Its tiny ELF supplies only
// return-zero/return-this stubs, exercising vtable recognition independently
// from any specific RouterOS release.
func fixture(t testing.TB) ([]byte, *Parser) { return fixtureABI(t, elf.EM_ARM, binary.LittleEndian) }

func fixtureABI(t testing.TB, machine elf.Machine, order binary.ByteOrder) ([]byte, *Parser) {
	t.Helper()
	data, raw := testutil.ConsoleFixture(t, machine, order)
	p, err := NewParser(raw)
	if err != nil {
		t.Fatal(err)
	}
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
	if _, err = NewParser(p.data); err != nil {
		t.Fatalf("new compatible parser rejected: %v", err)
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
	if base, err := BaseName("4294963200.mem"); err != nil || base != 0xfffff000 {
		t.Fatalf("maximum aligned base=%#x error=%v", base, err)
	}
}

func TestPrintableEncodingsAndControls(t *testing.T) {
	cases := []struct {
		name     string
		input    []byte
		text     string
		encoding string
		ok       bool
	}{
		{"ascii", []byte("hello"), "hello", "ascii", true},
		{"utf8", []byte("hello\xc2\xa0world"), "hello\u00a0world", "utf-8", true},
		{"latin1", []byte{0xff}, "\u00ff", "latin-1", true},
		{"line controls", []byte("a\t\r\nb"), "a\t\r\nb", "ascii", true},
		{"nul", []byte{'a', 0}, "", "", false},
		{"invalid utf8 control", []byte{0xc2, 0x01}, "", "", false},
		{"other space", []byte("a\xe2\x80\x87b"), "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text, encoding, ok := printable(tc.input)
			if text != tc.text || encoding != tc.encoding || ok != tc.ok {
				t.Fatalf("printable(%q) = (%q, %q, %v), want (%q, %q, %v)", tc.input, text, encoding, ok, tc.text, tc.encoding, tc.ok)
			}
		})
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
