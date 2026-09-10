// SPDX-License-Identifier: BSD-3-Clause

// Package testutil contains synthetic fixtures shared by tests.
package testutil

import (
	"debug/elf"
	"encoding/binary"
	"testing"
)

// ConsoleFixture builds a tiny ELF and console graph without vendor data.
func ConsoleFixture(t testing.TB, machine elf.Machine, order binary.ByteOrder) ([]byte, []byte) {
	t.Helper()
	elfBytes := make([]byte, 0x1000)
	copy(elfBytes, []byte{0x7f, 'E', 'L', 'F', 1, 1, 1})
	if order == binary.BigEndian {
		elfBytes[5] = 2
	}
	u16 := func(o int, v uint16) { order.PutUint16(elfBytes[o:], v) }
	u32 := func(o int, v uint32) { order.PutUint32(elfBytes[o:], v) }
	u16(16, 2)
	u16(18, uint16(machine))
	u32(20, 1)
	u32(32, 0x800)
	u16(40, 52)
	u16(46, 40)
	u16(48, 4)
	u16(50, 3)
	switch machine {
	case elf.EM_ARM:
		u32(0x100, 0xe3a00000)
		u32(0x104, 0xe12fff1e)
		u32(0x108, 0xe12fff1e)
	case elf.EM_MIPS:
		u32(0x100, 0x03e00008)
		u32(0x104, 0x00001025)
		u32(0x108, 0x03e00008)
		u32(0x10c, 0x00801025)
	case elf.EM_PPC:
		u32(0x100, 0x38600000)
		u32(0x104, 0x4e800020)
		u32(0x108, 0x4e800020)
	case elf.EM_386:
		copy(elfBytes[0x100:], []byte{0x31, 0xc0, 0xc3})
		copy(elfBytes[0x108:], []byte{0x55, 0x89, 0xe5, 0x8b, 0x45, 0x08, 0x5d, 0xc3})
	case elf.EM_TILEGX:
		copy(elfBytes[0x100:], []byte{0xc0, 0x0f, 0x10, 0x40, 0xe0, 0x6e, 0x6a, 0x28})
		copy(elfBytes[0x108:], []byte{0x00, 0x30, 0x48, 0x51, 0xe0, 0x6e, 0x6a, 0x28})
	}

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
	data := make([]byte, 0x1000)
	w := func(o int, v uint32) { order.PutUint32(data[o:], v) }
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
		binary.LittleEndian.PutUint32(data[node.o+4:], node.flags)
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
	return data, elfBytes
}
