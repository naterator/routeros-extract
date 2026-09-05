// SPDX-License-Identifier: 0BSD
package xz

// StopAtStreamEnd stops exactly after the first XZ footer, before padding or
// another embedded object. Use Reset with a non-nil reader before reusing it.
// Unlike Multistream(false), this deliberately does not consume stream padding.
func (z *Reader) StopAtStreamEnd() { z.stopAtEnd = true }

// InputConsumed excludes bytes buffered ahead of the decoder's current position.
func (z *Reader) InputConsumed() int64 { return z.consumed }

const idBCJARM64 xzFilterID = 10

// Port of bcj_arm64 from Tukaani XZ Embedded (0BSD), by Lasse Collin and
// Igor Pavlov. All address arithmetic intentionally wraps at 32 bits.
func bcjARM64Filter(s *xzDecBCJ, buf []byte) int {
	i := 0
	for ; i+4 <= len(buf); i += 4 {
		instr := getLE32(buf[i:])
		pc := uint32(s.pos) + uint32(i)
		if instr>>26 == 0x25 {
			addr := instr - (pc >> 2)
			putLE32(0x94000000|(addr&0x03ffffff), buf[i:])
		} else if instr&0x9f000000 == 0x90000000 {
			addr := ((instr >> 29) & 3) | ((instr >> 3) & 0x1ffffc)
			if (addr+0x020000)&0x1c0000 != 0 {
				continue
			}
			addr -= pc >> 12
			instr &= 0x9000001f
			instr |= (addr & 3) << 29
			instr |= (addr & 0x03fffc) << 3
			instr |= (0 - (addr & 0x020000)) & 0xe00000
			putLE32(instr, buf[i:])
		}
	}
	return i
}
