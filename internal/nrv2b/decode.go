// SPDX-License-Identifier: MIT
// Copyright (c) 2017 Avast Software
//
// Adapted from RetDec's Nrv2bData::decompress and BitParserLe32, under MIT.
// Source revision, license and changes: README.md in this directory.

// Package nrv2b decodes NRV2B streams with little-endian 32-bit control words.
package nrv2b

import (
	"encoding/binary"
	"errors"
	"io"
)

var (
	ErrLimit  = errors.New("nrv2b: output limit exceeded")
	ErrOffset = errors.New("nrv2b: invalid match distance")
	ErrCode   = errors.New("nrv2b: integer code overflow")
)

type input struct {
	data    []byte
	pos     int
	control uint32
}

func (in *input) byte() (uint32, error) {
	if in.pos == len(in.data) {
		return 0, io.ErrUnexpectedEOF
	}
	b := in.data[in.pos]
	in.pos++
	return uint32(b), nil
}

// RetDec's bit parser keeps a sentinel below the remaining bits. The sentinel
// reaches the high bit after the last data bit and shifts out on the next read.
func (in *input) bit() (uint32, error) {
	bit := in.control >> 31
	in.control <<= 1
	if in.control == 0 {
		if len(in.data)-in.pos < 4 {
			return 0, io.ErrUnexpectedEOF
		}
		word := binary.LittleEndian.Uint32(in.data[in.pos:])
		in.pos += 4
		bit = word >> 31
		in.control = word<<1 | 1
	}
	return bit, nil
}

// integer reads the interleaved data/stop bits used for distances and long
// match lengths. The bound prevents wraparound on malformed input.
func (in *input) integer(bound uint32) (uint32, error) {
	value := uint64(1)
	for {
		bit, err := in.bit()
		if err != nil {
			return 0, err
		}
		value = value*2 + uint64(bit)
		if value > uint64(bound) {
			return 0, ErrCode
		}
		stop, err := in.bit()
		if err != nil {
			return 0, err
		}
		if stop != 0 {
			return uint32(value), nil
		}
	}
}

// Decode returns the decoded bytes and the number of source bytes consumed
// through the end marker. Trailing envelope padding is left to the caller.
// At most limit output bytes are allocated; negative limits are invalid.
func Decode(src []byte, limit int) ([]byte, int, error) {
	if limit < 0 || uint64(limit) > uint64(^uint32(0)) {
		return nil, 0, ErrLimit
	}
	in := input{data: src}
	out := make([]byte, limit)
	written := 0
	lastDistance := uint32(1)
	for {
		literal, err := in.bit()
		if err != nil {
			return nil, in.pos, err
		}
		for literal == 1 {
			if written == len(out) {
				return nil, in.pos, ErrLimit
			}
			b, err := in.byte()
			if err != nil {
				return nil, in.pos, err
			}
			out[written] = byte(b)
			written++
			literal, err = in.bit()
			if err != nil {
				return nil, in.pos, err
			}
		}

		distance, err := in.integer(0x01000002)
		if err != nil {
			return nil, in.pos, err
		}
		if distance == 2 {
			distance = lastDistance
		} else {
			low, err := in.byte()
			if err != nil {
				return nil, in.pos, err
			}
			encoded := uint64(distance-3)<<8 | uint64(low)
			if encoded == 0xffffffff {
				return out[:written], in.pos, nil
			}
			if encoded >= 0xffffffff {
				return nil, in.pos, ErrOffset
			}
			distance = uint32(encoded) + 1
			lastDistance = distance
		}

		hi, err := in.bit()
		if err != nil {
			return nil, in.pos, err
		}
		lo, err := in.bit()
		if err != nil {
			return nil, in.pos, err
		}
		count := uint64(hi<<1 | lo)
		if count == 0 {
			long, err := in.integer(uint32(limit))
			if err != nil {
				return nil, in.pos, err
			}
			count = uint64(long) + 2
		}
		count++
		if distance > 0xd00 {
			count++
		}
		if distance == 0 || uint64(distance) > uint64(written) {
			return nil, in.pos, ErrOffset
		}
		if count > uint64(len(out)-written) {
			return nil, in.pos, ErrLimit
		}

		// Copy forward one byte at a time so an overlapping match repeats the
		// newly written bytes, including a match at distance one.
		from := written - int(distance)
		for range int(count) {
			out[written] = out[from]
			written++
			from++
		}
	}
}
