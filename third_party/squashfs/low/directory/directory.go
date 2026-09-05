package directory

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	maxDirectoryEntries = 1 << 20
	maxDirectoryName    = 255
	maxDirectoryCount   = 255 // field is stored one less than the entry count
)

type header struct {
	Count      uint32
	BlockStart uint32
	Num        uint32
}

func readHeader(r io.Reader) (h header, err error) {
	dat := make([]byte, 12)
	_, err = io.ReadFull(r, dat)
	if err != nil {
		return
	}
	h.Count = binary.LittleEndian.Uint32(dat)
	h.BlockStart = binary.LittleEndian.Uint32(dat[4:])
	h.Num = binary.LittleEndian.Uint32(dat[8:])
	return
}

type dirEntry struct {
	Offset    uint16
	NumOffset int16
	InodeType uint16
	NameSize  uint16
	Name      []byte
}

func readEntry(r io.Reader) (e dirEntry, err error) {
	dat := make([]byte, 8)
	_, err = io.ReadFull(r, dat)
	if err != nil {
		return
	}
	e.Offset = binary.LittleEndian.Uint16(dat)
	_, err = binary.Decode(dat[2:], binary.LittleEndian, &e.NumOffset)
	if err != nil {
		return
	}
	e.InodeType = binary.LittleEndian.Uint16(dat[4:])
	e.NameSize = binary.LittleEndian.Uint16(dat[6:])
	if e.NameSize > maxDirectoryName {
		return e, fmt.Errorf("SquashFS directory entry name is too large: %d bytes", e.NameSize)
	}
	e.Name = make([]byte, e.NameSize+1)
	_, err = io.ReadFull(r, e.Name)
	if err != nil {
		return
	}
	return
}

type Entry struct {
	Name       string
	BlockStart uint32
	Offset     uint16
	InodeType  uint16
	Num        uint32
}

func ReadDirectory(r io.Reader, size uint32) (out []Entry, err error) {
	if size < 3 {
		return nil, fmt.Errorf("invalid SquashFS directory size %d", size)
	}
	size -= 3
	// The size stored in the inode includes the synthetic "." and ".."
	// entries. Do not let malformed records consume the next metadata record.
	r = io.LimitReader(r, int64(size))
	var curRead uint32
	var h header
	var de dirEntry
	for curRead < size {
		h, err = readHeader(r)
		if err != nil {
			return
		}
		if h.Count > maxDirectoryCount {
			return nil, fmt.Errorf("SquashFS directory header contains too many entries: %d", uint64(h.Count)+1)
		}
		curRead += 12
		for i := uint32(0); i <= h.Count; i++ {
			if curRead >= size {
				return nil, fmt.Errorf("SquashFS directory header exceeds declared size")
			}
			de, err = readEntry(r)
			if err != nil {
				return
			}
			curRead += 8 + uint32(de.NameSize) + 1
			if len(out) >= maxDirectoryEntries {
				return nil, fmt.Errorf("SquashFS directory contains too many entries")
			}
			out = append(out, Entry{
				BlockStart: h.BlockStart,
				Offset:     de.Offset,
				Name:       string(de.Name),
				InodeType:  de.InodeType,
				Num:        h.Num + uint32(de.NumOffset),
			})
		}
	}
	return
}
