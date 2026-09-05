//go:build !no_obsolete

package decompress

import (
	"bytes"

	"github.com/ulikunitz/xz/lzma"
)

type Lzma struct{}

func NewLzma() (Lzma, error) {
	return Lzma{}, nil
}

func (l Lzma) Decompress(data []byte) ([]byte, error) {
	return l.DecompressBounded(data, MaxBlockSize)
}

func (l Lzma) DecompressBounded(data []byte, max int) ([]byte, error) {
	// SquashFS blocks are at most 1 MiB. Keep a compatibility margin for
	// compressor dictionaries while avoiding the decoder's 2 GiB default for
	// malformed LZMA headers.
	rdr, err := (lzma.ReaderConfig{DictCap: 8 << 20}).NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return readAllBounded(rdr, max)
}
