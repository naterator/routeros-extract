package decompress

import (
	"errors"
	"fmt"

	"github.com/pierrec/lz4/v4"
)

// SquashFS stores LZ4 data as independent raw LZ4 blocks, not LZ4 frames.
// The frame Reader is therefore intentionally not used here.
type Lz4 struct{}

func NewLz4() *Lz4 {
	return &Lz4{}
}

func (l *Lz4) Decompress(data []byte) ([]byte, error) {
	return l.DecompressBounded(data, MaxBlockSize)
}

func (l *Lz4) DecompressBounded(data []byte, max int) ([]byte, error) {
	if max < 1 || max > MaxBlockSize {
		return nil, fmt.Errorf("invalid SquashFS decompression limit %d", max)
	}
	// Keep one byte of headroom so an oversized block can be distinguished
	// from malformed input without allowing the decoder to grow the buffer.
	out := make([]byte, max+1)
	n, err := lz4.UncompressBlock(data, out)
	if err != nil {
		return nil, err
	}
	if n > max {
		return nil, fmt.Errorf("%w: got more than %d bytes", ErrOutputLimit, max)
	}
	if n < 0 || n > len(out) {
		return nil, errors.New("invalid LZ4 decoded size")
	}
	return out[:n], nil
}
