// SPDX-License-Identifier: MIT
// Local change: use Anchore's MIT-licensed LZO decoder with a block-size bound.

package decompress

import (
	"errors"
	"fmt"

	"github.com/anchore/go-lzo"
)

type Lzo struct{}

func NewLzo() (Lzo, error) {
	return Lzo{}, nil
}

func (l Lzo) Decompress(data []byte) ([]byte, error) {
	return l.DecompressBounded(data, MaxBlockSize)
}

func (l Lzo) DecompressBounded(data []byte, max int) ([]byte, error) {
	// SquashFS metadata blocks are at most 8 KiB, and data/fragment blocks
	// are at most 1 MiB. Grow only on a short output buffer, with that cap.
	if max < 1 || max > MaxBlockSize {
		return nil, fmt.Errorf("invalid SquashFS decompression limit %d", max)
	}
	size := 8 << 10
	if size > max {
		size = max
	}
	for {
		out := make([]byte, size)
		n, err := lzo.Decompress(data, out)
		if err == nil {
			return out[:n], nil
		}
		if !errors.Is(err, lzo.ErrOutputOverrun) {
			return nil, err
		}
		if size == max {
			break
		}
		next := size * 2
		if next > max {
			next = max
		}
		size = next
	}
	return nil, fmt.Errorf("SquashFS LZO block exceeds %d bytes: %w", max, lzo.ErrOutputOverrun)
}
