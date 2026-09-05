package decompress

import (
	"errors"
	"fmt"

	"github.com/klauspost/compress/zstd"
)

const maxZstdWindow = 8 << 20

type Zstd struct {
	rdr *zstd.Decoder
}

func NewZstd() Zstd {
	rdr, _ := zstd.NewReader(nil,
		zstd.WithDecoderLowmem(true),
		// SquashFS data blocks are capped at 1 MiB, but a zstd frame's
		// history window can be larger than one output block. Keep a generous
		// compatibility margin while preventing the library's 512 MiB default.
		zstd.WithDecoderMaxWindow(maxZstdWindow),
		zstd.WithDecoderMaxMemory(MaxBlockSize),
		zstd.WithDecodeAllCapLimit(true),
	)
	return Zstd{
		rdr: rdr,
	}
}

func (z Zstd) Decompress(data []byte) ([]byte, error) {
	return z.DecompressBounded(data, MaxBlockSize)
}

func (z Zstd) DecompressBounded(data []byte, max int) ([]byte, error) {
	if max < 1 || max > MaxBlockSize {
		return nil, fmt.Errorf("invalid SquashFS decompression limit %d", max)
	}
	// DecodeAll is stateless and safe for concurrent callers on the shared
	// decoder. DecodeAllCapLimit keeps the destination at the block limit and
	// rejects frames that would need a larger output buffer.
	out, err := z.rdr.DecodeAll(data, make([]byte, 0, max))
	if errors.Is(err, zstd.ErrDecoderSizeExceeded) {
		return nil, fmt.Errorf("%w: %w", ErrOutputLimit, err)
	}
	return out, err
}
