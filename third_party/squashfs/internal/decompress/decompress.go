package decompress

import (
	"errors"
	"fmt"
	"io"
)

// MaxBlockSize is the largest uncompressed data block permitted by the
// SquashFS 4 format. A decoder must enforce this while reading because a
// compressed block can expand before a caller's output-size check runs.
const MaxBlockSize = 1 << 20

// MaxMetadataSize is the largest uncompressed metadata block permitted by
// SquashFS 4.
const MaxMetadataSize = 8 << 10

// ErrOutputLimit reports a decoded block larger than the reader accepts.
var ErrOutputLimit = errors.New("SquashFS decompressed block exceeds size limit")

type Decompressor interface {
	Decompress([]byte) ([]byte, error)
}

// boundedDecompressor is optional so callers that provide a custom
// Decompressor keep the existing interface. All bundled decoders implement it
// and therefore enforce the limit before returning the output.
type boundedDecompressor interface {
	DecompressBounded([]byte, int) ([]byte, error)
}

// Decode runs a decoder with a format-specific output limit.
func Decode(d Decompressor, data []byte, max int) ([]byte, error) {
	if max < 1 || max > MaxBlockSize {
		return nil, fmt.Errorf("invalid SquashFS decompression limit %d", max)
	}
	if bounded, ok := d.(boundedDecompressor); ok {
		return bounded.DecompressBounded(data, max)
	}
	out, err := d.Decompress(data)
	if err != nil {
		return nil, err
	}
	if len(out) > max {
		return nil, fmt.Errorf("%w: got %d bytes, limit %d", ErrOutputLimit, len(out), max)
	}
	return out, nil
}

func readAllBounded(r io.Reader, max int) ([]byte, error) {
	if max < 1 || max > MaxBlockSize {
		return nil, fmt.Errorf("invalid SquashFS decompression limit %d", max)
	}
	out, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(out) > max {
		return nil, fmt.Errorf("%w: got more than %d bytes", ErrOutputLimit, max)
	}
	return out, nil
}
