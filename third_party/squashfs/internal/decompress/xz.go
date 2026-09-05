package decompress

import (
	"bytes"
	"sync"

	"github.com/mikelolasagasti/xz"
)

type Xz struct {
	pool sync.Pool
}

const maxXZDict = 8 << 20

func NewXz() *Xz {
	return &Xz{
		pool: sync.Pool{
			New: func() any {
				rdr, _ := xz.NewReader(nil, maxXZDict)
				return rdr
			},
		},
	}
}

func (x *Xz) Decompress(data []byte) ([]byte, error) {
	return x.DecompressBounded(data, MaxBlockSize)
}

func (x *Xz) DecompressBounded(data []byte, max int) ([]byte, error) {
	rdr := x.pool.Get().(*xz.Reader)
	defer x.pool.Put(rdr)
	err := rdr.Reset(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return readAllBounded(rdr, max)
}
