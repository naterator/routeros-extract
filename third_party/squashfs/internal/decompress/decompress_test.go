// SPDX-License-Identifier: BSD-3-Clause
package decompress

import (
	"bytes"
	"compress/zlib"
	"errors"
	"sync"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"github.com/ulikunitz/xz/lzma"
)

func TestBundledDecodersBoundOutput(t *testing.T) {
	plain := bytes.Repeat([]byte{'x'}, MaxBlockSize+1)
	tests := []struct {
		name string
		make func([]byte) ([]byte, error)
		new  func() Decompressor
	}{
		{
			name: "zlib",
			make: func(data []byte) ([]byte, error) {
				var out bytes.Buffer
				w := zlib.NewWriter(&out)
				if _, err := w.Write(data); err != nil {
					return nil, err
				}
				if err := w.Close(); err != nil {
					return nil, err
				}
				return out.Bytes(), nil
			},
			new: func() Decompressor { return NewZlib() },
		},
		{
			name: "lz4",
			make: func(data []byte) ([]byte, error) {
				out := make([]byte, lz4.CompressBlockBound(len(data)))
				n, err := lz4.CompressBlock(data, out, nil)
				if err != nil {
					return nil, err
				}
				if n == 0 {
					return nil, errors.New("test payload was not compressible")
				}
				return out[:n], nil
			},
			new: func() Decompressor { return NewLz4() },
		},
		{
			name: "zstd",
			make: func(data []byte) ([]byte, error) {
				var out bytes.Buffer
				w, err := zstd.NewWriter(&out, zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(MaxBlockSize))
				if err != nil {
					return nil, err
				}
				if _, err = w.Write(data); err != nil {
					return nil, err
				}
				if err = w.Close(); err != nil {
					return nil, err
				}
				return out.Bytes(), nil
			},
			new: func() Decompressor { return NewZstd() },
		},
		{
			name: "lzma",
			make: func(data []byte) ([]byte, error) {
				var out bytes.Buffer
				w, err := lzma.NewWriter(&out)
				if err != nil {
					return nil, err
				}
				if _, err = w.Write(data); err != nil {
					return nil, err
				}
				if err = w.Close(); err != nil {
					return nil, err
				}
				return out.Bytes(), nil
			},
			new: func() Decompressor { d, _ := NewLzma(); return d },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed, err := tt.make(plain)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tt.new().Decompress(compressed); !errors.Is(err, ErrOutputLimit) {
				t.Fatalf("decompress error = %v, want ErrOutputLimit", err)
			}
		})
	}
}

func TestDecodeEnforcesMetadataLimit(t *testing.T) {
	plain := bytes.Repeat([]byte{'m'}, MaxMetadataSize+1)
	var compressed bytes.Buffer
	w := zlib.NewWriter(&compressed)
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(NewZlib(), compressed.Bytes(), MaxMetadataSize); !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("metadata decode error = %v, want ErrOutputLimit", err)
	}
}

func TestZstdDecoderConcurrent(t *testing.T) {
	plain := bytes.Repeat([]byte("concurrent squashfs block"), 4096)
	var compressed bytes.Buffer
	w, err := zstd.NewWriter(&compressed, zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(MaxBlockSize))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	d := NewZstd()
	const workers = 16
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := d.Decompress(compressed.Bytes())
			if err == nil && !bytes.Equal(got, plain) {
				err = errors.New("decoded data mismatch")
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}
