# Local XZ changes

This directory is a vendored, modified copy of
`github.com/mikelolasagasti/xz` v1.0.1. The upstream package is licensed under
0BSD; its full license is in the root [LICENSE](../../LICENSE), and `AUTHORS`
remains beside the source. The local
module path is replaced in the root `go.mod` so the command is self-contained.

The RouterOS AArch64 kernel streams use XZ filter ID `0x0a`, the ARM64 BCJ
filter. The upstream Go package supported the other common BCJ filters but not
this one. `dec_bcj.go` and `dec_stream.go` therefore include an ARM64 filter
ported from XZ Embedded. The port follows XZ Embedded revision
`ae63ae3a36ed01724674e8f3d750dc47bf125410`; that source carries the 0BSD
notice from its authors.

`reader.go` and `routeros_extensions.go` add two small extraction-oriented
hooks:

* `StopAtStreamEnd` stops after the first XZ footer without consuming padding
  or a following embedded object;
* `InputConsumed` reports the exact compressed bytes consumed by that stream.

The extraction code needs both properties when an XZ stream is embedded in an
ELF or kernel wrapper. The decoder still validates XZ checks, block structure,
and the configured dictionary limit. It is not an XZ encoder.

The upstream `random-1mb.xz` test fixture is replaced with a deterministic
64 KiB + 1 byte sample, stored as `testdata/other/random-64k-plus-1.xz`.
It occupies 65,600 bytes instead of 1,000,108 bytes and retains coverage of
input-buffer refills, multiple uncompressed LZMA2 chunks, dictionary wrapping,
concatenated streams, byte-sized reads, and reader reuse. The decoded checksum
and all test references are updated. Its generation recipe is in
[`testdata/other/README.md`](testdata/other/README.md).

Local tests and the remaining upstream test corpus are in `reader_test.go` and
`testdata/`. When updating this fork, keep the upstream license text, rerun
`(cd third_party/xz && go test ./...)`, and record the upstream revision and functional
reason for any additional patch here.
