# Local SquashFS changes

This directory contains the MIT-licensed library source from
`github.com/CalebQ42/squashfs v1.4.1`. The upstream module checksum is
`h1:tBcFMQSRQvWcY50e9r9cv2uVzNf06fcUhly0LeZg8bI=`. The upstream copyright
and MIT license text are retained in the root [LICENSE](../../LICENSE).

The upstream command and tests are omitted. Those integration tests download
a large filesystem image and invoke external SquashFS executables. This
project tests the library using synthetic filesystems and the opt-in RouterOS
corpus instead; local decoder tests require no downloads.

Local changes:

- Replace the GPL-licensed `rasky/go-lzo` dependency with
  [`anchore/go-lzo v0.1.1`](https://github.com/anchore/go-lzo/tree/v0.1.1),
  licensed under MIT. LZO remains enabled in ordinary builds. The upstream
  `no_gpl` build condition and disabled-LZO stub are removed.
- Adapt the LZO decoder's buffer API and bound decoded blocks to the SquashFS
  maximum of 1 MiB, starting with an 8 KiB metadata-sized buffer.
- Bound every bundled decoder (zlib, LZ4, XZ, LZMA, Zstandard, and LZO) while
  decoding, including the 8 KiB metadata limit. Zstandard uses capped
  stateless decoding so the existing parallel extraction path remains safe;
  XZ and LZMA dictionaries are explicitly capped at 8 MiB.
- Reject malformed metadata, inode, fragment, and data-block size fields before
  they can cause oversized allocations or offset panics. The SquashFS
  superblock block-size validation also enforces the format's 4 KiB through
  1 MiB power-of-two range. Directory sizes, header counts, and 256-byte names
  are bounded before entry slices are grown.
- Use SquashFS's raw LZ4 block format rather than the unrelated LZ4 frame
  format; this keeps LZ4 images compatible with `mksquashfs` and bounds the
  destination buffer during decoding.
- Align compression dependency versions with the main module and use the
  adjacent XZ fork when testing this module on its own.
- Omit the unused `internal/routinemanager` package; no library code or tests
  import it.

The main module's `replace` directive is required to retain these changes.
There is no dependency on the former LZO implementation in either module.
