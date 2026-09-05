# Smaller random fixture

`random-64k-plus-1.xz` contains 65,537 deterministic pseudorandom bytes. It
replaces the upstream 1 MB random fixture and takes 65,600 bytes on disk.
The decoded data exceeds both the reader's 8 KiB input buffer and the
64 KiB LZMA2 uncompressed-chunk limit. A 64 KiB dictionary also exercises
wrapping. The existing tests use it for ordinary decoding, byte-sized reads,
concatenated streams, and reader reuse.

To regenerate from `third_party/xz/` using the Python standard library:

```sh
python3 - <<'PY'
from pathlib import Path
import hashlib
import lzma

seed = b'routeros-extract/xz/random-64k-plus-1/v1'
data = hashlib.shake_256(seed).digest(65537)
encoded = lzma.compress(
    data,
    format=lzma.FORMAT_XZ,
    check=lzma.CHECK_CRC64,
    filters=[{'id': lzma.FILTER_LZMA2, 'dict_size': 65536}],
)
Path('testdata/other/random-64k-plus-1.xz').write_bytes(encoded)
print('Decoded MD5:', hashlib.md5(data).hexdigest())
PY
```

The expected decoded checksum is recorded in `reader_test.go`. Normal Go
builds and tests use the checked-in fixture and do not run this generator.
