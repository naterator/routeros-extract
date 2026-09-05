# Synthetic filesystem fixtures

These archives contain only text and empty files created for this project's
tests. They contain no RouterOS files, executable code, or third-party source.

- `empty-file.squashfs`: an empty file and `nonempty`, containing
  `routeros squashfs fixture` followed by a newline.
- `lzo.squashfs`: `empty`, `nested/small.txt` containing
  `BSD extraction fixture` followed by a newline, and `repeat.txt` containing
  12,000 repetitions of `RouterOS LZO fixture` followed by a newline.
  Its 128 KiB blocks exercise compressed metadata, a full data block, a final
  partial block, and fragments.

The LZO fixture was generated with `mksquashfs` using:

```sh
mksquashfs SOURCE lzo.squashfs -comp lzo -b 131072 -noappend \
  -all-root -no-xattrs -mkfs-time 0 -all-time 0 -processors 1
```

The generator is not linked into the tool or included in the archives. These
test inputs are distributed under the project's BSD-3-Clause license.
