# RouterOS formats and extraction boundaries

This document records the formats the CLI currently recognizes. A format that
is not recognized is still retained as a raw NPK section whenever framing is
valid. Recognition and decoding are deliberately separate: a valid package
does not become unusable merely because a vendor adds a section or a new
payload encoding.

The console command-definition images under `nova/lib/console/*.mem` have
their own [format and decoder documentation](CONSOLE-MEM.md), including the
fixed-address object layout and the currently supported parser builds.

## NPK framing

An NPK begins with:

| Offset | Size | Encoding | Meaning |
|---:|---:|---|---|
| `0` | 4 | bytes | magic `1e f1 d0 ba` |
| `4` | 4 | little-endian `uint32` | file length minus eight |
| `8` | 2 | little-endian `uint16` | section type |
| `10` | 4 | little-endian `uint32` | section payload length |
| `14` | variable | bytes | payload; the next six-byte header follows immediately |

The parser checks declared length and every section bound. It keeps section
order and index because section IDs can repeat. Known labels include package
info (`0x01`), description (`0x02`), dependencies (`0x03`), file container
(`0x04`), install/uninstall scripts (`0x07`/`0x08`), signature (`0x09`), main
info (`0x12`), SquashFS (`0x15`), digest metadata (`0x17`), channel (`0x18`),
and bundle marker (`0x19`). Unknown IDs and padding are stored as raw `.bin`
files. A signature section is evidence to preserve, not proof of authenticity.
Text previews in metadata are capped at 4 KiB and marked `text_truncated`
when shortened; raw section files always retain the complete bytes.

Package-info and main-info records use a 16-byte NUL-padded name followed by
version fields and a Unix build timestamp. The architecture and channel text
are advisory metadata; the ELF headers and payloads determine the architecture
of individual binaries.

## File-container records

The `0x04` payload is zlib-compressed. Its decoded stream is a sequence of
30-byte records:

* bytes `0:2`: POSIX mode bits;
* bytes `8:12`: little-endian modification time;
* bytes `24:28`: little-endian content length;
* bytes `28:30`: little-endian filename length;
* bytes `30:30+nameSize`: filename bytes;
* following bytes: content or metadata payload.

The implementation checks exact record bounds, complete zlib consumption, and
archive path safety. Directories, symlinks, and special nodes are represented
in the manifest and the byte-exact `files-container.decoded` stream. The
browse copy contains regular files, directories, and optional symlinks; it
does not follow archive links or create device nodes. Special-node payloads
up to 4 KiB are also shown as `payload_hex`; larger payloads retain their
size and hash, with their bytes available in the decoded container. Symlink
targets containing NUL or exceeding 4 KiB are rejected.
PPC packages can contain multiple records for one path. Their four-byte
variant tags are retained and later records get a deterministic variant suffix
in the browse copy.

## SquashFS

Section `0x15` is read with a native Go SquashFS reader. SquashFS version,
compression, block size, inode count, ownership, modes, timestamps, symlinks,
device numbers, and regular-file hashes are copied into the output manifests.
The original image is retained as `sections/...squashfs` (or `image.squashfs`
for the standalone `squashfs` command). The generated `rootfs.tar.gz` is the
portable metadata-preserving representation; `rootfs/` is a browse copy.

Linux permits names that collide on common macOS and Windows volumes. The
browse copy maps case-fold collisions to `.__case_<sha256-prefix>` and long,
non-ASCII, or Windows-incompatible names to `_ros_<prefix>_<hash>`, while
`rootfs-path-map.json`, the manifest, and tar archive retain the original name.
Device nodes and other special nodes are metadata-only in the browse tree.

## Boot objects, kernels, and CPIO

`kernel` scans a boot object by validating candidate streams instead of
accepting magic bytes alone. It recognizes ELF, Linux ARM/AArch64 images,
Linux x86 bzImages, EFI/PE containers, gzip, XZ, and newc CPIO. Valid streams
are saved with their exact compressed bytes, decoded bytes, offsets, hashes,
integrity-check type, and Linux banners where present. Nested decoded ELF and
CPIO payloads are scanned recursively within bounded depth and size limits.

The validated architecture matrix is:

| Input family | Observed form in the validation corpus |
|---|---|
| ARM | boot object with two XZ streams |
| AArch64 | ELF boot loader with two XZ streams; XZ uses the ARM64 BCJ filter |
| MIPS big-endian | boot object with two XZ streams |
| MIPS little-endian / MMIPS | boot object with two XZ streams |
| SMIPS (MIPS big-endian) | boot object with two XZ streams |
| PowerPC | four boot variants, each with two XZ streams |
| TILE | uncompressed ELF with embedded XZ CPIO and a separate `boot/initrd.rgz` |
| x86 | `BOOTX64.EFI` / bzImage, then XZ to an ELF64 kernel and newc CPIO |

The table describes tested shapes, not a claim that every RouterOS release uses
the same wrapper. When an input has a new wrapper, the original object remains
available and valid nested streams can still be extracted. CPIO `070701` and
`070702` records are parsed with path, mode, owner, timestamp, device, link,
checksum, and trailer checks; device entries are recorded without creating
device nodes on the host. CPIO symlinks are retained as metadata only.

## RouterBOOT FWF and NRV2B

RouterBOOT update files usually end in `.fwf`. For modern ARM/ARM64 images,
the decoder checks the envelope
length at offset `32`, expected output length at `36`, compressed stream at
`40`, and the IEEE CRC32 stored at the block end. It decodes NRV2B with
little-endian 32-bit bit words, requires the exact expected output size, and
allows only bounded zero padding after the terminator. The platform tag and
version are kept in `manifest.json`; any trailing bytes remain in the original
FWF. The trailing data is not treated as a verified signature.

The observed MIPS, PowerPC, and TILE legacy FWFs have a 32-byte header followed
by an uncompressed image. They are identified by known platform tags and a
valid version field; a structurally valid ELF payload can identify an additional
legacy family. Their complete payload is retained without guessing a compression
format. The manifest reports `codec: none`, `decoded: false`, and
`crc32_available: false`. Unknown raw families fail explicitly. The modern
envelope is checked for platforms classified as modern. Known legacy tags
take precedence because legacy payload bytes can resemble modern framing;
this classification is not authentication of the platform tag or payload.

The implementation uses a Go adaptation of RetDec's MIT-licensed NRV2B
decoder and preserves its attribution. The exact source revision and local
changes are recorded in [internal/nrv2b/README.md](../internal/nrv2b/README.md).
Firmware extraction invokes it only after the FWF framing and limits pass.

## Analysis outputs

For file-container and rootfs entries, `analyze` can additionally produce:

* decompressed kernel `Image` and initramfs CPIO files;
* RouterBOOT decoded binaries and printable strings;
* WebFig gzip definitions;
* ELF header, section, dynamic dependency, and architecture inventories;
* selected printable-string reports and kernel-module `.modinfo` fields;
* JSON summaries and source-to-output hashes.

In `summary.json`, `kernels` counts analyzed boot objects, including separate
initrd and EFI files; it is not a count of distinct Linux kernel builds.
Malformed incidental ELF and WebFig gzip files are retained and noted in the
summary. Byte-limit violations, output errors, and failed kernel or firmware
decoding still stop extraction.

These reports support examination and comparison. They do not establish what a
binary does, whether a change is security-relevant, or whether a firmware
signature is valid. Use a disassembler or a controlled Linux environment for
those questions, and treat extracted code as untrusted input.

## Add-on packages and ZIP collections

An optional feature or hardware add-on NPK follows the same NPK framing even
when it has only package metadata, a file container, or a small SquashFS. The
CLI processes each member independently; absence of a boot kernel or
RouterBOOT section is normal for an add-on. `all_packages.zip` is a container
of such NPKs. Pass the ZIP directly to `extract`. ZIP directory names do not
become RouterOS archive paths: each original NPK is stored under `npk/` and
its extraction under `packages/`. Non-NPK members are inventoried and ignored.
The package parser does not infer a package's role from its filename.

`--max-bytes` defaults to 512 MiB. It limits each input, the aggregate decoded
ZIP members, each file container or filesystem, and the combined decoded
streams in each recursive kernel scan. Each NPK in a collection is processed
with its own limits. Retained originals, decoded copies, tar archives, and
reports consume additional space; the option is not a total disk or RAM quota.
