# RouterOS console `.mem` images

RouterOS uses prebuilt memory images for its console definitions. The `.mem`
files under `nova/lib/console/` contain menu trees, commands, parameters,
short and long help strings, and additional parser data. Feature bundles
provide further images under `bndl/<package>/nova/lib/console/`.

The console parser maps each file at the address given by its decimal
filename. A pointer into that mapping can be converted to a file offset:

```text
1073741824.mem             decimal 1073741824 = 0x40000000
stored pointer            0x4001da9c
file offset               0x4001da9c - 0x40000000 = 0x1da9c
bytes at that offset      "root\0"
```

Other pointers refer to virtual function tables in `nova/bin/parser`.
Resolving those requires the matching executable; subtracting the `.mem`
base from every word would produce incorrect results.

## Decode console files

Decode one image, supplying the parser from the same firmware:

```sh
routeros-extract console rootfs/nova/lib/console/1073741824.mem \
  --parser rootfs/nova/bin/parser -o console-output
```

Decode all numeric `.mem` files in an extracted filesystem:

```sh
routeros-extract console rootfs \
  --parser rootfs/nova/bin/parser -o console-output
routeros-extract verify console-output
```

The command also accepts several files or directories from one firmware
build. It skips nonnumeric `.mem` filenames found during directory searches,
does not follow directory symlinks, and rejects duplicate or overlapping
mapping ranges. An explicitly supplied file must have a numeric filename.
The output directory must be new.

Each image gets a directory named after its decimal mapping base containing:

- `<base>.mem`: the unchanged source image, retaining a usable filename.
- `nodes.json`: decoded nodes, original offsets and flags, vtable addresses,
  names, help, menu relationships, properties, and argument groups.
- `commands.txt`: recovered menu and command paths with short help.
- `strings.tsv`: pointer-backed string candidates, file offsets, addresses,
  reference counts, roles, encoding, and JSON-escaped text.

`index.json` records input and parser hashes, mappings, build values, and
counts. `integrity.json` covers the retained images and generated reports.

Normal `extract` and `analyze` also decode supported console images when a
matching `nova/bin/parser` is present in the same extracted filesystem.
Their reports appear under `derived/console/<filesystem>/<base>/`, with a
`derived/console/manifest.json` recording decoded and skipped files. The
source images remain in the normal filesystem extraction. `--no-derived`
skips this work, as it does the other derived reports.

An add-on may contain console images without the main parser. Those files
remain intact and receive a note explaining the missing parser. Use the
standalone `console --parser` command with the parser from the corresponding
main-system package to decode them.

## Supported builds and ABI

The recovered layout is checked against these exact parser binaries:

| Package | `nova/bin/parser` SHA-256 |
|---|---|
| 7.24.1 ARM64 | `d6ecbb1b0c0dbe3e96ccf1fb0ed617a5cfaef4f2697f67ee7436019203045156` |
| 7.24.2 ARM64 | `4e84fcf7a7e450f4633e4857273c0b465ddf4c59c9fc5c04b4492fb59b3ab8f8` |

Both executables are **ARM32**, despite the ARM64 package label. Their
console images use **32-bit little-endian words and absolute pointers**.
The decoder runs natively on all host platforms supported by the tool; it
does not emulate the firmware's CPU or execute extracted code.

Other firmware builds and CPU families are not yet supported by the console
decoder. A version string or ELF architecture alone does not establish
compatibility. Standalone decoding rejects an unsupported parser; automatic
package analysis records a note and keeps the original files. This does not
restrict ordinary NPK or filesystem extraction.

Each console image and parser input is limited to the smaller of
`--max-bytes` and 64 MiB. Additional bounds cover node counts, references,
string scanning, and path expansion. The decoder rejects invalid pointers,
truncated records, malformed vectors, and cycles in the traversed hierarchy.
Decoded report text is limited to 16 MiB per image, counting repeated help
and expanded paths as well as string candidates.

## Loader evidence

These addresses refer to the supplied **7.24.2** parser executable:

| Virtual address | Observed operation |
|---|---|
| `0x000a7bf4` | Loads `/nova/lib/console` before calling `nv::getAllDirs`. |
| `0x000a7d8c` | Calls `strtoul` on a directory entry's name. |
| `0x000a7da0` | Compares the remaining suffix with `.mem`. |
| `0x000a7e10` | Calls the mapping helper with the parsed address and filename. |
| `0x00046770` | Calls `mmap` with that address, the file size, protection `1`, flags `0x11`, and file offset zero. |
| `0x00046774` | Checks that the returned mapping equals the requested address. |
| `0x000a7e80`–`0x000a7e8c` | Compares the first word with the first loaded image. |
| `0x000a7ed4` | Reads the root object pointer at image offset `0x1c`. |

Protection `1` is `PROT_READ`; flags `0x11` combine `MAP_SHARED` and
`MAP_FIXED`. This fixed mapping makes the absolute pointers usable without
relocation. See the [Linux mapping constants](https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/asm-generic/mman-common.h)
and [mmap documentation](https://man7.org/linux/man-pages/man2/mmap.2.html).

The first word serves as a module compatibility value. A mismatch produces
a warning containing `!= root:` and skips that module's registration. All
eight images from each examined version share the same value:

| Version | First word | Interpreted as Unix seconds |
|---|---|---|
| 7.24.1 | `0x6a884e5a` | 2026-08-21 13:10:50 UTC |
| 7.24.2 | `0x6a994576` | 2026-09-03 10:01:26 UTC |

A build timestamp is a plausible interpretation; the loader's equality
check is confirmed. The extraction tool additionally checks this word
against the expected value for its supported parser profile.

## Image header

The observed header is `0x6c` bytes: 27 little-endian 32-bit words. The names
below describe recovered roles, not original C++ member names.

| File offset | Contents |
|---|---|
| `0x00` | Build/module compatibility word. |
| `0x04`–`0x14` | Five pointers to small parser/value objects; exact roles undecoded. |
| `0x18` | Zero in these samples. |
| `0x1c` | Root menu object pointer. |
| `0x20` | Shared `export` command object pointer. |
| `0x24` | Shared `recursive-print` command object pointer. |
| `0x28` | Shared `alias` command object pointer. |
| `0x2c`, `0x30` | Pointer and byte length for an additional table; length `0x50` here. |
| `0x34`, `0x38` | Pointer and variable byte length for another data area; layout undecoded. |
| `0x3c` | Pointer to the empty string; also the fallback for absent help. |
| `0x40` | Pointer to `yes`. |
| `0x44` | Pointer to `no`. |
| `0x48` | Zero in these samples. |
| `0x4c` | Shared `comment` parameter object pointer. |
| `0x50` | Shared `disabled` parameter object pointer. |
| `0x54` | Shared `dead` parameter object pointer. |
| `0x58`, `0x5c` | Pointer/byte-length pair; length `0x80` here. |
| `0x60`, `0x64` | Another pointer/byte-length pair; length `0x80` here. |
| `0x68` | Additional table pointer; role undecoded. |

Strings, objects, and supporting arrays follow. The image does not need
decompression before these definitions can be read.

## Object records

Objects begin with pointers into the matching parser's `.rodata` section.
Those locations contain virtual function tables used by indirect ARM calls.
The identified tables also have preceding offset-to-top and typeinfo words,
consistent with the [C++ virtual table layout](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#vtable-components);
both preceding words are zero here.

The common node prefix is:

| Object offset | Contents |
|---|---|
| `+0x00` | Vtable pointer into `parser`. |
| `+0x04` | One-byte offset to optional fields, followed by packed flags. |
| `+0x08` | Additional packed flags. |
| `+0x0c` | Pointer to a NUL-terminated name; some parameter names are empty. |
| `+0x10` onward | Type-specific fields. |

The decoder identifies node families through their vtables and shared
virtual methods. `menu`, `command`, `parameter`, `directory`, `settings`,
and `item-table` are descriptions of observed behavior, not recovered
source-level class names. Unrecognized type-specific fields remain
undecoded; their original bytes are retained in the source image.

For example, the main 7.24.2 image has this root object:

```text
file offset 0x1905c:  0x000d0818   vtable in parser .rodata
file offset 0x19060:  0x00008a20   optional-field offset and flags
file offset 0x19064:  0x00000000   additional flags
file offset 0x19068:  0x4001da9c   name -> "root"
file offset 0x1906c:  0x4001daa4   child pointer array
file offset 0x19070:  0x00000148   328 bytes = 82 child pointers
file offset 0x19074:  0x00000000   parent
file offset 0x19078:  0x00000000   additional menu field
file offset 0x1907c:  0x40015ff4   short help -> "internal commands"
```

The first entries at parser address `0x000d0818` point to ARM routines at
`0x0001db50`, `0x0001efc4`, `0x00092f8c`, and `0x0009c060`. The routine at
`0x00092f8c` traverses children to format names and help; `0x0009c060`
follows menu choices into parser dispatch.

## Optional fields and strings

Let `flags` be the little-endian word at object offset `+0x04`. Its low byte
is an offset, not a reliable total record size. It can be zero when no
optional fields are present. To find the first optional field, compute:

```text
cursor = align_up(object_address + (flags & 0xff), 4)
```

Consume these fields in order, only when their bits are set:

| Mask | Field |
|---|---|
| `0x00000400` | Four-byte value/reference; exact meaning undecoded. |
| `0x00000800` | Pointer to short help. |
| `0x00001000` | Pointer to long help. |

Other optional fields follow. The short-help accessor is at
`0x0002c958`/`0x0002c998`; the long-help accessor is at `0x00046928`. Both
skip preceding optional fields when necessary.

The shared `comment` node at file offset `0x1d944`, for example, has flags
`0x00801a14`. Its short-help pointer is at object offset `0x14`, followed by
the long-help pointer at `0x18`.

Text is NUL-terminated and mostly ASCII. Longer help often contains CRLF.
It is not uniformly UTF-8: the watchdog description at file offset `0x13c1`
contains a single `0xa0` byte between `per` and `10 seconds`. The decoder
tries ASCII, UTF-8, then a reversible Latin-1 interpretation and records
the choice in `strings.tsv`.

Strings referenced by validated nodes are labeled `name`, `summary`, or
`description`. Other printable strings reached through aligned words are
labeled `unclassified-candidate`: some may be enum or validator data, while
an integer can also accidentally resemble a pointer. Candidate strings are
not automatically treated as command definitions.

## Menus, arguments, and properties

The vectors use a start pointer and **byte length**, rather than an element
count or a start/end pair.

| Node layout | Object offsets | Entry layout |
|---|---|---|
| All menus | `+0x10` pointer, `+0x14` byte length | Four-byte child-node pointers. |
| All menus | `+0x18` | Parent menu pointer, or zero. |
| Settings menu | `+0x20` pointer, `+0x24` byte length | Four-byte property pointers. |
| Item-table menu | `+0x60` pointer, `+0x64` byte length | Eight-byte entries: property pointer, then flags. |
| Command | `+0x10` pointer, `+0x14` byte length | First argument-node vector. |
| Command | `+0x18` pointer, `+0x1c` byte length | Second argument-node vector. |

The two argument groups remain separate in JSON; their positional/named
semantics have not been fully established. Property-entry flags remain
numeric. The lookup routine at `0x00045168` explicitly checks bit `0x08`
before considering an item-table property.

`paths` contains recovered menu or command paths. A path containing ` :: `
denotes a property or argument of the preceding menu/command. This separator
is report notation, not RouterOS syntax. A shared object can have multiple
paths. Objects without a path through the decoded relationships remain in
`nodes.json` with an empty `paths` list. Empty relationship arrays and absent
parent pointers may be omitted from JSON.

## Validation and remaining fields

The eight images in the supplied 7.24.2 ARM64 package contain 568 menu
records, 4,816 command records, and 24,651 parameter records. The main image
alone contains 425, 3,575, and 18,150 respectively. These counts include
shared and internal definitions; they do not count unique usable commands
on a particular router.

All decoded fields, command listings, and string records matched the
research Python decoder for 16 images across 7.24.1 and 7.24.2. Automatic
NPK extraction produced the same decoded records, and both complete package
extractions passed source and integrity verification. Ordinary tests use
small synthetic images and a synthetic ELF, with no vendor fixtures in the
repository. See [VALIDATION.md](VALIDATION.md) for the validation scope.

Defaults, enum/value tables, validator/expression objects, dispatch IDs,
complete flag semantics, and the additional header tables need further
analysis. Names and help alone do not establish runtime behavior or command
availability. Supporting another parser build requires checking its object
layout and accessors before adding a compatible profile.
