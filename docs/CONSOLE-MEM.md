# RouterOS console `.mem` images

RouterOS stores console definitions as memory images under
`nova/lib/console/` and `bndl/<package>/nova/lib/console/`. They contain menu
trees, commands, parameters, help text, and other parser objects. They are
uncompressed binary object graphs, not plain string tables.

The filename supplies the mapping address. For `1073741824.mem`, the base
is `0x40000000`: a pointer to `0x4001da9c` refers to file offset `0x1da9c`.
Other pointers address virtual function tables in the matching executable,
usually `nova/bin/parser`. Earlier releases use `nova/bin/console`.

## Extract the definitions

Normal NPK extraction decodes console files automatically when the matching
executable is in the same filesystem:

```sh
routeros-extract extract routeros-7.24.2-arm64.npk -o extracted
```

Decode an extracted filesystem or individual numeric `.mem` files:

```sh
routeros-extract console extracted/routeros-7.24.2-arm64/rootfs \
  --parser extracted/routeros-7.24.2-arm64/rootfs/nova/bin/parser \
  -o console-output
routeros-extract verify console-output
```

For add-ons, supply the executable from the main package of the **same
release and architecture**:

```sh
routeros-extract extract all_packages-arm64-7.24.2.zip \
  --console-parser extracted/routeros-7.24.2-arm64/rootfs/nova/bin/parser \
  -o addons
```

`analyze DIRECTORY --console-parser FILE` also accepts this fallback.
An executable found inside the package takes precedence. The standalone
`console` command accepts multiple files or directories belonging to one
build. For older firmware, pass `nova/bin/console` to `--parser` instead.
No extracted code is executed, and no external decoder is required.

Standalone output contains an `index.json`, an integrity ledger, and a
subdirectory per mapping with:

- `<base>.mem`: the original bytes and numeric filename.
- `nodes.json`: node addresses, flags, names, help, relationships, and paths.
- `commands.txt`: recovered menu and command paths with short help.
- `strings.tsv`: pointer-backed strings, addresses, roles, and encodings.

Automatic extraction writes reports under
`derived/console/<filesystem>/<base>/`. Its manifest records successful
and skipped images. Original files remain intact. `--no-derived` disables
this analysis.

## Compatibility across releases and architectures

The decoder has **no release-number or parser-hash allowlist**. It reads the
ELF architecture and byte order, finds candidate C++ vtables, checks the
root's type accessors, and recognizes supported header and flag layouts.
Property vectors must resolve to parameter objects. Binary and image
SHA-256 hashes remain in the reports for provenance.

All eight 7.24.2 platforms were checked, including every NPK in each
`all_packages` ZIP. There were 144 console images and 278,668 decoded nodes.
Packages without console images were included in the inventory. The supplied
ARM64 and x86 installer ISOs contain 16 and 12 NPKs respectively, all
byte-identical to packages in that corpus. The install-image ZIP's FAT image
contains 11 matching NPKs.

| RouterOS package architecture | Console executable ABI | Pointer byte order |
|---|---|---|
| ARM, ARM64 | ELF32 ARM | Little endian |
| MIPSBE, SMIPS | ELF32 MIPS | Big endian |
| MMIPS | ELF32 MIPS | Little endian |
| PPC | ELF32 PowerPC | Big endian |
| TILE | ELF32 TILE-Gx | Little endian |
| x86 | ELF32 i386 | Little endian |

Package architecture is not pointer width: the examined ARM64 and TILE
console executables also use 32-bit pointers. The host running this tool
can have a different CPU and byte order.

Earlier samples cover 7.1.5, 7.20.1, 7.20.2, 7.20.6, 7.21.1, 7.21.2,
7.21.3, 7.22.1, 7.23.4, and 7.24.1. The detailed architecture, package, and image
counts are in [console-validation.json](console-validation.json). The tested
7.1.5 TILE main image still needs a different alias-method recognizer;
its seven bundled module images decode. The examined 6.49.19 executables
use another virtual-method layout and are rejected by the console decoder.
Ordinary NPK extraction still retains those files.

A routine rebuild does not require a source change. New vtable addresses,
parser hashes, compatibility words, and command definitions are read from
the inputs. A changed object layout, unfamiliar compiler sequence, or new
ELF ABI can require another structural decoder. Testing these samples cannot
guarantee every historical or future format. Unsupported or malformed
images produce an error in `console`, or a recorded skip during automatic
analysis; the tool does not label a strings-only scan as a decoded graph.

## Header and loader

The loader parses the decimal filename and maps the file at that address.
In the examined 7.24.2 ARM64 package's ARM32 parser, the directory lookup
starts near `0x000a7bf4`; `0x000a7d8c` calls `strtoul` and `0x000a7da0`
checks `.mem`. The helper at `0x00046770` calls `mmap` with protection `1`
and flags `0x11`: `PROT_READ`, `MAP_SHARED`, and `MAP_FIXED`.
See the [Linux mapping constants](https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/asm-generic/mman-common.h).
These addresses describe that executable, not offsets used by the decoder.

The first word is a **module compatibility value**. The loader compares
it with the first loaded image, warning and skipping a mismatched module.
The tool likewise checks equality within a collection. It does not require
a fixed expected value for a particular executable: 7.24.2 MIPSBE and SMIPS
have identical parser binaries but different module compatibility words.
Interpreting the word as Unix seconds is useful context, not an established
format version or proof that the supplied parser matches the image.

Headers grew as fields were added:

| Examined family | Root pointer field | Empty/yes/no pointer fields | Header bytes observed |
|---|---|---|---|
| 7.1.5 | `0x10` | `0x28`, `0x2c`, `0x30` | `0x50` |
| 7.20.x | `0x1c` | `0x38`, `0x3c`, `0x40` | `0x60` |
| 7.21.x | `0x1c` | `0x38`, `0x3c`, `0x40` | `0x64` |
| 7.22.1 | `0x1c` | `0x38`, `0x3c`, `0x40` | `0x68` |
| 7.23.4, 7.24.1, 7.24.2 | `0x1c` | `0x3c`, `0x40`, `0x44` | `0x6c` |

These versions are observations, not selection rules. The reader checks
root and string anchors, then scans bounded pointer/length extension words.
`header_size` and `header_words` report that inferred prefix. Unrecognized
additional tables remain undecoded.

In the `0x6c` layout, `0x20`, `0x24`, and `0x28` point to shared `export`,
`recursive-print`, and `alias` commands. `0x2c`/`0x30` and `0x34`/`0x38`
are pointer/byte-length pairs. `0x4c`, `0x50`, and `0x54` point to shared
`comment`, `disabled`, and `dead` parameters. Further vectors occupy
`0x58`/`0x5c` and `0x60`/`0x64`; `0x68` is another pointer.

## Objects and virtual methods

| Object offset | Contents |
|---|---|
| `+0x00` | Vtable pointer into the matching executable's `.rodata`. |
| `+0x04` | Byte offset to optional fields. |
| `+0x05` onward | Packed flags; their interpretation varies by layout. |
| `+0x08` | Further flags, preserved as a native-order word. |
| `+0x0c` | Pointer to a NUL-terminated name. |
| `+0x10` onward | Class-specific data. |

The observed non-RTTI tables have two preceding zero words: offset-to-top
and typeinfo, consistent with the [C++ ABI](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#vtable-components).
Within the supported node family, virtual slots 10, 11, and 12 return the
object itself for parameters, commands, and menus respectively, and zero
for the other two categories. Slot 9 is shared by ordinary nodes. The tool
recognizes complete trivial accessors for each supported CPU; it does not
run a disassembler or emulate arbitrary instructions. Older alias objects
forward those calls through a target pointer at `+0x10`.

`menu`, `command`, `parameter`, `alias`, `directory`, `settings`, and
`item-table` are descriptions of behavior, not recovered C++ class names.
The main 7.24.2 ARM64 image's root is at file offset `0x1905c`, with vtable
`0x000d0818`, name pointer `0x4001da9c`, and 82 child pointers. Those
addresses are evidence from one sample, not constants needed for another.

## Optional fields and text

Read the offset at `+0x04` and flags at `+0x05` as **bytes**, regardless of
pointer byte order. For example, bytes `20 8a 00 00` represent native word
`0x00008a20` on little-endian systems and `0x208a0000` on big-endian systems;
the optional-field offset remains `0x20` in both.

The following masks apply to the byte at `+0x05`:

| Report layout suffix | Optional byte | Optional word | Extra word | Short help | Long help |
|---|---|---|---|---|---|
| `flags-08-legacy` | `0x02` | `0x04` | — | `0x08` | `0x10` |
| `flags-10` | `0x02` | `0x04` | `0x08` | `0x10` | `0x20` |
| `flags-04` | — | `0x02` | — | `0x04` | `0x08` |
| `flags-08` | — | `0x04` | — | `0x08` | `0x10` |

Start at the object address plus its optional-field offset. Consume a
present optional byte, align to four bytes, then consume present words and
help pointers in table order. The offset can be zero when no optional data
is present; it is not a reliable total object size. Other optional fields
can follow the decoded fields.

For compatibility with earlier reports, `optional_0400` still names the
first optional word, including in `flags-04`, where its physical mask is
`0x02`. Its meaning remains unknown. `optional_byte` and `optional_extra`
retain the additional older fields. Header anchors and checked virtual
methods distinguish the supported flag layouts; a module need not itself
contain short help on its root.

Text is NUL-terminated, usually ASCII, and sometimes contains CRLF or
non-UTF-8 bytes. The decoder records ASCII, UTF-8, or a reversible Latin-1
interpretation. Validated node strings receive `name`, `summary`, or
`description` roles. Other printable strings reached through aligned words
are candidates: an integer can accidentally resemble a pointer. They are
not automatically treated as command definitions.

## Relationships and validation

Vectors contain a pointer and a **byte length**, not an element count.

| Node | Field offsets | Entries |
|---|---|---|
| Menu children | `+0x10`, `+0x14` | Four-byte node pointers. |
| Menu parent | `+0x18` | Menu pointer or zero. |
| Settings properties | `+0x20` or `+0x28`, followed by length | Four-byte parameter pointers. |
| Item-table properties | `+0x60`, `+0x64`, or `+0x68`, followed by length | Parameter pointer and flags, eight bytes total. |
| Command arguments | `+0x10`/`+0x14`, `+0x18`/`+0x1c` | Two separate node-pointer vectors. |
| Alias target | `+0x10` | Another node; calls and paths follow this target. |

Property-vector positions are checked across instances of the same vtable.
Every nonempty candidate must resolve to parameters; ambiguous candidates
are rejected. `property_vector_offset` records the selected relative offset.
The positional/named meaning of the command argument groups is unresolved,
so JSON keeps them separate. Property flags remain numeric.

A path containing ` :: ` denotes an argument or property in the report; it
is not RouterOS syntax. Shared nodes and alias targets can acquire several
paths. Unreachable nodes remain in JSON with an empty path list. Recovered
paths and help do not establish command availability on a running router.

Each image and executable is limited to the smaller of `--max-bytes` and
64 MiB. Limits also cover ELF sections, vtables, nodes, references, candidate
strings, layout probes, and path expansion. Decoded report text is limited
to 16 MiB per image, including repeated text. Collection input rejects
duplicate bases, overlapping mappings, and mixed compatibility words.
Directory discovery skips nonnumeric `.mem` names and follows no symlinks.

The eight original 7.24.2 ARM64 images retain exact parity with the earlier
decoder for all pre-existing decoded fields, command text, and string rows.
New tests generate small ELF and object fixtures for both byte orders,
CPU accessors, moved vectors, older flags, aliases, malformed inputs, and
automatic/add-on extraction. Firmware samples are not checked into the repo.

Defaults, enum/value tables, validator and expression objects, dispatch IDs,
complete flag meanings, and additional header tables still need analysis.
