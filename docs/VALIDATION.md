# Validation

## Releases through 7.25.2

Validated on 2026-11-23 with Go 1.27.4 on macOS ARM64. The replay covers
the 7.24.2 baseline, the 7.24.3 through 7.24.7 patch releases, and 7.25,
7.25.1, and 7.25.2. The 7.24.6 and 7.24.7 builds came from the long-term
channel. [MikroTik 7.24 release history](https://mikrotik.com/download/changelogs?channelFilter=&versionFilter=7.24)
and [7.25 release history](https://mikrotik.com/download/changelogs?channelFilter=stable&versionFilter=7.25).

Each release was tested with the official main NPK and `all_packages` ZIP
for ARM, ARM64, MIPSBE, MMIPS, PPC, SMIPS, TILE, and x86. The replay ran
full CLI extraction with `--no-symlinks` and `verify --source`, including
artifact hashes and byte-for-byte NPK section round trips. Each add-on ZIP
used the matching main package's console parser. The console report was
checked against every numeric `.mem` image in the filesystem manifests,
including add-on images. All 16 downloads for the 7.24.2 baseline matched
the previously recorded hashes. [Original validation results](validation.json)

Every NPK reported the expected package version. The 7.25 release stores a
zero patch field, so the NPK metadata reports `7.25.0`.

The initial 1.1.1 replay found one skipped image in each of the 7.24.6 MIPSBE
and SMIPS main packages. A word in help text happened to equal a console
vtable address. The decoder now checks the name pointer against the image
mapping before treating a speculative vtable match as a node. A full 7.24.6
CLI retest passed after the fix. A replay of the console decoder across the
entire matrix also passed, with byte-for-byte matches in the node JSON,
command listings, and strings for all 1,294 previously decoded images.
`make test vet` passed for all three Go modules. The console regression tests
cover coincidental vtable matches and unresolved references to skipped candidates.

The replay recorded the source SHA-256 values and counts for each input.
[Machine-readable results](release-validation.json)

| RouterOS | Main NPKs | Add-on NPKs | Console images | Decoded nodes |
| --- | ---: | ---: | ---: | ---: |
| 7.24.2 | 8 | 90 | 144 | 278,668 |
| 7.24.3 | 8 | 90 | 144 | 278,724 |
| 7.24.4 | 8 | 90 | 144 | 278,724 |
| 7.24.5 | 8 | 90 | 144 | 278,724 |
| 7.24.6 | 8 | 90 | 144 | 278,724 |
| 7.24.7 | 8 | 90 | 144 | 278,724 |
| 7.25 | 8 | 90 | 144 | 281,156 |
| 7.25.1 | 8 | 90 | 144 | 281,156 |
| 7.25.2 | 8 | 90 | 144 | 281,156 |

On ARM64, standalone console decoding also passed for 7.25.2. The
comparison reports for 7.24.2 to 7.25.2 and 7.25 to 7.25.2 passed output
integrity verification.

## Console decoder

Validated on 2026-09-09 with Go 1.27.1 on macOS ARM64:

- All 98 NPKs in the 7.24.2 main-package/add-on corpus passed full CLI
  extraction and integrity verification. All 144 console images decoded,
  producing 278,668 nodes across ARM, ARM64, MIPSBE, MMIPS, PPC, SMIPS,
  TILE, and x86. Add-ons used the matching main executable through
  `--console-parser`.
- The supplied ARM64 and x86 installer ISOs contained 28 NPKs in total;
  each matched an already tested package byte for byte. The install-image
  ZIP's FAT filesystem contained another 11 matching NPKs.
- The console-specific corpus covered 773 images from 12 releases: 701
  decoded. The 71 images from 6.49.19 require a different virtual-method
  layout. One 7.1.5 TILE image requires another alias recognizer. These
  cases report errors and retain their original files during extraction.
- All examined 7.20.x, 7.21.x, 7.22.1, 7.23.4, 7.24.1, and 7.24.2 images
  decoded. No version-number or binary-hash allowlist is used.
- The original eight 7.24.2 ARM64 images matched the previous decoder for
  every pre-existing decoded field, command listing, and string row.
  New layout metadata and property-vector offsets were excluded from that
  comparison, as were input-path and parser-profile presentation.
- Synthetic fixtures cover supported CPU accessors, both byte orders,
  relocated vtables, changed compatibility words, older header/flag layouts,
  moved and ambiguous property vectors, aliases, and malformed ELF metadata.
  Integration tests exercise automatic and add-on analysis and output
  verification. Firmware data is not checked into the repository.

Input hashes, architecture coverage, counts, and explicit unsupported cases
are recorded in [console-validation.json](console-validation.json).
See [CONSOLE-MEM.md](CONSOLE-MEM.md) for the recovered format and limits.

The earlier 2026-09-05 ARM64 validation compared 60,069 decoded records
from 7.24.1 and 7.24.2 against the research Python decoder, including all
node fields, graph relationships, paths, help, strings, and counts. Those
records matched, and both complete NPK extractions passed source and
integrity verification. That historical Python comparison has not been
repeated for the newly added architectures and releases.

## Existing extraction corpus

Validated on 2026-09-04 with Go 1.27.1 on macOS arm64. All 17 supplied inputs passed: nine core NPKs and eight ZIP archives containing 90 add-on NPKs (99 NPK extractions total).

| RouterOS architecture | Core NPK | Add-on NPKs from ZIP | Result |
|---|---:|---:|---|
| arm | 7.24.2 | 18 | Passed |
| arm64 | 7.24.2 | 18 | Passed |
| mipsbe | 7.24.2 | 9 | Passed |
| mmips | 7.24.2 | 10 | Passed |
| ppc | 7.24.2 | 9 | Passed |
| smips | 7.24.2 | 3 | Passed |
| tile | 7.24.2 | 11 | Passed |
| x86 | 7.24.2 | 12 | Passed |

The additional core input was RouterOS 7.24.1 arm64. An earlier validation compared both ARM64 versions with the Python extraction by original path, mode, owner, symlink target, file bytes, kernel streams, RouterBOOT payloads, WebFig definitions, and selected strings; they matched. Each root filesystem contains 819 entries. The Go scanner also found the built-in CPIO archive inside the decompressed Linux Image. The final readiness replay checks extraction, retained source bytes, and artifact integrity; it does not repeat the historical Python comparison.

The 7.24.2 cores yielded 47 RouterBOOT files: 22 NRV2B envelopes with verified CRC32 and 25 recognized legacy images preserved byte-for-byte after the 32-byte header. PowerPC retained all four boot/kernel variants. TILE retained its uncompressed Linux ELF and extracted both embedded and separate initramfs. x86 extraction reached the ELF64 kernel and its embedded initramfs through BOOTX64.EFI.

The comparison between the supplied ARM64 versions reproduced 55 changed files, 14 added paths, 14 removed paths, one changed symlink, and 749 unchanged paths. All 13 paired RouterBOOT families differ.

Release-readiness checks passed:

- Unit tests for all three modules on Go 1.25.13, the tested minimum toolchain.
- Unit tests with the race detector and `go vet` for all three modules on Go 1.27.1.
- Regression tests for recursive kernel and CPIO hardlink expansion limits, malformed SquashFS blocks and tables, portable filenames, bounded metadata, and incidental malformed ELF/WebFig files.
- Bundled XZ tests, including an independently encoded ARM64 BCJ fixture, and a 20-second NRV2B fuzz run.
- `govulncheck` for all three modules: no known vulnerabilities found.
- Workflow validation with `actionlint` and source scanning with Gitleaks: no findings.
- All 12 release builds: macOS, Linux, Windows, FreeBSD, NetBSD, and OpenBSD, each on AMD64 and ARM64, with CGO disabled. The native macOS ARM64 binary also passed version, help, and embedded-license checks.

The September runtime checks ran on macOS ARM64. Checks for the other platforms
in that run covered cross-compilation. The results predate the first hosted CI
run. The build workflow runs tests and vet on Linux, macOS, and Windows after
pushes and pull requests and uploads release assets on publication.

Per-input source hashes and verification results are recorded in [validation.json](validation.json). Replay outputs and cross-compiled binaries were generated in temporary directories and removed after validation. Original RouterOS packages and generated extraction trees are excluded from the source repository; normal tests use small synthetic or upstream public-domain fixtures. Use the opt-in corpus tests described in the [README](../README.md) to test additional releases. These results establish support for the sampled formats, not every historical or future RouterOS format.
