# Validation

## Console decoder

Validated on 2026-09-05 with Go 1.27.1 on macOS ARM64:

- Decoded all eight console images from each of the supplied 7.24.1 and
  7.24.2 ARM64 packages: 30,034 and 30,035 records respectively.
- Compared every decoded node field, menu/argument/property relationship,
  path, help string, string candidate, and count with the Python research
  decoder. All 60,069 records matched. Empty omitted JSON arrays were
  normalized to empty arrays, and input-path presentation was excluded.
- Verified standalone output ledgers for both eight-image collections.
- Reconstructed both original NPKs from retained sections and checked their
  complete SHA-256 hashes against the extraction metadata. Full extraction
  automatically decoded all eight console modules from each package.
  Derived console records matched standalone output, and both NPK
  extractions passed section reconstruction, source, and artifact checks.
- Synthetic tests cover object families, shared paths, argument/property
  vectors, optional help fields, Latin-1 text, malformed pointers and lengths,
  build mismatch, menu cycles, limits, filename collisions, and missing or
  unsupported parsers. A 10-second decoder fuzz run passed.
- All three modules passed `make test vet`. The changed packages passed
  race tests. The CLI cross-compiled for Windows AMD64, Windows ARM64, and
  Linux AMD64; these builds were not executed on those operating systems.

Console support is restricted to the two examined parser builds. It does
not establish a portable ABI for other RouterOS CPU families or versions.
See [CONSOLE-MEM.md](CONSOLE-MEM.md). Firmware samples and generated output
remain outside the source repository.

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

Runtime tests were executed on macOS ARM64. Cross-compilation does not establish native behavior on the other platforms. The build workflow runs tests and vet on Linux, macOS, and Windows after pushes and pull requests; these hosted checks have not yet run for the initial commit. Release assets are uploaded only for published releases.

Per-input source hashes and verification results are recorded in [validation.json](validation.json). Replay outputs and cross-compiled binaries were generated in temporary directories and removed after validation. Original RouterOS packages and generated extraction trees are excluded from the source repository; normal tests use small synthetic or upstream public-domain fixtures. Use the opt-in corpus tests described in the [README](../README.md) to test additional releases. These results establish support for the sampled formats, not every historical or future RouterOS format.
