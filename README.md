# routeros-extract

`routeros-extract` is a native Go command-line tool for inspecting RouterOS
`.npk` packages and the payloads nested inside them. It has no non-Go external
dependencies.

## Download and get started

Available for **macOS, Linux, Windows, FreeBSD, NetBSD, and OpenBSD** on
**AMD64 (Intel/AMD)** and **ARM64 (including Apple silicon)**. These commands
detect your computer's platform and download the latest release.

**macOS, Linux, and BSD** — downloads directly to `/usr/local/bin` and makes
the binary executable:

```sh
sudo curl -fL --create-dirs "https://github.com/naterator/routeros-extract/releases/latest/download/routeros-extract-$(uname -sm | tr 'A-Z ' 'a-z-' | sed 's/x86_64/amd64/;s/aarch64/arm64/')" -o /usr/local/bin/routeros-extract && sudo chmod 755 /usr/local/bin/routeros-extract
```

**Windows (64-bit PowerShell)** — downloads to the current directory:

```powershell
curl.exe -fL "https://github.com/naterator/routeros-extract/releases/latest/download/routeros-extract-windows-$($env:PROCESSOR_ARCHITECTURE.ToLower()).exe" -o routeros-extract.exe
```

Then run `routeros-extract --help` or
`routeros-extract extract /path/to/package.npk -o extracted`.
On Windows, use `.\routeros-extract.exe` as the command.
The `extract` command also accepts `all_packages*.zip` archives.

You can also [download a release manually](https://github.com/naterator/routeros-extract/releases/latest)
or [build from source](#build-from-source) if no release is available yet.
Each binary has a matching `.sha256` file. `README.md`, `LICENSE`, and `AUTHORS`
are separate release assets. All licenses are also included in the binary;
run `routeros-extract license` to read them.

Run `routeros-extract update` to install a newer stable release, or
`routeros-extract update --check` to check without installing. The updater
verifies SHA-256, checks the binary's platform, and replaces the executable
you ran. For a root-owned Unix installation, use `sudo routeros-extract update`.
Windows may keep the previous executable as `.old` until a later update;
you can delete that backup after the command exits.

## Build from source

Go 1.25 or newer is required. Clone
[`github.com/naterator/routeros-extract`](https://github.com/naterator/routeros-extract)
and build from the checkout; the project uses local copies of two Go modules
under `third_party/`.

Run `make` or `make help` to list every target and build option:

```sh
make
make build
make test
make vet
```

The binary is written to `bin/routeros-extract`. Set `VERSION` when producing
a release build, for example `make build VERSION=0.1.0`. Go's normal
`GOOS`/`GOARCH` variables can be used for cross-compilation; the analyzer does
not depend on the host operating system or CPU architecture.

For a Windows binary, set the output filename explicitly:

```sh
GOOS=windows GOARCH=amd64 make build BINARY=bin/routeros-extract.exe
```

The [build workflow](.github/workflows/build.yml) runs tests and vet for all
three modules on Linux, macOS, and Windows on pushes, pull requests, and
published releases. Releases also build and upload the binaries listed above.
Use semantic version tags such as
`v0.1.0`; the release tag supplies `--version` and the updater's version
comparison. A local `dev` build can also update to the latest stable release.
Binaries are uploaded directly, with an `.exe` extension for Windows;
documentation and license files are uploaded separately.

The [vulnerability workflow](.github/workflows/govulncheck.yml) runs
`govulncheck` for the project and both bundled Go modules on pull requests.
It retains the source workflow's advisory behavior: findings appear as
annotations and in the workflow summary, rather than failing the job solely
because vulnerabilities were found.

## Commands

Run `routeros-extract --help` or a command's `--help` for all flags.

* `inspect NPK...` reads the NPK header and lists every section without
  creating an extraction. `--json` produces machine-readable metadata.
* `extract INPUT... -o DIRECTORY` accepts NPKs and `all_packages*.zip` archives,
  creates one new directory per input, and runs
  the complete extraction: raw sections, file-container records, SquashFS,
  kernel streams, RouterBOOT FWFs, console definitions, WebFig data, ELF/module inventories,
  manifests, and `integrity.json`.
* `kernel IMAGE -o DIRECTORY` scans a boot object for valid XZ or gzip streams,
  recursively follows decoded ELF and CPIO payloads, and writes stream hashes,
  decoded files, and CPIO metadata.
* `firmware FWF -o DIRECTORY` extracts one RouterBOOT `.fwf` envelope.
  Modern NRV2B images have CRC32 and output-length checks; recognized legacy
  images retain their uncompressed payload and explicitly report that format.
* `squashfs IMAGE -o DIRECTORY` exports a SquashFS image, a metadata-preserving
  `rootfs.tar.gz`, a portable browse tree, and manifests.
* `console INPUT... --parser ELF -o DIRECTORY` decodes console `.mem` files
  or searches an extracted rootfs. It writes command paths, parameter and
  help records, strings, and an integrity ledger. The parser must match the
  firmware; supported profiles are currently 7.24.1 ARM64 and 7.24.2 ARM64.
* `analyze DIRECTORY...` adds nested payload reports to an extraction that was
  created with `--no-derived`. The `derived/` directory must not already exist.
* `compare BEFORE AFTER -o DIRECTORY` compares original archive paths,
  regular-file hashes, node types, symlink targets, modes, file containers,
  and RouterBOOT families. It writes JSON, CSV, and Markdown reports.
* `verify DIRECTORY [--source INPUT]` checks the integrity ledger, output
  hashes, and retained sections. ZIP collections verify every contained NPK.
  `--source` also checks the original NPK or ZIP hash.
* `update [--check]` checks GitHub for a newer stable release and installs it,
  unless `--check` is given. It never downgrades a versioned release.
* `license` prints the project license and all third-party notices.

The Cobra root command also supplies `--version` and shell completion. For
example:

```sh
routeros-extract inspect --json routeros-7.24.2-arm64.npk
routeros-extract extract routeros-7.24.2-arm64.npk -o extracted
routeros-extract extract all_packages-arm64-7.24.2.zip -o extracted
routeros-extract verify extracted/routeros-7.24.2-arm64 \
  --source routeros-7.24.2-arm64.npk
routeros-extract console rootfs --parser rootfs/nova/bin/parser \
  -o console-output
routeros-extract completion zsh > _routeros-extract
```

Output directories must be new. This avoids silently mixing artifacts from
different package versions. `--max-bytes` defaults to 512 MiB per input,
filesystem, file container, or recursive kernel scan. ZIP members share an
input-expansion limit, then each contained NPK is extracted independently.
It is not a total output-size or memory quota. `--no-symlinks` preserves link
metadata without creating host links, and is the default on Windows.
Use `extract --no-derived` to stop after filesystem extraction, or
`extract --sections-only` to preserve just the NPK sections and metadata.

## Package coverage

NPK framing and file-container records are architecture agnostic. The parser
preserves unknown and repeated section IDs by index, so an add-on package can
be inspected even when it has no main-system SquashFS, boot kernel, or
RouterBOOT update. A package without one of those layers is reported with the
layers it contains rather than being treated as a malformed main package.

The current validation corpus includes package labels for `arm`, `arm64`,
`x86`, `mipsbe`, `mmips`, `smips`, `ppc`, and `tile`. The package label does
not imply that every file has the same CPU type: RouterOS packages can contain
32-bit userland, 64-bit modules, boot helpers, and raw device firmware
together. ELF headers and the extracted manifests are the authority for an
individual file's architecture.

All 99 NPKs in the supplied test set passed, including 90 add-ons delivered
in eight ZIP archives. See [docs/VALIDATION.md](docs/VALIDATION.md) for versions,
per-architecture counts, reference comparisons, and build checks.

The package reader also preserves PPC file-container variants. If the same
original path occurs with different four-byte variant tags, later records are
stored with a deterministic `.__variant_<tag>` suffix while `archive_path` and
`variant_tag_hex` retain the original relationship.

Supported console images are also decoded automatically into
`derived/console/` when their matching parser is present. Unsupported builds
and add-ons without a parser keep their source images and receive a note.
For a separate add-on, use `console --parser` with the corresponding main
package's parser. See [the console format documentation](docs/CONSOLE-MEM.md)
for supported builds, output files, and the recovered layout.

For an `all_packages.zip`, `extract` preserves each NPK under `npk/` and
extracts it under `packages/<package-name>/`. `zip-metadata.json` lists every
archive member, including ignored non-NPK files. Each add-on is processed
independently, including feature packages and hardware drivers.

## Safety and fidelity

The tool is intended for firmware research and package comparison. It writes
raw input sections beside decoded copies, records Linux metadata in JSON, and
keeps SHA-256 hashes so an extraction can be checked later. It never executes
an extracted install script, ELF, kernel, or firmware image. RouterOS package
and firmware signatures are retained as bytes; they are not authenticated.

Archive paths are validated before writing. Absolute paths, parent traversal,
backslashes, NUL bytes, duplicate paths, and non-directory ancestors are
rejected. Colliding Linux names receive a stable `.__case_<hash>` browse
suffix; names unsupported by common host filesystems receive deterministic
aliases. Original names and Linux metadata remain in the manifests and
retained raw containers; SquashFS also produces a tar archive.
Special device nodes are metadata-only in the browse tree.
The original SquashFS remains authoritative for inode identity, extended
attributes, and other metadata not represented by the browse copy or tar.

The package's install and uninstall script sections are saved as raw bytes and
shown as text where appropriate. They are never run. The same rule applies to
ELF files, kernels, CPIO `init`, FWF output, and WebFig definitions.

The detailed byte layout, boot-object formats, and known architecture matrix
are in [docs/FORMAT.md](docs/FORMAT.md); console memory images are documented
in [docs/CONSOLE-MEM.md](docs/CONSOLE-MEM.md). The bundled XZ changes and attribution
are in [third_party/xz/LOCAL_CHANGES.md](third_party/xz/LOCAL_CHANGES.md), and
dependency notices are in [LICENSE](LICENSE).

## Replay validation

Use a directory containing NPK samples, or a single NPK:

```sh
go run ./tools/corpus -corpus /path/to/samples -output /path/to/new-results
ROUTEROS_TEST_CORPUS=/path/to/samples go test ./internal/extract -run TestCorpus -v
```

The corpus helper writes a JSON report and continues after individual failures.
Set `ROUTEROS_PYTHON_REFERENCE` to the earlier Python extraction parent to also
compare those manifests and derived payload hashes. Normal `make test` uses
small synthetic fixtures and requires no RouterOS downloads or external tools.

## License

The project's original code is licensed under [BSD-3-Clause](LICENSE).
Bundled and linked components retain their MIT, BSD, 0BSD, or Apache-2.0
licenses. All license texts, attribution, and third-party notices are
consolidated in [LICENSE](LICENSE), which is also included in every binary.
Include that file when redistributing source or binaries.

After editing `LICENSE`, run `go generate ./internal/license` to refresh
the copy compiled into the CLI.

The license covers the tool's code, not RouterOS firmware or extracted
payloads. The NRV2B and LZO implementations use permissively licensed
sources; their provenance is recorded in the third-party notices.
