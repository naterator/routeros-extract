// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/naterator/routeros-extract/internal/console"
)

type ConsoleReport struct {
	Parser        string             `json:"parser"`
	ParserSHA256  string             `json:"parser_sha256"`
	ParserProfile string             `json:"parser_profile"`
	Modules       []console.Metadata `json:"modules"`
	Skipped       []string           `json:"skipped_non_numeric_filenames"`
}

type consoleFile struct {
	source, section, sha256 string
	base                    uint32
}

func consoleOptions(opt Options) Options {
	opt.MaxBytes = min(opt.limit(), console.MaxInputBytes)
	return opt
}

// consoleFiles walks directories without following symlinks. Explicit files
// must have valid mapping filenames; unrelated files in a rootfs are ignored.
func consoleFiles(inputs []string) ([]consoleFile, []string, error) {
	files := []consoleFile{}
	skipped := []string{}
	seenPaths := map[string]bool{}
	seenBases := map[uint32]string{}
	visits := 0
	add := func(source string, explicit bool) error {
		base, err := console.BaseName(filepath.Base(source))
		if err != nil {
			if explicit {
				return fmt.Errorf("%s: %w", source, err)
			}
			if strings.HasSuffix(source, ".mem") {
				skipped = append(skipped, source)
			}
			return nil
		}
		source, err = filepath.Abs(source)
		if err != nil {
			return err
		}
		if seenPaths[source] {
			return nil
		}
		if previous, found := seenBases[base]; found {
			return fmt.Errorf("duplicate console mapping base %#x: %s and %s; decode each firmware separately", base, previous, source)
		}
		if len(files) >= 256 {
			return errors.New("too many console images (limit 256)")
		}
		seenPaths[source], seenBases[base] = true, source
		files = append(files, consoleFile{source: source, base: base})
		return nil
	}
	for _, input := range inputs {
		info, err := os.Lstat(input)
		if err != nil {
			return nil, nil, err
		}
		if !info.IsDir() {
			if err := add(input, true); err != nil {
				return nil, nil, err
			}
			continue
		}
		err = filepath.WalkDir(input, func(name string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			visits++
			if visits > MaxEntries {
				return errors.New("too many entries while searching for console images")
			}
			if entry.IsDir() || !entry.Type().IsRegular() {
				return nil
			}
			return add(name, false)
		})
		if err != nil {
			return nil, nil, err
		}
	}
	if len(files) == 0 {
		return nil, nil, errors.New("no numeric .mem files found")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].base < files[j].base })
	sort.Strings(skipped)
	return files, skipped, nil
}

func writeConsoleImage(d *disk, folder string, image *console.Image) error {
	if err := d.json(path.Join(folder, "nodes.json"), image); err != nil {
		return err
	}
	if err := d.put(path.Join(folder, "commands.txt"), image.Commands()); err != nil {
		return err
	}
	return d.put(path.Join(folder, "strings.tsv"), image.StringsTSV())
}

// Console decodes one firmware's images with its matching parser. Outputs
// retain the source images, decoded data, and an integrity ledger in a new directory.
func Console(inputs []string, parserSource, destination string, opt Options) (ConsoleReport, error) {
	report := ConsoleReport{Parser: parserSource, Modules: []console.Metadata{}, Skipped: []string{}}
	files, skipped, err := consoleFiles(inputs)
	if err != nil {
		return report, err
	}
	report.Skipped = skipped
	b, err := ReadInput(parserSource, consoleOptions(opt))
	if err != nil {
		return report, err
	}
	parser, err := console.NewParser(b)
	if err != nil {
		return report, err
	}
	report.ParserSHA256, report.ParserProfile = parser.SHA256, parser.Profile
	// Validate the whole collection before creating output. Retain metadata,
	// rather than every object graph, so memory does not grow with module count.
	var end uint64
	for _, file := range files {
		b, err := ReadInput(file.source, consoleOptions(opt))
		if err != nil {
			return report, err
		}
		if uint64(file.base) < end {
			return report, errors.New("overlapping console image mappings")
		}
		end = uint64(file.base) + uint64(len(b))
		image, err := console.Decode(b, file.base, parser, file.source)
		if err != nil {
			return report, fmt.Errorf("%s: %w", file.source, err)
		}
		report.Modules = append(report.Modules, image.Metadata)
	}
	d, err := newDisk(destination)
	if err != nil {
		return report, err
	}
	defer d.Close()
	for i, file := range files {
		folder := strconv.FormatUint(uint64(file.base), 10)
		b, err := ReadInput(file.source, consoleOptions(opt))
		if err != nil {
			return report, err
		}
		if digest(b) != report.Modules[i].SHA256 {
			return report, fmt.Errorf("console input changed during extraction: %s", file.source)
		}
		image, err := console.Decode(b, file.base, parser, file.source)
		if err != nil {
			return report, err
		}
		if err = d.put(path.Join(folder, folder+".mem"), b); err != nil {
			return report, err
		}
		if err = writeConsoleImage(d, folder, image); err != nil {
			return report, err
		}
	}
	if err = d.json("index.json", report); err != nil {
		return report, err
	}
	return report, writeIntegrity(d)
}

type consoleParser struct {
	parser *console.Parser
	err    error
}

type consoleAnalysis struct {
	Source   string            `json:"source"`
	Decoded  bool              `json:"decoded"`
	Output   string            `json:"output,omitempty"`
	Reason   string            `json:"reason,omitempty"`
	Metadata *console.Metadata `json:"metadata,omitempty"`
}

func isConsoleImage(name string) (uint32, bool) {
	if !strings.HasSuffix("/"+path.Dir(name), "/nova/lib/console") {
		return 0, false
	}
	base, err := console.BaseName(path.Base(name))
	return base, err == nil
}

func analyzeConsole(d *disk, files []consoleFile, parsers map[string]consoleParser, opt Options, summary *Analysis) error {
	if len(files) == 0 {
		return nil
	}
	reports := []consoleAnalysis{}
	used := map[string]bool{}
	for _, file := range files {
		record := consoleAnalysis{Source: file.source}
		p, found := parsers[file.section]
		var image *console.Image
		err := p.err
		if !found {
			err = errors.New("matching nova/bin/parser is absent; use console --parser with the main package's parser")
		}
		folder := path.Join("derived/console", file.section, strconv.FormatUint(uint64(file.base), 10))
		if err == nil && used[folder] {
			err = errors.New("duplicate console mapping base in this filesystem")
		}
		if err == nil {
			b, readErr := d.read(file.source, consoleOptions(opt).limit())
			if readErr != nil {
				err = readErr
			} else {
				if digest(b) != file.sha256 {
					return fmt.Errorf("manifest hash mismatch before console analysis: %s", file.source)
				}
				image, err = console.Decode(b, file.base, p.parser, file.source)
			}
		}
		if err != nil {
			record.Reason = err.Error()
			summary.Notes = append(summary.Notes, analysisWarning("Console", file.source, err))
		} else {
			if err = writeConsoleImage(d, folder, image); err != nil {
				return err
			}
			used[folder] = true
			record.Decoded, record.Output, record.Metadata = true, folder, &image.Metadata
			summary.ConsoleFiles++
			summary.ConsoleNodes += len(image.Nodes)
		}
		reports = append(reports, record)
	}
	return d.json("derived/console/manifest.json", reports)
}
