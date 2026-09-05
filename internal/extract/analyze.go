// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"bytes"
	"compress/gzip"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/naterator/routeros-extract/internal/console"
)

type ELFInfo struct {
	Path    string `json:"path"`
	Bits    int    `json:"bits"`
	Machine string `json:"machine"`
	Type    string `json:"type"`
}
type ModuleInfo struct {
	Path     string   `json:"path"`
	Metadata []string `json:"metadata"`
}
type WebInfo struct {
	Source string `json:"source"`
	File   string `json:"file"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}
type Analysis struct {
	Kernels            int            `json:"kernels"`
	KernelStreams      int            `json:"kernel_streams"`
	RouterBOOTImages   int            `json:"routerboot_images"`
	WebfigDecodedFiles int            `json:"webfig_decoded_files"`
	KernelModules      int            `json:"kernel_modules"`
	ConsoleFiles       int            `json:"console_files"`
	ConsoleNodes       int            `json:"console_nodes"`
	ELFCounts          map[string]int `json:"elf_counts"`
	Notes              []string       `json:"notes"`
}

func describeELF(data []byte, name string) (ELFInfo, string, error) {
	f, e := elf.NewFile(bytes.NewReader(data))
	if e != nil {
		return ELFInfo{}, "", e
	}
	defer f.Close()
	bits := 32
	if f.Class == elf.ELFCLASS64 {
		bits = 64
	}
	machine := map[elf.Machine]string{elf.EM_ARM: "ARM", elf.EM_AARCH64: "AArch64", elf.EM_386: "x86", elf.EM_X86_64: "x86-64", elf.EM_MIPS: "MIPS", elf.EM_PPC: "PowerPC", elf.EM_PPC64: "PowerPC64", elf.EM_TILEGX: "TILE-Gx"}[f.Machine]
	if machine == "" {
		machine = f.Machine.String()
	}
	kind := map[elf.Type]string{elf.ET_REL: "relocatable", elf.ET_EXEC: "executable", elf.ET_DYN: "shared_object"}[f.Type]
	if kind == "" {
		kind = f.Type.String()
	}
	var report strings.Builder
	fmt.Fprintf(&report, "Path: %s\nClass: %s\nData: %s\nMachine: %s\nType: %s\nEntry: %#x\nOSABI: %s\n\nSections:\n", name, f.Class, f.Data, f.Machine, f.Type, f.Entry, f.OSABI)
	for _, s := range f.Sections {
		fmt.Fprintf(&report, "%-28s %-18s address=%#x offset=%#x size=%#x flags=%s\n", s.Name, s.Type, s.Addr, s.Offset, s.Size, s.Flags)
	}
	report.WriteString("\nProgram headers:\n")
	for _, p := range f.Progs {
		fmt.Fprintf(&report, "%s offset=%#x vaddr=%#x filesz=%#x memsz=%#x flags=%s\n", p.Type, p.Off, p.Vaddr, p.Filesz, p.Memsz, p.Flags)
	}
	for _, tag := range []elf.DynTag{elf.DT_NEEDED, elf.DT_SONAME, elf.DT_RPATH, elf.DT_RUNPATH} {
		vals, err := f.DynString(tag)
		if err != nil {
			return ELFInfo{}, "", err
		}
		for _, v := range vals {
			fmt.Fprintf(&report, "%s: %s\n", tag, v)
		}
	}
	return ELFInfo{Path: name, Bits: bits, Machine: machine, Type: kind}, report.String(), nil
}

func streamCount(r KernelReport) int {
	n := len(r.Streams)
	for _, s := range r.Streams {
		if s.Nested != nil {
			n += streamCount(*s.Nested)
		}
	}
	return n
}

func hasELFMagic(b []byte) bool {
	return len(b) >= 4 && bytes.Equal(b[:4], []byte{0x7f, 'E', 'L', 'F'})
}

func analysisWarning(kind, source string, err error) string {
	return fmt.Sprintf("%s %s: %v; original retained", kind, source, err)
}

func analyze(d *disk, m Metadata, opt Options) (Analysis, error) {
	summary := Analysis{ELFCounts: map[string]int{}, Notes: []string{}}
	if e := d.Mkdir("derived", 0755); e != nil {
		return summary, fmt.Errorf("derived output must not exist: %w", e)
	}
	boots := []FirmwareInfo{}
	bootFiles := map[string]bool{}
	web := []WebInfo{}
	elves := []ELFInfo{}
	modules := []ModuleInfo{}
	consoleImages := []consoleFile{}
	consoleParsers := map[string]consoleParser{}
	for _, s := range m.Sections {
		if s.ExtractedTo == "" {
			continue
		}
		entries, e := readJSON[[]Entry](d, s.ExtractedTo+"-manifest.json")
		if e != nil {
			return summary, e
		}
		for _, item := range entries {
			if item.Type != "file" {
				continue
			}
			if e = safePath(item.Path); e != nil {
				return summary, e
			}
			stored := item.StoredPath
			if stored == "" {
				stored = item.Path
			}
			if e = safePath(stored); e != nil {
				return summary, e
			}
			source := path.Join(s.ExtractedTo, stored)
			b, e := d.read(source, opt.limit())
			if e != nil {
				return summary, e
			}
			if digest(b) != item.SHA256 {
				return summary, fmt.Errorf("manifest hash mismatch before analysis: %s", source)
			}
			if item.Path == "nova/bin/parser" {
				p, err := console.NewParser(b)
				consoleParsers[s.ExtractedTo] = consoleParser{p, err}
			}
			if base, ok := isConsoleImage(item.Path); ok {
				consoleImages = append(consoleImages, consoleFile{source: source, section: s.ExtractedTo, sha256: item.SHA256, base: base})
			}
			if s.Type == 4 && (strings.HasPrefix(item.Path, "boot/kernel") || strings.HasPrefix(item.Path, "boot/initrd") || strings.HasPrefix(path.Base(item.Path), "vmlinuz") || strings.HasSuffix(strings.ToLower(item.Path), ".efi")) {
				summary.Kernels++
				folder := path.Join("derived", folderName("kernel", summary.Kernels))
				r, e := kernelData(b, d, folder, opt, 0)
				if e != nil {
					return summary, fmt.Errorf("kernel %s: %w", source, e)
				}
				summary.KernelStreams += streamCount(r)
				if len(r.Streams) == 0 && len(r.CPIOArchives) == 0 {
					summary.Notes = append(summary.Notes, "No supported compressed payload or newc archive found in "+source+"; original retained")
				}
				if hasELFMagic(b) {
					if _, report, e := describeELF(b, item.Path); e != nil {
						summary.Notes = append(summary.Notes, analysisWarning("ELF", source, e))
					} else if e = d.put(path.Join("derived/elf", folderName("kernel", summary.Kernels)+".txt"), []byte(report)); e != nil {
						return summary, e
					}
				}
			}
			if strings.HasSuffix(item.Path, ".fwf") {
				out, info, e := DecodeFirmware(b, opt)
				if e != nil {
					return summary, fmt.Errorf("firmware %s: %w", source, e)
				}
				name := portableComponent(strings.TrimSuffix(path.Base(item.Path), ".fwf"))
				// Preserve the simple names of single-rootfs packages; disambiguate repeats.
				file := name + ".bin"
				for attempt := 1; bootFiles[portablePathKey(file)]; attempt++ {
					file = portableComponent(fmt.Sprintf("%s-%s-%d", name, digest([]byte(source))[:8], attempt)) + ".bin"
				}
				bootFiles[portablePathKey(file)] = true
				info.Source = source
				info.File = file
				boots = append(boots, info)
				if e = d.put(path.Join("derived/routerboot", file), out); e != nil {
					return summary, e
				}
				if e = d.put(path.Join("derived/routerboot", strings.TrimSuffix(file, ".bin")+".strings.txt"), stringDump(out)); e != nil {
					return summary, e
				}
			}
			if strings.HasSuffix(item.Path, ".gz") && strings.Contains("/"+item.Path, "/webfig/") {
				z, e := gzip.NewReader(bytes.NewReader(b))
				if e != nil {
					summary.Notes = append(summary.Notes, analysisWarning("WebFig", source, e))
					continue
				}
				out, readErr := io.ReadAll(io.LimitReader(z, opt.limit()+1))
				closeErr := z.Close()
				if int64(len(out)) > opt.limit() {
					return summary, fmt.Errorf("WebFig %s: decoded size exceeds limit of %d bytes", source, opt.limit())
				}
				if e = errors.Join(readErr, closeErr); e != nil {
					summary.Notes = append(summary.Notes, analysisWarning("WebFig", source, e))
					continue
				}
				name := path.Join("webfig", strings.TrimSuffix(stored, ".gz"))
				if s.ExtractedTo != "rootfs" {
					name = path.Join("webfig", s.ExtractedTo, strings.TrimSuffix(stored, ".gz"))
				}
				if e = d.put(path.Join("derived", name), out); e != nil {
					return summary, e
				}
				web = append(web, WebInfo{Source: item.Path, File: name, Size: len(out), SHA256: digest(out)})
			}
			if s.Type != 0x15 {
				continue
			}
			if hasELFMagic(b) {
				info, report, e := describeELF(b, item.Path)
				if e != nil {
					summary.Notes = append(summary.Notes, analysisWarning("ELF", source, e))
				} else {
					elves = append(elves, info)
					summary.ELFCounts[fmt.Sprintf("%d-bit %s %s", info.Bits, info.Machine, info.Type)]++
					if e = d.put(path.Join("derived/elf", s.ExtractedTo, stored+".txt"), []byte(report)); e != nil {
						return summary, e
					}
				}
			}
			if strings.HasSuffix(item.Path, ".ko") {
				info := ModuleInfo{Path: item.Path, Metadata: []string{}}
				// .modinfo is NUL-delimited. Keep only the fields the Python analyzer exported.
				for _, field := range bytes.Split(b, []byte{0}) {
					for _, key := range []string{"vermagic=", "description=", "license=", "depends=", "name="} {
						if strings.HasPrefix(string(field), key) {
							info.Metadata = append(info.Metadata, strings.ToValidUTF8(string(field), "�"))
							break
						}
					}
				}
				modules = append(modules, info)
			}
			for _, evidence := range []string{"sbin/sysinit", "nova/bin/loader", "nova/bin/www", "nova/bin/login", "lib/libc.so"} {
				if item.Path == evidence {
					name := path.Join("derived/strings", path.Base(item.Path)+".txt")
					if s.ExtractedTo != "rootfs" {
						name = path.Join("derived/strings", s.ExtractedTo, path.Base(item.Path)+".txt")
					}
					if e = d.put(name, stringDump(b)); e != nil {
						return summary, e
					}
				}
			}
		}
	}
	if b, e := d.read("derived/kernel/initramfs/init", opt.limit()); e == nil {
		if e = d.put("derived/strings/init.txt", stringDump(b)); e != nil {
			return summary, e
		}
	}
	summary.RouterBOOTImages = len(boots)
	if err := analyzeConsole(d, consoleImages, consoleParsers, opt, &summary); err != nil {
		return summary, err
	}
	summary.WebfigDecodedFiles = len(web)
	summary.KernelModules = len(modules)
	if summary.Kernels == 0 {
		summary.Notes = append(summary.Notes, "Package contains no boot kernel")
	}
	for name, v := range map[string]any{"derived/routerboot/manifest.json": boots, "derived/webfig/manifest.json": web, "derived/elf-inventory.json": elves, "derived/kernel-modules.json": modules, "derived/summary.json": summary} {
		if e := d.json(name, v); e != nil {
			return summary, e
		}
	}
	return summary, nil
}

func Analyze(directory string, opt Options) (Analysis, error) {
	d, e := openDisk(directory)
	if e != nil {
		return Analysis{}, e
	}
	defer d.Close()
	if _, err := d.Lstat("integrity.json"); err == nil {
		if _, err = Verify(directory, ""); err != nil {
			return Analysis{}, fmt.Errorf("verify extraction before analysis: %w", err)
		}
	}
	m, e := readJSON[Metadata](d, "metadata.json")
	if e != nil {
		return Analysis{}, e
	}
	r, e := analyze(d, m, opt)
	if e != nil {
		return r, e
	}
	return r, writeIntegrity(d)
}
