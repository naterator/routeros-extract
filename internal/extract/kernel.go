// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"bytes"
	"compress/gzip"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/mikelolasagasti/xz"
)

type Stream struct {
	Offset         int           `json:"offset"`
	OffsetHex      string        `json:"offset_hex"`
	Compression    string        `json:"compression"`
	CompressedSize int           `json:"compressed_size"`
	DecodedSize    int           `json:"decoded_size"`
	File           string        `json:"file"`
	SHA256         string        `json:"sha256"`
	Check          int           `json:"xz_integrity_check,omitempty"`
	Banners        []string      `json:"linux_banners,omitempty"`
	Nested         *KernelReport `json:"nested,omitempty"`
}
type Candidate struct {
	Offset      int    `json:"offset"`
	Compression string `json:"compression"`
	Valid       bool   `json:"valid_stream"`
	Error       string `json:"error,omitempty"`
}
type KernelReport struct {
	InputFormat        string      `json:"input_format"`
	SourceSHA256       string      `json:"source_sha256"`
	Streams            []Stream    `json:"streams"`
	Rejected           []Candidate `json:"rejected_magic_candidates"`
	CPIOArchives       []string    `json:"cpio_archives,omitempty"`
	InputBanners       []string    `json:"input_linux_banners,omitempty"`
	UncompressedKernel string      `json:"uncompressed_kernel_file,omitempty"`
}

var xzMagic = []byte{0xfd, '7', 'z', 'X', 'Z', 0}
var gzMagic = []byte{0x1f, 0x8b, 8}
var bannerRE = regexp.MustCompile(`Linux version [^\x00\n]{1,300}`)

var errKernelBudget = errors.New("decoded kernel payload exceeds byte limit")

func inputFormat(b []byte) string {
	if len(b) >= 4 && string(b[:4]) == "\x7fELF" {
		f, e := elf.NewFile(bytes.NewReader(b))
		if e == nil {
			defer f.Close()
			return fmt.Sprintf("%s %s %s", f.Class, f.Machine, f.Type)
		}
		return "ELF"
	}
	if len(b) >= 60 && string(b[56:60]) == "ARM\x64" {
		return "Linux ARM64 Image"
	}
	if len(b) >= 0x206 && string(b[0x202:0x206]) == "HdrS" {
		return "Linux x86 bzImage"
	}
	if len(b) >= 40 && bytes.Equal(b[36:40], []byte{0x18, 0x28, 0x6f, 0x01}) {
		return "Linux ARM zImage"
	}
	if len(b) >= 2 && string(b[:2]) == "MZ" {
		return "PE/COFF boot image"
	}
	if isCPIO(b) {
		return "newc CPIO"
	}
	if bytes.HasPrefix(b, xzMagic) {
		return "XZ stream"
	}
	if bytes.HasPrefix(b, gzMagic) {
		return "gzip stream"
	}
	return "binary"
}
func isCPIO(b []byte) bool {
	return len(b) >= 6 && (string(b[:6]) == "070701" || string(b[:6]) == "070702")
}

func decodeXZ(b []byte, max int64) (out []byte, consumed, check int, err error) {
	z, e := xz.NewReader(bytes.NewReader(b), 64<<20)
	if e != nil {
		return nil, 0, 0, e
	}
	z.StopAtStreamEnd()
	out, e = bounded(z, max)
	if e != nil {
		return nil, 0, 0, markKernelDecodeLimit(e)
	}
	return out, int(z.InputConsumed()), int(z.CheckType), nil
}
func decodeGzip(b []byte, max int64) (out []byte, consumed int, err error) {
	r := bytes.NewReader(b)
	z, e := gzip.NewReader(r)
	if e != nil {
		return nil, 0, e
	}
	z.Multistream(false)
	out, e = bounded(z, max)
	e = errors.Join(e, z.Close())
	e = markKernelDecodeLimit(e)
	return out, len(b) - r.Len(), e
}

func markKernelDecodeLimit(err error) error {
	if errors.Is(err, errByteLimit) {
		return fmt.Errorf("%w: %v", errKernelBudget, err)
	}
	return err
}

// parseCPIO returns a single newc archive and its exact trailer end. Callers can
// distinguish archive padding from additional data in a larger kernel image.
func parseCPIO(b []byte, opt Options) ([]Entry, int, error) {
	entries := []Entry{}
	var total int64
	for off := 0; off < len(b); {
		if len(b)-off < 110 || !isCPIO(b[off:]) {
			return nil, 0, errors.New("invalid/truncated newc header")
		}
		vals := [13]uint32{}
		for i := range vals {
			v, e := strconv.ParseUint(string(b[off+6+i*8:off+14+i*8]), 16, 32)
			if e != nil {
				return nil, 0, errors.New("invalid newc hexadecimal field")
			}
			vals[i] = uint32(v)
		}
		ns := uint64(vals[11])
		ne := uint64(off) + 110 + ns
		if ns < 1 || ne > uint64(len(b)) || b[ne-1] != 0 {
			return nil, 0, errors.New("invalid CPIO filename")
		}
		start := (ne + 3) &^ uint64(3)
		end := start + uint64(vals[6])
		next := (end + 3) &^ uint64(3)
		if end > uint64(len(b)) || next > uint64(len(b)) {
			return nil, 0, errors.New("CPIO content exceeds archive length")
		}
		name := string(b[uint64(off)+110 : ne-1])
		data := b[start:end]
		if string(b[off:off+6]) == "070702" {
			var sum uint32
			for _, v := range data {
				sum += uint32(v)
			}
			if sum != vals[12] {
				return nil, 0, errors.New("CPIO checksum mismatch")
			}
		}
		if name == "TRAILER!!!" {
			if vals[6] != 0 {
				return nil, 0, errors.New("CPIO trailer has content")
			}
			planned, e := planPaths(entries)
			return planned, int(next), e
		}
		name = strings.TrimPrefix(name, "./")
		if name == "." && vals[1]&0170000 == 0040000 {
			off = int(next)
			continue
		}
		if e := safePath(name); e != nil {
			return nil, 0, e
		}
		if len(entries) >= MaxEntries {
			return nil, 0, errors.New("too many CPIO entries")
		}
		total += int64(vals[6])
		if total > opt.limit() {
			return nil, 0, errors.New("CPIO expanded size exceeds limit")
		}
		v := Entry{Path: name, Mode: octal(vals[1]), UID: int(vals[2]), GID: int(vals[3]), Mtime: utc(vals[5]), Size: int64(vals[6]), RdevMajor: vals[9], RdevMinor: vals[10], Inode: vals[0], Links: vals[4], data: data}
		switch vals[1] & 0170000 {
		case 0040000:
			v.Type = "directory"
		case 0100000:
			v.Type = "file"
			v.SHA256 = digest(data)
		case 0120000:
			if len(data) > maxInlineMetadataBytes {
				return nil, 0, fmt.Errorf("CPIO symlink %q target exceeds %d bytes", name, maxInlineMetadataBytes)
			}
			if bytes.IndexByte(data, 0) >= 0 {
				return nil, 0, fmt.Errorf("CPIO symlink %q target contains NUL", name)
			}
			v.Type = "symlink_metadata_only"
			v.Target = string(data)
		default:
			v.Type = "special_metadata_only"
		}
		entries = append(entries, v)
		off = int(next)
	}
	return nil, 0, errors.New("CPIO trailer missing")
}

func extractCPIO(b []byte, d *disk, folder string, opt Options) error {
	entries, end, e := parseCPIO(b, opt)
	if e != nil {
		return e
	}
	for _, v := range b[end:] {
		if v != 0 {
			return errors.New("unexpected data after CPIO trailer")
		}
	}
	// Resolve newc hardlinks whose content appears once in the inode group.
	content := map[uint32][]byte{}
	for _, v := range entries {
		if v.Type == "file" && v.Links > 1 && len(v.data) > 0 {
			content[v.Inode] = v.data
		}
	}
	for i := range entries {
		v := &entries[i]
		if v.Type == "file" && v.Links > 1 && v.Size == 0 {
			if b, ok := content[v.Inode]; ok {
				v.data = b
				v.Size = int64(len(b))
				v.SHA256 = digest(b)
			}
		}
	}
	var materialized int64
	for _, v := range entries {
		if v.Type != "file" {
			continue
		}
		n := int64(len(v.data))
		if n > opt.limit()-materialized {
			return errors.New("CPIO materialized file data exceeds byte limit")
		}
		materialized += n
	}
	if e = writeEntries(d, folder, entries, true); e != nil {
		return e
	}
	return d.json(folder+"-manifest.json", entries)
}

type kernelBudget struct {
	limit int64
	used  int64
}

func (b *kernelBudget) remaining() int64 {
	if b.used >= b.limit {
		return 0
	}
	return b.limit - b.used
}

func (b *kernelBudget) reserve(n int) error {
	if n < 0 || int64(n) > b.remaining() {
		return errKernelBudget
	}
	b.used += int64(n)
	return nil
}

func kernelData(b []byte, d *disk, folder string, opt Options, depth int) (KernelReport, error) {
	return kernelDataWithBudget(b, d, folder, opt, depth, &kernelBudget{limit: opt.limit()})
}

func kernelDataWithBudget(b []byte, d *disk, folder string, opt Options, depth int, budget *kernelBudget) (KernelReport, error) {
	r := KernelReport{InputFormat: inputFormat(b), SourceSHA256: digest(b), Streams: []Stream{}, Rejected: []Candidate{}}
	if depth > 4 {
		return r, errors.New("nested kernel compression depth exceeds 4")
	}
	if e := d.MkdirAll(folder, 0755); e != nil {
		return r, e
	}
	used := map[string]int{}
	attempts := 0
	for cursor := 0; cursor < len(b); {
		x := bytes.Index(b[cursor:], xzMagic)
		g := bytes.Index(b[cursor:], gzMagic)
		pos := x
		kind := "xz"
		if g >= 0 && (x < 0 || g < x) {
			pos = g
			kind = "gzip"
		}
		if pos < 0 {
			break
		}
		pos += cursor
		attempts++
		if attempts > 256 {
			return r, errors.New("too many compressed kernel candidates")
		}
		var decoded []byte
		var n, check int
		var err error
		remaining := budget.remaining()
		if remaining <= 0 {
			return r, errKernelBudget
		}
		if kind == "xz" {
			decoded, n, check, err = decodeXZ(b[pos:], remaining)
		} else {
			decoded, n, err = decodeGzip(b[pos:], remaining)
		}
		if err != nil {
			if errors.Is(err, errKernelBudget) {
				return r, fmt.Errorf("%s stream at %#x: %w", kind, pos, err)
			}
			validHeader := kind == "xz" && len(b)-pos >= 12 && crc32.ChecksumIEEE(b[pos+6:pos+8]) == binary.LittleEndian.Uint32(b[pos+8:pos+12])
			if pos == 0 || validHeader {
				return r, fmt.Errorf("%s stream at %#x: %w", kind, pos, err)
			}
			r.Rejected = append(r.Rejected, Candidate{Offset: pos, Compression: kind, Error: err.Error()})
			cursor = pos + 3
			continue
		}
		if n <= 0 {
			return r, errors.New("compressed stream did not advance")
		}
		if err = budget.reserve(len(decoded)); err != nil {
			return r, err
		}
		name := fmt.Sprintf("stream-%x.bin", pos)
		if isCPIO(decoded) {
			name = "initramfs.cpio"
		} else if len(decoded) >= 60 && string(decoded[56:60]) == "ARM\x64" {
			name = "Image"
		} else if len(decoded) >= 4 && string(decoded[:4]) == "\x7fELF" {
			name = "vmlinux"
		} else if bannerRE.Match(decoded) {
			name = "Image"
		}
		used[name]++
		if used[name] > 1 {
			name = fmt.Sprintf("%s-%x", name, pos)
		}
		suffix := ".xz"
		if kind == "gzip" {
			suffix = ".gz"
		}
		if err = d.put(path.Join(folder, name), decoded); err != nil {
			return r, err
		}
		if err = d.put(path.Join(folder, name+suffix), b[pos:pos+n]); err != nil {
			return r, err
		}
		s := Stream{Offset: pos, OffsetHex: fmt.Sprintf("0x%x", pos), Compression: kind, CompressedSize: n, DecodedSize: len(decoded), File: name, SHA256: digest(decoded), Check: check}
		for _, v := range bannerRE.FindAll(decoded, -1) {
			s.Banners = append(s.Banners, strings.ToValidUTF8(string(v), "�"))
		}
		if isCPIO(decoded) {
			cf := strings.TrimSuffix(name, ".cpio")
			if err = extractCPIO(decoded, d, path.Join(folder, cf), opt); err != nil {
				return r, err
			}
			r.CPIOArchives = append(r.CPIOArchives, name)
		} else if bytes.Contains(decoded, xzMagic) || bytes.Contains(decoded, gzMagic) || bytes.Contains(decoded, []byte("070701")) || bytes.Contains(decoded, []byte("070702")) {
			nr, err := kernelDataWithBudget(decoded, d, path.Join(folder, name+".parts"), opt, depth+1, budget)
			if err != nil {
				return r, err
			}
			s.Nested = &nr
		}
		r.Streams = append(r.Streams, s)
		cursor = pos + n
	}
	// Uncompressed built-in initramfs archives (including those in vmlinux).
	for cursor, n := 0, 0; cursor < len(b); {
		p := bytes.Index(b[cursor:], []byte("07070"))
		if p < 0 {
			break
		}
		p += cursor
		entries, end, e := parseCPIO(b[p:], opt)
		if e != nil || len(entries) == 0 {
			cursor = p + 6
			continue
		}
		// Do not extract text lookalikes or archives inside already handled streams.
		inside := false
		for _, s := range r.Streams {
			if p >= s.Offset && p < s.Offset+s.CompressedSize {
				inside = true
				break
			}
		}
		if inside {
			cursor = p + end
			continue
		}
		n++
		if n > 128 {
			return r, errors.New("too many embedded CPIO archives")
		}
		name := folderName("initramfs", n)
		if used[name+".cpio"] > 0 {
			name += fmt.Sprintf("-%x", p)
		}
		if e = d.put(path.Join(folder, name+".cpio"), b[p:p+end]); e != nil {
			return r, e
		}
		if e = extractCPIO(b[p:p+end], d, path.Join(folder, name), opt); e != nil {
			return r, e
		}
		r.CPIOArchives = append(r.CPIOArchives, name+".cpio")
		cursor = p + end
	}
	// A Linux ELF can contain its own compressed initramfs while the kernel code
	// itself is already uncompressed (for example TILE). Preserve that ELF as-is.
	for _, at := range bannerRE.FindAllIndex(b, -1) {
		inside := false
		for _, s := range r.Streams {
			if at[0] >= s.Offset && at[0] < s.Offset+s.CompressedSize {
				inside = true
				break
			}
		}
		if !inside {
			r.InputBanners = append(r.InputBanners, strings.ToValidUTF8(string(b[at[0]:at[1]]), "�"))
		}
	}
	if depth == 0 && len(r.InputBanners) > 0 && strings.HasPrefix(r.InputFormat, "ELF") {
		r.UncompressedKernel = "vmlinux"
		if e := d.put(path.Join(folder, "vmlinux"), b); e != nil {
			return r, e
		}
	}
	return r, d.json(path.Join(folder, "streams.json"), r)
}

func Kernel(source, destination string, opt Options) (KernelReport, error) {
	b, e := ReadInput(source, opt)
	if e != nil {
		return KernelReport{}, e
	}
	d, e := newDisk(destination)
	if e != nil {
		return KernelReport{}, e
	}
	defer d.Close()
	if e = d.put("source.bin", b); e != nil {
		return KernelReport{}, e
	}
	r, e := kernelData(b, d, "kernel", opt, 0)
	if e != nil {
		return r, e
	}
	return r, writeIntegrity(d)
}
