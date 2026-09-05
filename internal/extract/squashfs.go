// SPDX-License-Identifier: BSD-3-Clause
package extract

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/CalebQ42/squashfs"
	"github.com/CalebQ42/squashfs/low/inode"
)

func unpackSquashFS(body []byte, d *disk, folder string, opt Options) (entries []Entry, err error) {
	// A malformed third-party filesystem decoder must not crash the CLI.
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("malformed SquashFS: %v", p)
		}
	}()
	if len(body) < 96 || string(body[:4]) != "hsqs" {
		return nil, errors.New("invalid SquashFS superblock")
	}
	if n := binary.LittleEndian.Uint32(body[4:]); n > MaxEntries+1 {
		return nil, errors.New("too many SquashFS inodes")
	}
	bs := binary.LittleEndian.Uint32(body[12:])
	if bs < 4096 || bs > 1<<20 || bs&(bs-1) != 0 {
		return nil, errors.New("invalid SquashFS block size")
	}
	if used := binary.LittleEndian.Uint64(body[40:]); used > uint64(len(body)) {
		return nil, errors.New("truncated SquashFS image")
	}
	r, e := squashfs.NewReader(bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	entries = []Entry{}
	var total int64
	err = fs.WalkDir(r.FS, ".", func(name string, de fs.DirEntry, walkerr error) error {
		if walkerr != nil {
			return walkerr
		}
		if name == "." {
			return nil
		}
		if e := safePath(name); e != nil {
			return e
		}
		if len(entries) >= MaxEntries {
			return errors.New("too many SquashFS entries")
		}
		f, e := r.OpenFile(name)
		if e != nil {
			return e
		}
		defer f.Close()
		info, e := f.Stat()
		if e != nil {
			return e
		}
		uid, e := f.Low.Uid(&r.Low)
		if e != nil {
			return e
		}
		gid, e := f.Low.Gid(&r.Low)
		if e != nil {
			return e
		}
		item := Entry{Path: name, Mode: octal(uint32(f.Low.Inode.Perm)), UID: int(uid), GID: int(gid), Mtime: utc(f.Low.Inode.ModTime)}
		switch f.Low.Inode.Type {
		case inode.Dir, inode.EDir:
			item.Type = "directory"
		case inode.Sym, inode.ESym:
			item.Type = "symlink"
			item.Target = f.SymlinkPath()
		case inode.Fil, inode.EFil:
			item.Type = "file"
			item.Size = info.Size()
			if item.Size < 0 || item.Size > opt.limit()-total {
				return errors.New("SquashFS expanded size exceeds byte limit")
			}
			// CalebQ42/squashfs initializes its data.Reader by reading block 0.
			// A zero-length regular file has no data blocks, so asking the
			// library to read it returns "invalid block index".  Empty files are
			// valid SquashFS records; retain their metadata and skip the reader.
			if item.Size > 0 {
				item.data, e = bounded(f, item.Size+1)
				if e != nil {
					return e
				}
				if int64(len(item.data)) != item.Size {
					return fmt.Errorf("SquashFS size mismatch: %s", name)
				}
			}
			total += item.Size
			item.SHA256 = digest(item.data)
		default:
			item.Type = "special_metadata_only"
			var dev uint32
			switch v := f.Low.Inode.Data.(type) {
			case inode.Device:
				dev = v.Dev
			case inode.EDevice:
				dev = v.Dev
			}
			item.RdevMajor = (dev & 0xfff00) >> 8
			item.RdevMinor = (dev & 0xff) | ((dev >> 12) & 0xfff00)
			// Retain the POSIX node type so the tar writer can preserve device/FIFO metadata.
			m := uint32(f.Low.Inode.Perm)
			switch f.Low.Inode.Type {
			case inode.Char, inode.EChar:
				m |= 0020000
			case inode.Block, inode.EBlock:
				m |= 0060000
			case inode.Fifo, inode.EFifo:
				m |= 0010000
			case inode.Sock, inode.ESock:
				m |= 0140000
			}
			item.Mode = octal(m)
		}
		entries = append(entries, item)
		return nil
	})
	if err != nil {
		return nil, err
	}
	entries, err = planPaths(entries)
	if err != nil {
		return nil, err
	}
	if err = writeEntries(d, folder, entries, opt.NoSymlinks); err != nil {
		return nil, err
	}
	if err = writeTar(d, folder+".tar.gz", entries); err != nil {
		return nil, err
	}
	if err = d.json(folder+"-manifest.json", entries); err != nil {
		return nil, err
	}
	aliases := []map[string]string{}
	var listing strings.Builder
	for _, e := range entries {
		if e.Path != e.StoredPath {
			aliases = append(aliases, map[string]string{"original": e.Path, "stored": e.StoredPath})
		}
		fmt.Fprintf(&listing, "%s %s %d/%d %d %s %s", e.Type, e.Mode, e.UID, e.GID, e.Size, e.Mtime, e.Path)
		if e.Type == "symlink" {
			fmt.Fprintf(&listing, " -> %s", e.Target)
		}
		listing.WriteByte('\n')
	}
	if err = d.json(folder+"-path-map.json", aliases); err != nil {
		return nil, err
	}
	if err = d.json(folder+"-superblock.json", r.Low.Superblock); err != nil {
		return nil, err
	}
	if err = d.put(folder+"-listing.txt", []byte(listing.String())); err != nil {
		return nil, err
	}
	if err = d.put(folder+"-superblock.txt", []byte(fmt.Sprintf("SquashFS %d.%d\nCompression ID: %d\nBlock size: %d\nInodes: %d\nBytes used: %d\nCreated: %s\n", r.Low.Superblock.VerMaj, r.Low.Superblock.VerMin, r.Low.Superblock.CompType, bs, r.Low.Superblock.InodeCount, r.Low.Superblock.Size, utc(r.Low.Superblock.ModTime)))); err != nil {
		return nil, err
	}
	err = d.put(folder+"-extraction.log", []byte(fmt.Sprintf("Extracted and size-checked %d entries using native Go.\nCase-safe paths: %d. Original names and metadata retained in %s.tar.gz.\nBrowse files use 0644, directories 0755. Special nodes are metadata-only.\n", len(entries), len(aliases), folder)))
	return entries, err
}

func writeTar(d *disk, name string, entries []Entry) error {
	f, e := d.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if e != nil {
		return e
	}
	g := gzip.NewWriter(f)
	t := tar.NewWriter(g)
	for _, v := range entries {
		mode, err := modeValue(v.Mode)
		if err != nil {
			e = err
			break
		}
		mt, err := time.Parse(time.RFC3339, v.Mtime)
		if err != nil {
			e = err
			break
		}
		h := &tar.Header{Name: v.Path, Mode: int64(mode & 07777), Uid: v.UID, Gid: v.GID, ModTime: mt, Format: tar.FormatPAX}
		switch v.Type {
		case "directory":
			h.Typeflag = tar.TypeDir
		case "symlink", "symlink_metadata_only":
			h.Typeflag = tar.TypeSymlink
			h.Linkname = v.Target
		case "file":
			h.Typeflag = tar.TypeReg
			h.Size = v.Size
		default:
			h.Devmajor = int64(v.RdevMajor)
			h.Devminor = int64(v.RdevMinor)
			switch mode & 0170000 {
			case 0020000:
				h.Typeflag = tar.TypeChar
			case 0060000:
				h.Typeflag = tar.TypeBlock
			case 0010000:
				h.Typeflag = tar.TypeFifo
			default:
				continue
			}
		}
		if e = t.WriteHeader(h); e != nil {
			break
		}
		if v.Type == "file" {
			if _, e = t.Write(v.data); e != nil {
				break
			}
		}
	}
	return errors.Join(e, t.Close(), g.Close(), f.Close())
}

func SquashFS(source, destination string, opt Options) error {
	b, e := ReadInput(source, opt)
	if e != nil {
		return e
	}
	d, e := newDisk(destination)
	if e != nil {
		return e
	}
	defer d.Close()
	if e = d.put("image.squashfs", b); e != nil {
		return e
	}
	if _, e = unpackSquashFS(b, d, "rootfs", opt); e != nil {
		return e
	}
	return writeIntegrity(d)
}
