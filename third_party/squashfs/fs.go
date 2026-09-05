package squashfs

import (
	"io"
	"io/fs"
	"path"
	"slices"
	"strings"

	squashfslow "github.com/CalebQ42/squashfs/low"
	"github.com/CalebQ42/squashfs/low/directory"
	"github.com/CalebQ42/squashfs/low/inode"
)

// FS is a fs.FS representation of a squashfs directory.
// Archive paths use forward slashes on every host, as required by io/fs.
// Implements fs.GlobFS, fs.ReadDirFS, fs.ReadFileFS, fs.StatFS, and fs.SubFS
type FS struct {
	r      *Reader
	parent *FS
	LowDir squashfslow.Directory
}

// Creates a new *FS from the given squashfs.directory
func (r *Reader) FSFromDirectory(d squashfslow.Directory, parent FS) FS {
	return FS{
		LowDir: d,
		r:      r,
		parent: &parent,
	}
}

// Glob returns the name of the files at the given pattern.
// All paths are relative to the FS.
// Uses path.Match to compare names; archive paths always use forward slashes.
func (f FS) Glob(pattern string) (out []string, err error) {
	pattern = path.Clean(pattern)
	if !fs.ValidPath(pattern) {
		return nil, &fs.PathError{
			Op:   "glob",
			Path: pattern,
			Err:  fs.ErrInvalid,
		}
	}
	split := strings.Split(pattern, "/")
	for i := range f.LowDir.Entries {
		if match, _ := path.Match(split[0], f.LowDir.Entries[i].Name); match {
			if len(split) == 1 {
				out = append(out, f.LowDir.Entries[i].Name)
				continue
			}
			if typ := f.LowDir.Entries[i].InodeType; typ != inode.Dir && typ != inode.EDir {
				continue
			}
			sub, err := f.Sub(f.LowDir.Entries[i].Name)
			if err != nil {
				if pathErr, ok := err.(*fs.PathError); ok {
					if pathErr.Err == fs.ErrNotExist {
						continue
					}
					pathErr.Op = "glob"
					pathErr.Path = pattern
					return nil, pathErr
				}
				return nil, &fs.PathError{
					Op:   "glob",
					Path: pattern,
					Err:  err,
				}
			}
			subGlob, err := sub.(fs.GlobFS).Glob(strings.Join(split[1:], "/"))
			if err != nil {
				if pathErr, ok := err.(*fs.PathError); ok {
					if pathErr.Err == fs.ErrNotExist {
						continue
					}
					pathErr.Op = "glob"
					pathErr.Path = pattern
					return nil, pathErr
				}
				return nil, &fs.PathError{
					Op:   "glob",
					Path: pattern,
					Err:  err,
				}
			}
			for j := range subGlob {
				subGlob[j] = path.Join(f.LowDir.Entries[i].Name, subGlob[j])
			}
			out = append(out, subGlob...)
		}
	}
	return
}

// Opens the file at name. Returns a *File as an fs.File.
func (f FS) Open(name string) (fs.File, error) {
	return f.OpenFile(name)
}

func (f FS) OpenFile(name string) (*File, error) {
	name = path.Clean(name)
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{
			Op:   "open",
			Path: name,
			Err:  fs.ErrInvalid,
		}
	}
	if name == "." || name == "" {
		return f.File(), nil
	}
	split := strings.Split(name, "/")
	if split[0] == ".." {
		if f.parent == nil { // root directory
			return nil, &fs.PathError{
				Op:   "open",
				Path: name,
				Err:  fs.ErrNotExist,
			}
		} else {
			return f.parent.OpenFile(strings.Join(split[1:], "/"))
		}
	}
	i, found := slices.BinarySearchFunc(f.LowDir.Entries, split[0], func(e directory.Entry, name string) int {
		return strings.Compare(e.Name, name)
	})
	if !found {
		return nil, &fs.PathError{
			Op:   "open",
			Path: name,
			Err:  fs.ErrNotExist,
		}
	}
	b, err := f.r.Low.BaseFromEntry(f.LowDir.Entries[i])
	if err != nil {
		return nil, err
	}
	if len(split) == 1 {
		return &File{
			Low:    b,
			r:      f.r,
			parent: f,
		}, nil
	}
	if !b.IsDir() {
		return nil, &fs.PathError{
			Op:   "open",
			Path: name,
			Err:  fs.ErrNotExist,
		}
	}
	d, err := b.ToDir(f.r.Low)
	if err != nil {
		return nil, err
	}
	return f.r.FSFromDirectory(d, f).OpenFile(strings.Join(split[1:], "/"))
}

// Returns all DirEntry's for the directory at name.
// If name is not a directory, returns an error.
func (f FS) ReadDir(name string) ([]fs.DirEntry, error) {
	name = path.Clean(name)
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{
			Op:   "readdir",
			Path: name,
			Err:  fs.ErrInvalid,
		}
	}
	if name == "." || name == "" {
		return f.File().ReadDir(-1)
	}
	fil, err := f.Open(name)
	if err != nil {
		return nil, err
	}
	return fil.(*File).ReadDir(-1)
}

// Returns the contents of the file at name.
func (f FS) ReadFile(name string) (out []byte, err error) {
	name = path.Clean(name)
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{
			Op:   "readfile",
			Path: name,
			Err:  fs.ErrInvalid,
		}
	}
	if name == "." || name == "" {
		return nil, fs.ErrInvalid
	}
	fil, err := f.Open(name)
	if err != nil {
		return nil, err
	}
	if !fil.(*File).IsRegular() {
		return nil, fs.ErrInvalid
	}
	return io.ReadAll(fil)
}

// Returns the fs.FileInfo for the file at name.
func (f FS) Stat(name string) (fs.FileInfo, error) {
	name = path.Clean(name)
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{
			Op:   "stat",
			Path: name,
			Err:  fs.ErrInvalid,
		}
	}
	if name == "." || name == "" {
		return f.File().Stat()
	}
	fil, err := f.Open(name)
	if err != nil {
		return nil, err
	}
	return fil.(*File).Stat()
}

// Returns the FS at dir
func (f FS) Sub(dir string) (fs.FS, error) {
	dir = path.Clean(dir)
	if !fs.ValidPath(dir) {
		return nil, &fs.PathError{
			Op:   "dir",
			Path: dir,
			Err:  fs.ErrInvalid,
		}
	}
	if dir == "." || dir == "" {
		return f, nil
	}
	fil, err := f.Open(dir)
	if err != nil {
		return nil, err
	}
	if !fil.(*File).IsDir() {
		return nil, &fs.PathError{
			Op:   "dir",
			Path: dir,
			Err:  fs.ErrInvalid,
		}
	}
	return fil.(*File).FS()
}

// Extract the FS to the given folder. If the file is a folder, the folder's contents will be extracted to the folder.
// Uses default extraction options.
func (f FS) Extract(folder string) error {
	return f.File().Extract(folder)
}

// Extract the FS to the given folder. If the file is a folder, the folder's contents will be extracted to the folder.
// Allows setting various extraction options via ExtractionOptions.
func (f FS) ExtractWithOptions(folder string, op *ExtractionOptions) error {
	return f.File().ExtractWithOptions(folder, op)
}

// Returns the FS as a *File
func (f FS) File() *File {
	if f.parent != nil {
		return &File{
			Low:    f.LowDir.FileBase,
			parent: *f.parent,
			r:      f.r,
		}
	}
	return &File{
		Low: f.LowDir.FileBase,
		r:   f.r,
	}
}

func (f FS) path() string {
	if f.parent == nil {
		return f.LowDir.Name
	}
	return path.Join(f.parent.path(), f.LowDir.Name)
}
